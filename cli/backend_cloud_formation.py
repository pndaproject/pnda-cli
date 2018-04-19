#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Copyright (c) 2016 Cisco and/or its affiliates.
#   This software is licensed to you under the terms of the Apache License, Version 2.0
#   (the "License").
#   You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#   The code, technical concepts, and all information contained herein, are the property of
#   Cisco Technology, Inc.and/or its affiliated entities, under various laws including copyright,
#   international treaties, patent, and/or contract.
#   Any use of the material herein must be in accordance with the terms of the License.
#   All rights not expressly granted by the License are reserved.
#   Unless required by applicable law or agreed to separately in writing, software distributed
#   under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
#   ANY KIND, either express or implied.
#
#   Purpose: Backend implementation for creating PNDA on Amazon Web Services EC2

import sys
import json
import time
import traceback
import ssl

import boto.cloudformation
import boto.ec2
from backend_base import BaseBackend
import pnda_cli_utils as utils

utils.init_logging()
CONSOLE = utils.CONSOLE_LOGGER
LOG = utils.FILE_LOGGER
LOG_FILE_NAME = utils.LOG_FILE_NAME

class CloudFormationBackend(BaseBackend):
    '''
    Deployment specific implementation for AWS Cloud Formation
    '''
    def __init__(self, pnda_env, cluster, no_config_check, flavor, keyname, branch, dry_run):
        self._dry_run = dry_run

        super(CloudFormationBackend, self).__init__(
            pnda_env, cluster, no_config_check, flavor, self._keyfile_from_keyname(keyname), branch)

    def check_target_specific_config(self):
        '''
        Check AWS specific configuration has been entered correctly
        '''
        self._check_aws_connection()
        name = self._keyname_from_keyfile(self._keyfile)
        self._check_keypair(name)

    def load_node_config(self):
        '''
        Load a node config descriptor from a config.json file in the cloud-formation flavor specific directory
        '''
        node_config_file = file('cloud-formation/%s/config.json' % self._flavor)
        config = json.load(node_config_file)
        node_config_file.close()
        return config

    def fill_instance_map(self):
        '''
        Use the AWS Ec2 API to generate a list of the target instances
        '''
        CONSOLE.debug('Checking details of created instances')
        region = self._pnda_env['aws_parameters']['AWS_REGION']
        ec2 = boto.ec2.connect_to_region(region)
        reservations = self._retry(ec2.get_all_reservations)
        instance_map = {}
        for reservation in reservations:
            for instance in reservation.instances:
                if 'pnda_cluster' in instance.tags and instance.tags['pnda_cluster'] == self._cluster and instance.state == 'running':
                    CONSOLE.debug(instance.private_ip_address + ' ' + instance.tags['Name'])
                    instance_map[instance.tags['Name']] = {
                        "bootstrapped": False,
                        "public_dns": instance.public_dns_name,
                        "ip_address": instance.ip_address,
                        "private_ip_address":instance.private_ip_address,
                        "name": instance.tags['Name'],
                        "node_idx": instance.tags['node_idx'],
                        "node_type": instance.tags['node_type']
                    }
        return instance_map

    def pre_install_pnda(self, node_counts):
        '''
        Use the AWS Cloud Formation API to launch a stack that PNDA can be installed on
        The cloud formation stack is defined in json files in the flavor specific cloud-formation directory
        '''
        template_data = self._generate_template_file(
            self._flavor, node_counts['datanodes'], node_counts['opentsdb_nodes'], node_counts['kafka_nodes'], node_counts['zk_nodes'])

        region = self._pnda_env['aws_parameters']['AWS_REGION']
        aws_availability_zone = self._pnda_env['aws_parameters']['AWS_AVAILABILITY_ZONE']
        cf_parameters = [('keyName', self._keyname_from_keyfile(self._keyfile)), ('pndaCluster', self._cluster), ('awsAvailabilityZone', aws_availability_zone)]
        exclude=['AWS_SECRET_ACCESS_KEY','AWS_AVAILABILITY_ZONE','AWS_REGION','AWS_ACCESS_KEY_ID']
        for parameter in self._pnda_env['aws_parameters']:
            if parameter not in exclude:
                cf_parameters.append((parameter, self._pnda_env['aws_parameters'][parameter]))

        self._save_cf_resources('create_%s' % utils.MILLI_TIME(), self._cluster, cf_parameters, template_data)
        if self._dry_run:
            CONSOLE.info('Dry run mode completed')
            sys.exit(0)

        CONSOLE.info('Creating Cloud Formation stack')
        conn = boto.cloudformation.connect_to_region(region)
        stack_status = 'CREATING'
        stack_status_new = None
        conn.create_stack(self._cluster,
                          template_body=template_data,
                          parameters=cf_parameters)

        while stack_status in ['CREATE_IN_PROGRESS', 'CREATING']:
            time.sleep(5)
            if stack_status != stack_status_new:
                if stack_status_new is not None:
                    stack_status = stack_status_new
                CONSOLE.info('Stack is: %s', stack_status)
            else:
                CONSOLE.debug('Stack is: %s', stack_status)
            stacks = self._retry(conn.describe_stacks, self._cluster)
            if stacks:
                stack_status_new = stacks[0].stack_status

        if stack_status != 'CREATE_COMPLETE':
            CONSOLE.error('Stack did not come up, status is: %s', stack_status)
            self._fetch_stack_events(conn, self._cluster)
            sys.exit(1)

        self.clear_instance_map_cache()

    def pre_expand_pnda(self, node_counts):
        '''
        Use the AWS Cloud Formation API to launch a stack that PNDA can be installed on
        The cloud formation stack is defined in json files in the flavor specific cloud-formation directory
        '''
        template_data = self._generate_template_file(
            self._flavor, node_counts['datanodes'], node_counts['opentsdb_nodes'], node_counts['kafka_nodes'], node_counts['zk_nodes'])

        region = self._pnda_env['aws_parameters']['AWS_REGION']
        cf_parameters = [('keyName', self._keyname_from_keyfile(self._keyfile)), ('pndaCluster', self._cluster)]
        exclude=['AWS_SECRET_ACCESS_KEY','AWS_AVAILABILITY_ZONE','AWS_REGION','AWS_ACCESS_KEY_ID']
        for parameter in self._pnda_env['aws_parameters']:
            if parameter not in exclude:
                cf_parameters.append((parameter, self._pnda_env['aws_parameters'][parameter]))

        self._save_cf_resources('expand_%s' % utils.MILLI_TIME(), self._cluster, cf_parameters, template_data)
        if self._dry_run:
            CONSOLE.info('Dry run mode completed')
            sys.exit(0)

        CONSOLE.info('Updating Cloud Formation stack')
        conn = boto.cloudformation.connect_to_region(region)
        stack_status = 'UPDATING'
        stack_status_new = None
        self._retry(conn.update_stack, self._cluster,
                    template_body=template_data,
                    parameters=cf_parameters)

        while stack_status in ['UPDATE_IN_PROGRESS', 'UPDATING', 'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS']:
            time.sleep(5)
            if stack_status != stack_status_new:
                if stack_status_new is not None:
                    stack_status = stack_status_new
                CONSOLE.info('Stack is: %s', stack_status)
            else:
                CONSOLE.debug('Stack is: %s', stack_status)
            stacks = self._retry(conn.describe_stacks, self._cluster)
            if stacks:
                stack_status_new = stacks[0].stack_status

        if stack_status != 'UPDATE_COMPLETE':
            CONSOLE.error('Stack did not come up, status is: %s', stack_status)
            self._fetch_stack_events(conn, self._cluster)
            sys.exit(1)

        self.clear_instance_map_cache()

    def pre_destroy_pnda(self):
        '''
        Use the AWS Cloud Formation API to delete the cloud formation stack that PNDA was installed on
        '''
        CONSOLE.info('Deleting Cloud Formation stack')
        region = self._pnda_env['aws_parameters']['AWS_REGION']
        conn = boto.cloudformation.connect_to_region(region)
        stack_status = 'DELETING'
        stack_status_new = None
        self._retry(conn.delete_stack, self._cluster)
        while stack_status in ['DELETE_IN_PROGRESS', 'DELETING']:
            time.sleep(5)
            if stack_status != stack_status_new:
                if stack_status_new is not None:
                    stack_status = stack_status_new
                CONSOLE.info('Stack is: %s', stack_status)
            else:
                CONSOLE.debug('Stack is: %s', stack_status)
            try:
                stacks = self._retry(conn.describe_stacks, self._cluster)
            except:
                stacks = []

            if stacks:
                stack_status_new = stacks[0].stack_status
            else:
                stack_status_new = 'DELETE_COMPLETE'

    def _retry(self, do_func, *args, **kwargs):
        ret = None
        for _ in xrange(3):
            try:
                ret = do_func(*args, **kwargs)
                break
            except ssl.SSLError, exception:
                LOG.warning(exception)
        return ret

    def _fetch_stack_events(self, cfn_cnxn, stack_name):
        page_token = True
        while page_token is not None:
            event_page = cfn_cnxn.describe_stack_events(stack_name, page_token)
            for event in event_page:
                resource_id = event.logical_resource_id
                status = event.resource_status
                reason = event.resource_status_reason
                message = "%s: %s%s" % (resource_id, status, '' if reason is None else ' - %s' % reason)
                if status in ['CREATE_FAILED', 'UPDATE_FAILED'] and reason != 'Resource creation cancelled':
                    CONSOLE.error(message)
                else:
                    LOG.debug(message)
            page_token = event_page.next_token

    def _keyname_from_keyfile(self, keyfile):
        return keyfile[:-4]

    def _keyfile_from_keyname(self, keyname):
        return '%s.pem' % keyname

    def _save_cf_resources(self, context, cluster_name, params, template):
        params_file = 'cli/logs/%s_%s_cloud-formation-parameters.json' % (cluster_name, context)
        CONSOLE.info('Writing Cloud Formation parameters for %s to %s', cluster_name, params_file)
        with open(params_file, 'w') as outfile:
            json.dump(params, outfile, sort_keys=True, indent=4)

        template_file = 'cli/logs/%s_%s_cloud-formation-template.json' % (cluster_name, context)
        CONSOLE.info('Writing Cloud Formation template for %s to %s', cluster_name, template_file)
        with open(template_file, 'w') as outfile:
            json.dump(json.loads(template), outfile, sort_keys=True, indent=4)

    def _generate_instance_templates(self, template_data, instance_name, instance_count):
        if instance_name in template_data['Resources']:
            instance_def = json.dumps(template_data['Resources'].pop(instance_name))

        for instance_index in range(0, instance_count):
            instance_def_n = instance_def.replace('$node_idx$', str(instance_index))
            template_data['Resources']['%s%s' % (instance_name, instance_index)] = json.loads(instance_def_n)

    def _generate_template_file(self, flavor, datanodes, opentsdbs, kafkas, zookeepers):
        common_filepath = 'cloud-formation/cf-common.json'
        with open(common_filepath, 'r') as template_file:
            template_data = json.loads(template_file.read())

        flavor_filepath = 'cloud-formation/%s/cf-flavor.json' % flavor
        with open(flavor_filepath, 'r') as template_file:
            flavor_data = json.loads(template_file.read())

        for element in flavor_data:
            if element not in template_data:
                template_data[element] = flavor_data[element]
            else:
                for child in flavor_data[element]:
                    template_data[element][child] = flavor_data[element][child]

        self._generate_instance_templates(template_data, 'instanceCdhDn', datanodes)
        self._generate_instance_templates(template_data, 'instanceOpenTsdb', opentsdbs)
        self._generate_instance_templates(template_data, 'instanceKafka', kafkas)
        self._generate_instance_templates(template_data, 'instanceZookeeper', zookeepers)

        return json.dumps(template_data)

    def _check_keypair(self, keyname):
        try:
            region = self._pnda_env['aws_parameters']['AWS_REGION']
            ec2 = boto.ec2.connect_to_region(region)
            stored_key = ec2.get_key_pair(keyname)
            if stored_key is None:
                raise Exception("Key not found %s" % keyname)
            CONSOLE.info('Keyfile.......... OK')
        except:
            CONSOLE.info('Keyfile.......... ERROR')
            CONSOLE.error('Failed to find key %s in ec2.', keyname)
            CONSOLE.error(traceback.format_exc())
            sys.exit(1)

    def _check_aws_connection(self):
        region = self._pnda_env['aws_parameters']['AWS_REGION']

        valid_regions = [valid_region.name for valid_region in boto.ec2.regions()]
        if region not in valid_regions:
            CONSOLE.info('AWS connection... ERROR')
            CONSOLE.error('Failed to connect to cloud formation API, ec2 region "%s" was not valid. Valid options are %s', region, json.dumps(valid_regions))
            sys.exit(1)

        conn = boto.cloudformation.connect_to_region(region)
        if conn is None:
            CONSOLE.info('AWS connection... ERROR')
            CONSOLE.error('Failed to connect to cloud formation API, verify aws_parameters settings in "pnda_env.yaml" and try again.')
            sys.exit(1)

        try:
            conn.list_stacks()
            CONSOLE.info('AWS connection... OK')
        except:
            CONSOLE.info('AWS connection... ERROR')
            CONSOLE.error('Failed to query cloud formation API, verify aws_parameters settings in "pnda_env.yaml" and try again.')
            CONSOLE.error(traceback.format_exc())
            sys.exit(1)
