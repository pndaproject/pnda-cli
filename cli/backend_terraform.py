#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   Copyright (c) 2018 Cisco and/or its affiliates.
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
#   Purpose: Backend implementation for creating PNDA on vSphere ESX with Terraform

import os
import sys
import json
import string
import traceback
from shutil import copy, rmtree
from distutils.dir_util import copy_tree
from python_terraform import Terraform

from backend_base import BaseBackend
import pnda_cli_utils as utils

utils.init_logging()
CONSOLE = utils.CONSOLE_LOGGER
LOG = utils.FILE_LOGGER
LOG_FILE_NAME = utils.LOG_FILE_NAME

class TerraformBackend(BaseBackend):
    '''
    Deployment specific implementation for TerraformBackend for vSphere ESX
    '''
    def __init__(self, pnda_env, cluster, no_config_check, flavor, keyname, branch, dry_run):
        self._tf_work_dir = 'cli/tf-%s' % cluster
        self._terraform = Terraform(working_dir=self._tf_work_dir)
        self._dry_run = dry_run
        self._keyfile_pub = self._keyfile_pub_from_keyname(keyname)
        self._terraform_debug_notice = ', note debug log is not updated until the command finishes and in the case of timeout errors this can be much longer'
        super(TerraformBackend, self).__init__(
            pnda_env, cluster, no_config_check, flavor, self._keyfile_from_keyname(keyname), branch)

    def check_target_specific_config(self):
        '''
        Check Terraform specific configuration has been entered correctly
        '''
        self._check_public_key_exists()
        self._check_terraform_installed()

    def load_node_config(self):
        '''
        Load a node config descriptor from a config.json file in the terraform flavor specific directory
        '''
        node_config_file = file('terraform/%s/config.json' % self._flavor)
        config = json.load(node_config_file)
        node_config_file.close()
        return config

    def fill_instance_map(self):
        '''
        Use the terraform outputs to generate a list of the target instances
        '''
        CONSOLE.debug('Checking details of created instances')
        instance_map = {}
        if os.path.exists('%s/outputs.tf' % self._tf_work_dir):
            output = self._terraform.output()
            if output:
                for entry in output:
                    output_data = output[entry]
                    output_values = output_data['value']
                    index = 0
                    for output_value in output_values:
                        output_name = entry.replace('_private_ip', '')
                        node_type, node_name = self._node_type_from_output_name(output_name, index)
                        ip_address = output_value
                        instance_map[self._cluster + '-' + node_name] = {
                            "bootstrapped": False,
                            "ip_address": None,
                            "private_ip_address": ip_address,
                            "name": node_name,
                            "node_idx": index,
                            "node_type": node_type
                        }
                        index += 1
        return instance_map

    def pre_install_pnda(self, node_counts):
        '''
        Use Terraform to launch a stack that PNDA can be installed on
        The ESX stack is defined in tf files in the flavor specific terraform directory
        '''
        self._set_up_terraform_resources(node_counts)
        if self._dry_run:
            return_code, stdout, stderr = self._terraform.plan()
            self._dump_output(stdout, stderr)
            CONSOLE.info('Dry run mode completed')
            sys.exit(0)

        CONSOLE.info('Creating ESX stack. Expect this to take 5 - 10 minutes%s', self._terraform_debug_notice)
        return_code, stdout, stderr = self._terraform.apply('-auto-approve')
        self._dump_output(stdout, stderr)
        if return_code != 0:
            CONSOLE.error('ESX stack did not come up. Exit code = %s', return_code)
            sys.exit(1)

        self.clear_instance_map_cache()

    def pre_expand_pnda(self, node_counts):
        '''
        Use Terraform to launch a stack that PNDA can be installed on
        The ESX stack is defined in tf files in the flavor specific terraform directory
        '''
        self._set_up_terraform_resources(node_counts)
        if self._dry_run:
            return_code, stdout, stderr = self._terraform.plan()
            self._dump_output(stdout, stderr)
            CONSOLE.info('Dry run mode completed')
            sys.exit(0)

        CONSOLE.info('Updating ESX stack. Expect this to take 5 - 10 minutes%s', self._terraform_debug_notice)
        return_code, stdout, stderr = self._terraform.apply('-auto-approve')
        self._dump_output(stdout, stderr)
        if return_code != 0:
            CONSOLE.error('ESX stack did not come up. Exit code = %s', return_code)
            sys.exit(1)

        self.clear_instance_map_cache()

    def pre_destroy_pnda(self):
        '''
        Use Terraform to delete the ESX stack that PNDA was installed on
        '''
        if not os.path.exists('%s/tfvars.tf' % self._tf_work_dir):
            CONSOLE.error("Directory %s from the cluster creation phase is required", self._tf_work_dir)
            sys.exit(1)

        CONSOLE.info('Deleting ESX stack. Expect this to take 1 - 2 minutes%s', self._terraform_debug_notice)
        return_code, stdout, stderr = self._terraform.destroy('-auto-approve')
        self._dump_output(stdout, stderr)
        if return_code != 0:
            CONSOLE.error('ESX stack was not destroyed. Exit code = %s', return_code)
            sys.exit(1)

        if os.path.exists(self._tf_work_dir):
            rmtree(self._tf_work_dir)

        self.clear_instance_map_cache()

    def _check_terraform_installed(self):
        '''
        Check Terraform can be used
        '''
        try:
            Terraform().show()
        except OSError:
            CONSOLE.error(traceback.format_exc())
            CONSOLE.error('Terraform does not appear to be installed. Please ensure the "terraform" command can be run from a command prompt')
            sys.exit(1)

    def _check_public_key_exists(self):
        '''
        Check public key is present and named correctly
        '''
        if not os.path.isfile(self._keyfile_pub):
            CONSOLE.info('Public key....... ERROR')
            CONSOLE.error('Did not find local file named %s', self._keyfile_pub)
            sys.exit(1)
        CONSOLE.info('Public key....... OK')

    def _node_type_from_output_name(self, name, idx):
        # look at using metadata to carry this information like with the other
        # backend impls instead of reverse engineering it from the node name
        if name == 'hadoop-mgr':
            node_type = 'hadoop-mgr-%s' % (idx+1)
            node_name = 'hadoop-mgr-%s' % (idx+1)
        elif name in ['datanode', 'kafkanode', 'zookeeper', 'opentsdb']:
            node_type = name
            node_name = '%s-%s' % (name, idx)
        else:
            node_type = name
            node_name = name

        return node_type, node_name

    def _keyfile_pub_from_keyname(self, keyname):
        return '%s.pub' % keyname

    def _dump_output(self, stdout, stderr):
        LOG.info('stdout from terraform command:')
        for line in stdout.splitlines():
            LOG.info(line)
        LOG.info('stderr from terraform command:')
        for line in stderr.splitlines():
            LOG.info(line)

    def _set_up_terraform_resources(self, node_counts):
        properties = {}
        properties['PNDA_CLUSTER'] = self._cluster
        if node_counts:
            properties['DATANODE_COUNT'] = node_counts['datanodes']
            properties['OPENTSDB_COUNT'] = node_counts['opentsdb_nodes']
            properties['KAFKA_COUNT'] = node_counts['kafka_nodes']
            properties['ZK_COUNT'] = node_counts['zk_nodes']
        for parameter in self._pnda_env['terraform_parameters']:
            properties[parameter] = self._pnda_env['terraform_parameters'][parameter]

        # Make a directory for terraform to use
        if not os.path.exists(self._tf_work_dir):
            os.makedirs(self._tf_work_dir)
        CONSOLE.debug('Creating Terraform directory at %s', self._tf_work_dir)
        # Copy in script resources
        copy_tree("terraform/scripts", "%s/terraform/scripts" % self._tf_work_dir)
        # Copy in public key
        copy(self._keyfile_pub, "%s/terraform/scripts/key_name.pem.pub" % self._tf_work_dir)
        # Copy in deploy.tf and flavor/outputs.tf
        copy('terraform/deploy.tf', self._tf_work_dir)
        copy('terraform/%s/outputs.tf' % self._flavor, self._tf_work_dir)
        # Merge tfvars-common.tf and flavor/tfvars-flavor.tf and expand out properties
        with open('terraform/tfvars-common.tf', 'rb') as vars_common_file:
            vars_common = vars_common_file.read()
        with open('terraform/%s/tfvars-flavor.tf' % self._flavor, 'rb') as vars_flavor_file:
            vars_flavor = vars_flavor_file.read()
        tf_vars = "%s\n%s" % (vars_common, vars_flavor)
        tf_vars = string.Template(tf_vars).safe_substitute(properties)
        with open('%s/tfvars.tf' % self._tf_work_dir, 'wb') as vars_file:
            vars_file.write(tf_vars)
        self._terraform.init()
        CONSOLE.info('Created Terraform directory at %s. Please make a backup of this directory', self._tf_work_dir)
