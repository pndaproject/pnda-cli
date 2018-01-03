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
#   Purpose: Script to create PNDA on Amazon Web Services EC2

import uuid
import sys
import os
import os.path
import json
import time
import logging
import atexit
import traceback
import datetime
import tarfile
import ssl
import Queue
import StringIO

from threading import Thread

import requests
import boto.cloudformation
import boto.ec2
import yaml

import subprocess_to_log

from validation import UserInputValidator

os.chdir(os.path.dirname(os.path.abspath(__file__)))

LOG_FILE_NAME = 'logs/pnda-cli.%s.log' % time.time()
logging.basicConfig(filename=LOG_FILE_NAME,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

LOG_FORMATTER = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
LOG = logging.getLogger('everything')
CONSOLE = logging.getLogger('console')
CONSOLE.addHandler(logging.StreamHandler())
CONSOLE.handlers[0].setFormatter(LOG_FORMATTER)

NODE_CONFIG = None
PNDA_ENV = None
START = datetime.datetime.now()
THROW_BASH_ERROR = "cmd_result=${PIPESTATUS[0]} && if [ ${cmd_result} != '0' ]; then exit ${cmd_result}; fi"
RUNFILE = None
MILLI_TIME = lambda: int(round(time.time() * 1000))

class PNDAConfigException(Exception):
    pass

def retry(do_func, *args, **kwargs):
    ret = None
    for _ in xrange(3):
        try:
            ret = do_func(*args, **kwargs)
            break
        except ssl.SSLError, exception:
            LOG.warning(exception)
    return ret

def init_runfile(cluster):
    global RUNFILE
    RUNFILE = 'cli/logs/%s.%s.run' % (cluster, int(time.time()))

def to_runfile(pairs):
    '''
    Append arbitrary pairs to a JSON dict on disk from anywhere in the code
    '''
    mode = 'w' if not os.path.isfile(RUNFILE) else 'r'
    with open(RUNFILE, mode) as runfile:
        jrf = json.load(runfile) if mode == 'r' else {}
        jrf.update(pairs)
        json.dump(jrf, runfile)

def banner():
    print r"    ____  _   ______  ___ "
    print r"   / __ \/ | / / __ \/   |"
    print r"  / /_/ /  |/ / / / / /| |"
    print r" / ____/ /|  / /_/ / ___ |"
    print r"/_/   /_/ |_/_____/_/  |_|"
    print r""

@atexit.register
def display_elasped():
    blue = '\033[94m'
    reset = '\033[0m'
    elapsed = datetime.datetime.now() - START
    CONSOLE.info("%sTotal execution time: %s%s", blue, str(elapsed), reset)

def save_cf_resources(context, cluster_name, params, template):
    params_file = 'cli/logs/%s_%s_cloud-formation-parameters.json' % (cluster_name, context)
    CONSOLE.info('Writing Cloud Formation parameters for %s to %s', cluster_name, params_file)
    with open(params_file, 'w') as outfile:
        json.dump(params, outfile, sort_keys=True, indent=4)

    template_file = 'cli/logs/%s_%s_cloud-formation-template.json' % (cluster_name, context)
    CONSOLE.info('Writing Cloud Formation template for %s to %s', cluster_name, template_file)
    with open(template_file, 'w') as outfile:
        json.dump(json.loads(template), outfile, sort_keys=True, indent=4)

def generate_instance_templates(template_data, instance_name, instance_count):
    if instance_name in template_data['Resources']:
        instance_def = json.dumps(template_data['Resources'].pop(instance_name))

    for instance_index in range(0, instance_count):
        instance_def_n = instance_def.replace('$node_idx$', str(instance_index))
        template_data['Resources']['%s%s' % (instance_name, instance_index)] = json.loads(instance_def_n)

def generate_template_file(flavor, datanodes, opentsdbs, kafkas, zookeepers, esmasters, esingests, esdatas, escoords, esmultis, logstashs):
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

    generate_instance_templates(template_data, 'instanceCdhDn', datanodes)
    generate_instance_templates(template_data, 'instanceOpenTsdb', opentsdbs)
    generate_instance_templates(template_data, 'instanceKafka', kafkas)
    generate_instance_templates(template_data, 'instanceZookeeper', zookeepers)
    generate_instance_templates(template_data, 'instanceESMaster', esmasters)
    generate_instance_templates(template_data, 'instanceESData', esdatas)
    generate_instance_templates(template_data, 'instanceESIngest', esingests)
    generate_instance_templates(template_data, 'instanceESCoordinator', escoords)
    generate_instance_templates(template_data, 'instanceESMulti', esmultis)
    generate_instance_templates(template_data, 'instanceLogstash', logstashs)

    return json.dumps(template_data)

def get_instance_map(cluster, existing_machines_def_file):
    instance_map = {}
    if existing_machines_def_file is not None:
        instance_map = {}
        existing_machines_def = file(existing_machines_def_file)
        existing_machines = json.load(existing_machines_def)
        for node in existing_machines:
            node_detail = existing_machines[node]
            new_instance = {}
            new_instance['private_ip_address'] = node_detail['ip_address']
            if 'is_bastion' in node_detail and node_detail['is_bastion'] is True:
                new_instance['ip_address'] = node_detail['public_ip_address']
            else:
                new_instance['ip_address'] = None
            new_instance['node_type'] = node_detail['node_type']
            if 'is_saltmaster' in node_detail and node_detail['is_saltmaster'] is True:
                new_instance['is_saltmaster'] = True
            try:
                new_instance['node_idx'] = int(node.split('-')[-1])
            except ValueError:
                new_instance['node_idx'] = ''
            new_instance['name'] = node_detail['ip_address']
            instance_map[cluster + '-' + node] = new_instance
        existing_machines_def.close()
    else:
        CONSOLE.debug('Checking details of created instances')
        region = PNDA_ENV['ec2_access']['AWS_REGION']
        ec2 = boto.ec2.connect_to_region(region)
        reservations = retry(ec2.get_all_reservations)
        instance_map = {}
        for reservation in reservations:
            for instance in reservation.instances:
                if 'pnda_cluster' in instance.tags and instance.tags['pnda_cluster'] == cluster and instance.state == 'running':
                    CONSOLE.debug(instance.private_ip_address, ' ', instance.tags['Name'])
                    instance_map[instance.tags['Name']] = {
                        "public_dns": instance.public_dns_name,
                        "ip_address": instance.ip_address,
                        "private_ip_address":instance.private_ip_address,
                    		  "name": instance.tags['Name'],
                        "node_idx": instance.tags['node_idx'],
                        "node_type": instance.tags['node_type']
                    }
    return instance_map

def get_current_node_counts(cluster, existing_machines_def_file):
    CONSOLE.debug('Counting existing instances')
    node_counts = {'zk':0, 'kafka':0, 'hadoop-dn':0, 'opentsdb':0}
    for _, instance in get_instance_map(cluster, existing_machines_def_file).iteritems():
        if len(instance['node_type']) > 0:
            if instance['node_type'] in node_counts:
                current_count = node_counts[instance['node_type']]
            else:
                current_count = 0
            node_counts[instance['node_type']] = current_count + 1
    return node_counts

def scp(files, cluster, host):
    cmd = "scp -F cli/ssh_config-%s %s %s:%s" % (cluster, ' '.join(files), host, '/tmp')
    CONSOLE.debug(cmd)
    ret_val = subprocess_to_log.call(cmd.split(' '), LOG, host)
    if ret_val != 0:
        raise Exception("Error transferring files to new host %s via SCP. See debug log (%s) for details." % (host, LOG_FILE_NAME))

def ssh(cmds, cluster, host):
    cmd = "ssh -F cli/ssh_config-%s %s" % (cluster, host)
    parts = cmd.split(' ')
    parts.append(';'.join(cmds))
    CONSOLE.debug(json.dumps(parts))
    ret_val = subprocess_to_log.call(parts, LOG, host, scan_for_errors=[r'lost connection', r'\s*Failed:\s*[1-9].*'])
    if ret_val != 0:
        raise Exception("Error running ssh commands on host %s. See debug log (%s) for details." % (host, LOG_FILE_NAME))

def get_volume_info(node_type, config_file):
    volumes = None
    if len(node_type) > 0:
        with open(config_file, 'r') as infile:
            volume_config = yaml.load(infile)
            volume_class = volume_config['instances'][node_type]
            volumes = volume_config['classes'][volume_class]
    return volumes

def export_bootstrap_resources(cluster, files, commands):
    with tarfile.open('cli/logs/%s_%s_bootstrap-resources.tar.gz' % (cluster, MILLI_TIME()), "w:gz") as tar:
        map(tar.add, files)
        command_text = StringIO.StringIO()
        command_text.write('\n'.join([command for command in commands if command.startswith('export')]))
        command_text.seek(0)
        command_info = tarfile.TarInfo(name="cli/additional_exports.sh")
        command_info.size = len(command_text.buf)
        tar.addfile(tarinfo=command_info, fileobj=command_text)

def bootstrap(instance, saltmaster, cluster, flavor, branch, salt_tarball, error_queue, bootstrap_files=None, bootstrap_commands=None):
    ret_val = None
    try:
        ip_address = instance['private_ip_address']
        CONSOLE.debug('bootstrapping %s', ip_address)
        node_type = instance['node_type']
        if len(node_type) <= 0:
            return

        type_script = 'bootstrap-scripts/%s/%s.sh' % (flavor, node_type)
        if not os.path.isfile(type_script):
            type_script = 'bootstrap-scripts/%s.sh' % (node_type)
        node_idx = instance['node_idx']
        files_to_scp = ['cli/pnda_env_%s.sh' % cluster,
                        'bootstrap-scripts/package-install.sh',
                        'bootstrap-scripts/base.sh',
                        'bootstrap-scripts/volume-mappings.sh',
                        type_script]

        volume_config = 'bootstrap-scripts/%s/%s' % (flavor, 'volume-config.yaml')
        requested_volumes = get_volume_info(node_type, volume_config)
        cmds_to_run = ['source /tmp/pnda_env_%s.sh' % cluster,
                       'export PNDA_SALTMASTER_IP=%s' % saltmaster,
                       'export PNDA_CLUSTER=%s' % cluster,
                       'export PNDA_FLAVOR=%s' % flavor,
                       'export PLATFORM_GIT_BRANCH=%s' % branch,
                       'export PLATFORM_SALT_TARBALL=%s' % salt_tarball if salt_tarball is not None else ':',
                       'sudo chmod a+x /tmp/package-install.sh',
                       'sudo chmod a+x /tmp/base.sh',
                       'sudo chmod a+x /tmp/volume-mappings.sh']

        if requested_volumes is not None and 'partitions' in requested_volumes:
            cmds_to_run.append('sudo mkdir -p /etc/pnda/disk-config && echo \'%s\' | sudo tee /etc/pnda/disk-config/partitions' % '\n'.join(
                requested_volumes['partitions']))
        if requested_volumes is not None and 'volumes' in requested_volumes:
            cmds_to_run.append('sudo mkdir -p /etc/pnda/disk-config && echo \'%s\' | sudo tee /etc/pnda/disk-config/requested-volumes' % '\n'.join(
                requested_volumes['volumes']))

        cmds_to_run.append('(sudo -E /tmp/base.sh 2>&1) | tee -a pnda-bootstrap.log; %s' % THROW_BASH_ERROR)

        if node_type == NODE_CONFIG['salt-master-instance'] or "is_saltmaster" in instance:
            files_to_scp.append('bootstrap-scripts/saltmaster-common.sh')
            cmds_to_run.append('sudo chmod a+x /tmp/saltmaster-common.sh')
            cmds_to_run.append('(sudo -E /tmp/saltmaster-common.sh 2>&1) | tee -a pnda-bootstrap.log; %s' % THROW_BASH_ERROR)
            if os.path.isfile('git.pem'):
                files_to_scp.append('git.pem')

        cmds_to_run.append('sudo chmod a+x /tmp/%s.sh' % node_type)
        cmds_to_run.append('(sudo -E /tmp/%s.sh %s 2>&1) | tee -a pnda-bootstrap.log; %s' % (node_type, node_idx, THROW_BASH_ERROR))

        scp(files_to_scp, cluster, ip_address)
        ssh(cmds_to_run, cluster, ip_address)

        if bootstrap_files is not None:
            map(bootstrap_files.put, files_to_scp)
            bootstrap_files.put(volume_config)
        if bootstrap_commands is not None:
            map(bootstrap_commands.put, cmds_to_run)

    except:
        ret_val = 'Error for host %s. %s' % (instance['name'], traceback.format_exc())
        CONSOLE.error(ret_val)
        error_queue.put(ret_val)

def check_config_file():
    if not os.path.exists('pnda_env.yaml'):
        CONSOLE.error('Missing required pnda_env.yaml config file, make a copy of pnda_env_example.yaml named pnda_env.yaml, fill it out and try again.')
        sys.exit(1)

def check_keypair(keyname, keyfile, existing_machines_def_file):
    if not os.path.isfile(keyfile):
        CONSOLE.info('Keyfile.......... ERROR')
        CONSOLE.error('Did not find local file named %s', keyfile)
        sys.exit(1)

    if existing_machines_def_file is not None:
        # TODO: Check ssh access to each machine here
        pass
    else:
        try:
            region = PNDA_ENV['ec2_access']['AWS_REGION']
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


def check_aws_connection():
    region = PNDA_ENV['ec2_access']['AWS_REGION']

    valid_regions = [valid_region.name for valid_region in boto.ec2.regions()]
    if region not in valid_regions:
        CONSOLE.info('AWS connection... ERROR')
        CONSOLE.error('Failed to connect to cloud formation API, ec2 region "%s" was not valid. Valid options are %s', region, json.dumps(valid_regions))
        sys.exit(1)

    conn = boto.cloudformation.connect_to_region(region)
    if conn is None:
        CONSOLE.info('AWS connection... ERROR')
        CONSOLE.error('Failed to connect to cloud formation API, verify ec2_access settings in "pnda_env.yaml" and try again.')
        sys.exit(1)

    try:
        conn.list_stacks()
        CONSOLE.info('AWS connection... OK')
    except:
        CONSOLE.info('AWS connection... ERROR')
        CONSOLE.error('Failed to query cloud formation API, verify ec2_access settings in "pnda_env.yaml" and try again.')
        CONSOLE.error(traceback.format_exc())
        sys.exit(1)

def check_pnda_mirror():

    def raise_error(reason):
        CONSOLE.info('PNDA mirror...... ERROR')
        CONSOLE.error(reason)
        CONSOLE.error(traceback.format_exc())
        sys.exit(1)

    try:
        mirror = PNDA_ENV['mirrors']['PNDA_MIRROR']
        response = requests.head(mirror)
        # expect 200 (open mirror) 403 (no listing allowed)
        # or any redirect (in case of proxy/redirect)
        if response.status_code not in [200, 403, 301, 302, 303, 307, 308]:
            raise_error("PNDA mirror configured and present "
                        "but responded with unexpected status code (%s). " % response.status_code)
        CONSOLE.info('PNDA mirror...... OK')
    except KeyError:
        raise_error('PNDA mirror was not defined in pnda_env.yaml')
    except:
        raise_error("Failed to connect to PNDA mirror. Verify connection "
                    "to %s, check mirror in pnda_env.yaml and try again." % mirror)

def check_config(keyname, keyfile, existing_machines_def_file):
    check_aws_connection()
    check_keypair(keyname, keyfile, existing_machines_def_file)
    check_pnda_mirror()

def write_pnda_env_sh(cluster):
    client_only = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'PLATFORM_GIT_BRANCH']
    with open('cli/pnda_env_%s.sh' % cluster, 'w') as pnda_env_sh_file:
        for section in PNDA_ENV:
            for setting in PNDA_ENV[section]:
                if setting not in client_only:
                    val = '"%s"' % PNDA_ENV[section][setting] if isinstance(PNDA_ENV[section][setting], (list, tuple)) else PNDA_ENV[section][setting]
                    pnda_env_sh_file.write('export %s=%s\n' % (setting, val))

def write_ssh_config(cluster, bastion_ip, os_user, keyfile):
    with open('cli/ssh_config-%s' % cluster, 'w') as config_file:
        config_file.write('host *\n')
        config_file.write('    User %s\n' % os_user)
        config_file.write('    IdentityFile %s\n' % keyfile)
        config_file.write('    StrictHostKeyChecking no\n')
        config_file.write('    UserKnownHostsFile /dev/null\n')
        if bastion_ip:
            config_file.write('    ProxyCommand ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s exec nc %%h %%p\n'
                              % (keyfile, os_user, bastion_ip))
    if not bastion_ip:
        return

    socks_file_path = 'cli/socks_proxy-%s' % cluster
    with open(socks_file_path, 'w') as config_file:
        config_file.write('''
unset SSH_AUTH_SOCK
unset SSH_AGENT_PID

for FILE in $(find /tmp/ssh-* -type s -user ${LOGNAME} -name "agent.[0-9]*" 2>/dev/null)
do
    SOCK_PID=${FILE##*.}

    PID=$(ps -fu${LOGNAME}|awk '/ssh-agent/ && ( $2=='${SOCK_PID}' || $3=='${SOCK_PID}' || $2=='${SOCK_PID}' +1 ) {print $2}')

    if [ -z "$PID" ]
    then
        continue
    fi

    export SSH_AUTH_SOCK=${FILE}
    export SSH_AGENT_PID=${PID}
    break
done

if [ -z "$SSH_AGENT_PID" ]
then
    echo "Starting a new SSH Agent..."
    eval `ssh-agent`
else
    echo "Using existing SSH Agent with pid: ${SSH_AGENT_PID}, sock file: ${SSH_AUTH_SOCK}"
fi\n''')
        config_file.write('eval `ssh-agent`\n')
        config_file.write('ssh-add %s\n' % keyfile)
        config_file.write('ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -A -D 9999 %s@%s\n' % (keyfile, os_user, bastion_ip))
    mode = os.stat(socks_file_path).st_mode
    os.chmod(socks_file_path, mode | (mode & 292) >> 2)

def process_thread_errors(action, errors):
    while not errors.empty():
        error_message = errors.get()
        raise Exception("Error %s, error msg: %s. See debug log (%s) for details." % (action, error_message, LOG_FILE_NAME))

def wait_on_host_operations(action, thread_list, bastion_ip, errors):
    # Run the threads in thread_list in sets, waiting for each set to
    # complete before moving onto the next.
    thread_set_size = PNDA_ENV['cli']['MAX_SIMULTANEOUS_OUTBOUND_CONNECTIONS']
    thread_sets = [thread_list[x:x+thread_set_size] for x in xrange(0, len(thread_list), thread_set_size)]
    for thread_set in thread_sets:
        for thread in thread_set:
            thread.start()
            if bastion_ip:
                # If there is no bastion, start all threads at once. Otherwise leave a gap
                # between starting each one to avoid overloading the bastion with too many
                # inbound connections and possibly having one rejected.
                time.sleep(2)

        for thread in thread_set:
            thread.join()

    process_thread_errors(action, errors)

def wait_for_host_connectivity(hosts, cluster, bastion_ip):
    wait_threads = []
    wait_errors = Queue.Queue()

    def do_wait(host, cluster, wait_errors):
        time_start = MILLI_TIME()
        while True:
            try:
                CONSOLE.info('Checking connectivity to %s', host)
                ssh(['ls ~'], cluster, host)
                break
            except:
                LOG.debug('Still waiting for connectivity to %s.', host)
                LOG.info(traceback.format_exc())
                if MILLI_TIME() - time_start > 10 * 60 * 1000:
                    ret_val = 'Giving up waiting for connectivity to %s' % host
                    wait_errors.put(ret_val)
                    CONSOLE.error(ret_val)
                    break
                time.sleep(2)

    for host in hosts:
        thread = Thread(target=do_wait, args=[host, cluster, wait_errors])
        wait_threads.append(thread)

    wait_on_host_operations('waiting for host connectivity', wait_threads, bastion_ip, wait_errors)

def fetch_stack_events(cfn_cnxn, stack_name):
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

def create(template_data, cluster, flavor, keyname, no_config_check, dry_run, branch, existing_machines_def_file):

    init_runfile(cluster)
    bastion = NODE_CONFIG['bastion-instance']

    to_runfile({'cmdline':sys.argv,
                'bastion':bastion,
                'saltmaster':NODE_CONFIG['salt-master-instance']})

    keyfile = '%s.pem' % keyname

    if existing_machines_def_file is None:
        region = PNDA_ENV['ec2_access']['AWS_REGION']
        aws_availability_zone = PNDA_ENV['ec2_access']['AWS_AVAILABILITY_ZONE']
        cf_parameters = [('keyName', keyname), ('pndaCluster', cluster), ('awsAvailabilityZone', aws_availability_zone)]
        for parameter in PNDA_ENV['cloud_formation_parameters']:
            cf_parameters.append((parameter, PNDA_ENV['cloud_formation_parameters'][parameter]))

        if not no_config_check:
            check_config(keyname, keyfile, None)

        save_cf_resources('create_%s' % MILLI_TIME(), cluster, cf_parameters, template_data)
        if dry_run:
            CONSOLE.info('Dry run mode completed')
            sys.exit(0)

    if existing_machines_def_file is None:
        check_config(keyname, keyfile, existing_machines_def_file)

        CONSOLE.info('Creating Cloud Formation stack')
        conn = boto.cloudformation.connect_to_region(region)
        stack_status = 'CREATING'
        conn.create_stack(cluster,
                          template_body=template_data,
                          parameters=cf_parameters)

        while stack_status in ['CREATE_IN_PROGRESS', 'CREATING']:
            time.sleep(5)
            CONSOLE.info('Stack is: ' + stack_status)
            stacks = retry(conn.describe_stacks, cluster)
            if len(stacks) > 0:
                stack_status = stacks[0].stack_status

        if stack_status != 'CREATE_COMPLETE':
            CONSOLE.error('Stack did not come up, status is: ' + stack_status)
            fetch_stack_events(conn, cluster)
            sys.exit(1)

    instance_map = get_instance_map(cluster, existing_machines_def_file)

    bastion_ip = ''
    bastion_name = cluster + '-' + bastion
    if bastion_name in instance_map.keys():
        bastion_ip = instance_map[cluster + '-' + bastion]['ip_address']

    write_ssh_config(cluster, bastion_ip,
                     PNDA_ENV['ec2_access']['OS_USER'], os.path.abspath(keyfile))
    CONSOLE.debug('The PNDA console will come up on: http://%s', instance_map[cluster + '-' + NODE_CONFIG['console-instance']]['private_ip_address'])

    if bastion_ip:
        time_start = MILLI_TIME()
        while True:
            try:
                nc_ssh_cmd = 'ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s' % (keyfile,
                                                                                                              PNDA_ENV['ec2_access']['OS_USER'], bastion_ip)
                nc_install_cmd = nc_ssh_cmd.split(' ')
                nc_install_cmd.append('sudo yum install -y nc || echo nc already installed')
                ret_val = subprocess_to_log.call(nc_install_cmd, LOG, bastion_ip)
                if ret_val != 0:
                    raise Exception("Error running ssh commands on host %s. See debug log (%s) for details." % (bastion_ip, LOG_FILE_NAME))
                break
            except:
                CONSOLE.info('Still waiting for connectivity to bastion. See debug log (%s) for details.', LOG_FILE_NAME)
                LOG.info(traceback.format_exc())
                if MILLI_TIME() - time_start > 10 * 60 * 1000:
                    CONSOLE.error('Giving up waiting for connectivity to %s', bastion_ip)
                    sys.exit(-1)
                time.sleep(2)

    wait_for_host_connectivity([instance_map[h]['private_ip_address'] for h in instance_map], cluster, bastion_ip)

    CONSOLE.info('Bootstrapping saltmaster. Expect this to take a few minutes, check the debug log for progress (%s).', LOG_FILE_NAME)
    saltmaster = instance_map[cluster + '-' + NODE_CONFIG['salt-master-instance']]
    saltmaster_ip = saltmaster['private_ip_address']
    platform_salt_tarball = None
    if 'PLATFORM_SALT_LOCAL' in PNDA_ENV['platform_salt']:
        local_salt_path = PNDA_ENV['platform_salt']['PLATFORM_SALT_LOCAL']
        platform_salt_tarball = '%s.tmp' % str(uuid.uuid1())
        with tarfile.open(platform_salt_tarball, mode='w:gz') as archive:
            archive.add(local_salt_path, arcname='platform-salt', recursive=True)
        scp([platform_salt_tarball], cluster, saltmaster_ip)
        os.remove(platform_salt_tarball)

    bootstrap_threads = []
    bootstrap_errors = Queue.Queue()
    bootstrap_files = Queue.Queue()
    bootstrap_commands = Queue.Queue()

    bootstrap(saltmaster, saltmaster_ip, cluster, flavor, branch, platform_salt_tarball, bootstrap_errors, bootstrap_files, bootstrap_commands)
    process_thread_errors('bootstrapping saltmaster', bootstrap_errors)

    CONSOLE.info('Bootstrapping other instances. Expect this to take a few minutes, check the debug log for progress (%s).', LOG_FILE_NAME)
    for key, instance in instance_map.iteritems():
        if '-' + NODE_CONFIG['salt-master-instance'] not in key:
            thread = Thread(target=bootstrap, args=[instance, saltmaster_ip,
                                                    cluster, flavor, branch,
                                                    platform_salt_tarball, bootstrap_errors,
                                                    bootstrap_files, bootstrap_commands])
            bootstrap_threads.append(thread)

    wait_on_host_operations('bootstrapping host', bootstrap_threads, bastion_ip, bootstrap_errors)

    export_bootstrap_resources(cluster, list(set(bootstrap_files.queue)), list(set(bootstrap_commands.queue)))
    time.sleep(30)

    CONSOLE.info('Running salt to install software. Expect this to take 45 minutes or more, check the debug log for progress (%s).', LOG_FILE_NAME)
    bastion = NODE_CONFIG['bastion-instance']
    ssh(['(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed "*" state.highstate queue=True 2>&1) | tee -a pnda-salt.log; %s'
         % THROW_BASH_ERROR,
         '(sudo CLUSTER=%s salt-run --log-level=debug state.orchestrate orchestrate.pnda 2>&1) | tee -a pnda-salt.log; %s'
         % (cluster, THROW_BASH_ERROR)], cluster, saltmaster_ip)

    return instance_map[cluster + '-' + NODE_CONFIG['console-instance']]['private_ip_address']

def expand(template_data, cluster, flavor, old_datanodes, old_kafka, do_orchestrate, keyname, no_config_check, dry_run, branch, existing_machines_def_file):
    keyfile = '%s.pem' % keyname

    if existing_machines_def_file is None:

        if not no_config_check:
            check_config(keyname, keyfile, existing_machines_def_file)

        region = PNDA_ENV['ec2_access']['AWS_REGION']
        cf_parameters = [('keyName', keyname), ('pndaCluster', cluster)]
        for parameter in PNDA_ENV['cloud_formation_parameters']:
            cf_parameters.append((parameter, PNDA_ENV['cloud_formation_parameters'][parameter]))

        save_cf_resources('expand_%s' % MILLI_TIME(), cluster, cf_parameters, template_data)
        if dry_run:
            CONSOLE.info('Dry run mode completed')
            sys.exit(0)

        CONSOLE.info('Updating Cloud Formation stack')
        conn = boto.cloudformation.connect_to_region(region)
        stack_status = 'UPDATING'
        retry(conn.update_stack, cluster,
              template_body=template_data,
              parameters=cf_parameters)

        while stack_status in ['UPDATE_IN_PROGRESS', 'UPDATING', 'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS']:
            time.sleep(5)
            CONSOLE.info('Stack is: ' + stack_status)
            stacks = retry(conn.describe_stacks, cluster)
            if len(stacks) > 0:
                stack_status = stacks[0].stack_status

        if stack_status != 'UPDATE_COMPLETE':
            CONSOLE.error('Stack did not come up, status is: ' + stack_status)
            fetch_stack_events(conn, cluster)
            sys.exit(1)

    instance_map = get_instance_map(cluster, existing_machines_def_file)
    bastion = NODE_CONFIG['bastion-instance']
    bastion_ip = ''
    bastion_name = cluster + '-' + bastion
    if bastion_name in instance_map.keys():
        bastion_ip = instance_map[cluster + '-' + bastion]['ip_address']
    write_ssh_config(cluster, bastion_ip,
                     PNDA_ENV['ec2_access']['OS_USER'], os.path.abspath(keyfile))
    saltmaster = instance_map[cluster + '-' + NODE_CONFIG['salt-master-instance']]
    saltmaster_ip = saltmaster['private_ip_address']

    wait_for_host_connectivity([instance_map[h]['private_ip_address'] for h in instance_map], cluster, bastion_ip)
    CONSOLE.info('Bootstrapping new instances. Expect this to take a few minutes, check the debug log for progress. (%s)', LOG_FILE_NAME)
    bootstrap_threads = []
    bootstrap_errors = Queue.Queue()
    for _, instance in instance_map.iteritems():
        if len(instance['node_type']) > 0:
            if ((instance['node_type'] == 'hadoop-dn' and int(instance['node_idx']) >= old_datanodes
                 or instance['node_type'] == 'kafka' and int(instance['node_idx']) >= old_kafka)):
                thread = Thread(target=bootstrap, args=[instance, saltmaster_ip, cluster, flavor, branch, None, bootstrap_errors])
                bootstrap_threads.append(thread)

    wait_on_host_operations('bootstrapping host', bootstrap_threads, bastion_ip, bootstrap_errors)

    time.sleep(30)

    CONSOLE.info('Running salt to install software. Expect this to take 10 - 20 minutes, check the debug log for progress. (%s)', LOG_FILE_NAME)

    expand_commands = ['(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed "*" state.sls hostsfile queue=True 2>&1)' +
                       ' | tee -a pnda-salt.log; %s' % THROW_BASH_ERROR,
                       '(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed -C "G@pnda:is_new_node" state.highstate queue=True 2>&1)' +
                       ' | tee -a pnda-salt.log; %s' % THROW_BASH_ERROR]
    if do_orchestrate:
        CONSOLE.info('Including orchestrate because new Hadoop datanodes are being added')
        expand_commands.append('(sudo CLUSTER=%s salt-run --log-level=debug state.orchestrate orchestrate.pnda-expand 2>&1)' % cluster +
                               ' | tee -a pnda-salt.log; %s' % THROW_BASH_ERROR)

    ssh(expand_commands, cluster, saltmaster_ip)
    CONSOLE.info("Nodes may reboot due to kernel upgrade, wait for few minutes")

    return instance_map[cluster + '-' + NODE_CONFIG['console-instance']]['private_ip_address']

def destroy(cluster, existing_machines_def_file):
    CONSOLE.info('Removing ssh access scripts')
    socks_proxy_file = 'cli/socks_proxy-%s' % cluster
    if os.path.exists(socks_proxy_file):
        os.remove(socks_proxy_file)
    ssh_config_file = 'cli/ssh_config-%s' % cluster
    if os.path.exists(ssh_config_file):
        os.remove(ssh_config_file)
    env_sh_file = 'cli/pnda_env_%s.sh' % cluster
    if os.path.exists(env_sh_file):
        os.remove(env_sh_file)

    if existing_machines_def_file is None:
        CONSOLE.info('Deleting Cloud Formation stack')
        region = PNDA_ENV['ec2_access']['AWS_REGION']
        conn = boto.cloudformation.connect_to_region(region)
        stack_status = 'DELETING'
        retry(conn.delete_stack, cluster)
        while stack_status in ['DELETE_IN_PROGRESS', 'DELETING']:
            time.sleep(5)
            CONSOLE.info('Stack is: ' + stack_status)
            try:
                stacks = retry(conn.describe_stacks, cluster)
            except:
                stacks = []

            if len(stacks) > 0:
                stack_status = stacks[0].stack_status
            else:
                stack_status = None

def valid_flavors():
    cfn_dirs = [dir_name for dir_name in os.listdir('../cloud-formation') if  os.path.isdir(os.path.join('../cloud-formation', dir_name))]
    bootstap_dirs = [dir_name for dir_name in os.listdir('../bootstrap-scripts') if  os.path.isdir(os.path.join('../bootstrap-scripts', dir_name))]

    return list(set(cfn_dirs + bootstap_dirs))

def main():
    print 'Saving debug log to %s' % LOG_FILE_NAME

    if not os.path.basename(os.getcwd()) == "cli":
        print 'Please run from inside the /cli directory'
        sys.exit(1)

    ###
    # Process user input
    ###
    input_validator = UserInputValidator(valid_flavors())
    fields = input_validator.parse_user_input()

    create_cloud_infra = fields['x_machines_definition'] is None

    os.chdir('../')

    ###
    # Process & validate YAML configuration
    # TODO: refactor out in a similar way to user input validation and share common code
    ###

    global PNDA_ENV
    check_config_file()
    with open('pnda_env.yaml', 'r') as infile:
        PNDA_ENV = yaml.load(infile)

        if not create_cloud_infra:
            CONSOLE.info('Installing to existing infra, defined in %s', fields['x_machines_definition'])
            node_counts = get_current_node_counts(fields['pnda_cluster'], fields['x_machines_definition'])
            fields['datanodes'] = node_counts['hadoop-dn']
            fields['opentsdb_nodes'] = node_counts['opentsdb']
            fields['kafka_nodes'] = node_counts['kafka']
            fields['zk_nodes'] = node_counts['zk']
        else:
            os.environ['AWS_ACCESS_KEY_ID'] = PNDA_ENV['ec2_access']['AWS_ACCESS_KEY_ID']
            os.environ['AWS_SECRET_ACCESS_KEY'] = PNDA_ENV['ec2_access']['AWS_SECRET_ACCESS_KEY']
            print 'Using ec2 credentials:'
            print '  AWS_REGION = %s' % PNDA_ENV['ec2_access']['AWS_REGION']
            print '  AWS_ACCESS_KEY_ID = %s' % PNDA_ENV['ec2_access']['AWS_ACCESS_KEY_ID']
            print '  AWS_SECRET_ACCESS_KEY = %s' % PNDA_ENV['ec2_access']['AWS_SECRET_ACCESS_KEY']

    # read ES cluster setup from yaml
    es_fields = {
        "elk_es_master":PNDA_ENV['elk-cluster']['MASTER_NODES'],
        "elk_es_data":PNDA_ENV['elk-cluster']['DATA_NODES'],
        "elk_es_ingest":PNDA_ENV['elk-cluster']['INGEST_NODES'],
        "elk_es_coordinator":PNDA_ENV['elk-cluster']['COORDINATING_NODES'],
        "elk_es_multi":PNDA_ENV['elk-cluster']['MULTI_ROLE_NODES'],
        "elk_logstash":PNDA_ENV['elk-cluster']['LOGSTASH_NODES']
    }

    # TODO parsing and validation of YAML needs to be factored out
    range_validator = input_validator.get_range_validator()
    try:
        for field, val in es_fields.items():
            numeric_val = int(val) if val is not None else 0
            if range_validator is not None and not range_validator.validate_field(field, numeric_val):
                raise PNDAConfigException("Error in pnda_env.yaml: %s must be in range (%s)" % (field, range_validator.get_validation_rule(field)))
            es_fields[field] = numeric_val
    except ValueError:
        raise PNDAConfigException("Error in pnda_env.yaml: %s must be a number" % field)

    # Branch defaults to master
    # but may be overridden by pnda_env.yaml
    # and both of those are overridden by --branch
    branch = 'master'
    if 'PLATFORM_GIT_BRANCH' in PNDA_ENV['platform_salt']:
        branch = PNDA_ENV['platform_salt']['PLATFORM_GIT_BRANCH']
    if fields['branch'] is not None:
        branch = fields['branch']

    if not os.path.isfile('git.pem') and create_cloud_infra:
        with open('git.pem', 'w') as git_key_file:
            git_key_file.write('If authenticated access to the platform-salt git repository is required then' +
                               ' replace this file with a key that grants access to the git server.\n\n' +
                               'Set PLATFORM_GIT_REPO_HOST and PLATFORM_GIT_REPO_URI in pnda_env.yaml, for example:\n' +
                               'PLATFORM_GIT_REPO_HOST: github.com\n' +
                               'PLATFORM_GIT_REPO_URI: git@github.com:pndaproject/platform-salt.git\n')

    global NODE_CONFIG
    if not create_cloud_infra:
        NODE_CONFIG = {'bastion-instance':''}
        existing_machines_def = file(fields['x_machines_definition'])
        existing_machines = json.load(existing_machines_def)
        for node in existing_machines:
            if 'is_bastion' in existing_machines[node] and existing_machines[node]['is_bastion'] is True:
                NODE_CONFIG['bastion-instance'] = node
            if 'is_saltmaster' in existing_machines[node] and existing_machines[node]['is_saltmaster'] is True:
                NODE_CONFIG['salt-master-instance'] = node
            if 'is_console' in existing_machines[node] and existing_machines[node]['is_console'] is True:
                NODE_CONFIG['console-instance'] = node
        existing_machines_def.close()
    else:
        if fields['flavor'] is not None:
            node_config_file = file('cloud-formation/%s/config.json' % fields["flavor"])
            NODE_CONFIG = json.load(node_config_file)
            node_config_file.close()

    do_orchestrate = False
    template_data = None

    write_pnda_env_sh(fields['pnda_cluster'])

    ###
    # Handle destroy command
    ###
    if fields['command'] == 'destroy':
        destroy(fields['pnda_cluster'], fields['x_machines_definition'])
        sys.exit(0)

    ###
    # Handle expand command
    ###
    if fields['command'] == 'expand':
        node_counts = get_current_node_counts(fields['pnda_cluster'], fields['x_machines_definition'])

        if fields['datanodes'] < node_counts['hadoop-dn']:
            print "You cannot shrink the cluster using this CLI, existing number of datanodes is: %s" % node_counts['hadoop-dn']
            sys.exit(1)
        elif fields['datanodes'] > node_counts['hadoop-dn']:
            print "Increasing the number of datanodes from %s to %s" % (node_counts['hadoop-dn'], fields['datanodes'])
            do_orchestrate = True
        if fields['kafka_nodes'] < node_counts['kafka']:
            print "You cannot shrink the cluster using this CLI, existing number of kafkanodes is: %s" % node_counts['kafka']
            sys.exit(1)
        elif fields['kafka_nodes'] > node_counts['kafka']:
            print "Increasing the number of kafkanodes from %s to %s" % (node_counts['kafka'], fields['kafka_nodes'])

        if create_cloud_infra:
            template_data = generate_template_file(fields['flavor'], fields['datanodes'], node_counts['opentsdb'], fields['kafka_nodes'], node_counts['zk'],
                                                   es_fields['elk_es_master'], es_fields['elk_es_ingest'], es_fields['elk_es_data'],
                                                   es_fields['elk_es_coordinator'], es_fields['elk_es_multi'], es_fields['elk_logstash'])

        expand(template_data, fields['pnda_cluster'], fields['flavor'], node_counts['hadoop-dn'], node_counts['kafka'],
               do_orchestrate, fields['keyname'], fields["no_config_check"], fields['dry_run'], branch, fields['x_machines_definition'])

        sys.exit(0)

    ###
    # Handle create command
    ###
    if fields['command'] == 'create':
        if create_cloud_infra:
            template_data = generate_template_file(fields['flavor'], fields['datanodes'], fields['opentsdb_nodes'], fields['kafka_nodes'], fields['zk_nodes'],
                                                   es_fields['elk_es_master'], es_fields['elk_es_ingest'], es_fields['elk_es_data'],
                                                   es_fields['elk_es_coordinator'], es_fields['elk_es_multi'], es_fields['elk_logstash'])

        console_dns = create(template_data, fields['pnda_cluster'], fields['flavor'],
                             fields['keyname'], fields["no_config_check"], fields['dry_run'],
                             branch, fields['x_machines_definition'])

        CONSOLE.info('Use the PNDA console to get started: http://%s', console_dns)
        CONSOLE.info(' Access hints:')
        CONSOLE.info('  - The script ./socks_proxy-%s sets up port forwarding to the PNDA cluster with SSH acting as a SOCKS server on localhost:9999',
                     fields['pnda_cluster'])
        CONSOLE.info('  - Please review ./socks_proxy-%s and ensure it complies with your local security policies before use', fields['pnda_cluster'])
        CONSOLE.info('  - Set up a socks proxy with: chmod +x socks_proxy-%s; ./socks_proxy-%s', fields['pnda_cluster'], fields['pnda_cluster'])
        CONSOLE.info('  - SSH to a node with: ssh -F ssh_config-%s <private_ip>', fields['pnda_cluster'])

if __name__ == "__main__":
    try:
        main()
    except Exception as exception:
        CONSOLE.error(exception)
        raise
