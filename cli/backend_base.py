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
#   Purpose: Backend base implementation for creating PNDA

import uuid
import sys
import os
import os.path
import json
import time
import traceback
import tarfile
import Queue
import StringIO
import glob
import random

from threading import Thread

import yaml
import requests
import jinja2
import pnda_cli_utils as utils
from pnda_cli_utils import PNDAConfigException
from pnda_cli_utils import MILLI_TIME
from pnda_cli_utils import to_runfile
from ssh_client import SshClient
from service_registry_consul import ServiceRegistryConsul
import subprocess_to_log

utils.init_logging()
CONSOLE = utils.CONSOLE_LOGGER
LOG = utils.FILE_LOGGER
LOG_FILE_NAME = utils.LOG_FILE_NAME
THROW_BASH_ERROR = "cmd_result=${PIPESTATUS[0]} && if [ ${cmd_result} != '0' ]; then exit ${cmd_result}; fi"
PNDAPROJECTCA = "pndaproject-ca"

class BaseBackend(object):
    '''
    Base class for deploying PNDA
    Must to be overridden to support specific deployment targets
    '''
    def __init__(self, pnda_env, cluster, no_config_check, flavor, keyfile, branch):
        self._pnda_env = pnda_env
        self._cluster = cluster
        self._ssh_client = SshClient(self._cluster)
        self._no_config_check = no_config_check
        self._flavor = flavor
        self._keyfile = keyfile
        self._branch = branch
        if flavor is not None:
            self._node_config = self.load_node_config()
        self._cached_instance_map = None
        self._set_up_env_conf()
        self._service_registry = ServiceRegistryConsul(self._ssh_client)

    ### Public interface
    def create(self, node_counts):
        '''
        Create a new PNDA deployment
        Parameters:
         - node_counts: a dictionary containing counts of the number of nodes required.
                        Should contain the following keys: 'datanodes', 'opentsdb_nodes', 'kafka_nodes', 'zk_nodes'

        '''
        if not self._no_config_check:
            self._check_config(self._keyfile)
        self.pre_install_pnda(node_counts)
        self._set_up_env_conf()
        self._install_pnda()
        self.post_install_pnda()

        instance_map = self.get_instance_map()
        return instance_map[self._cluster + '-' + self._node_config['console-instance']]['private_ip_address']

    def expand(self, node_counts, do_orchestrate):
        '''
        Expand an existing PNDA deployment
        Parameters:
         - node_counts:    a dictionary containing counts of the number of nodes required.
                           Should contain the following keys: 'datanodes', 'opentsdb_nodes', 'kafka_nodes', 'zk_nodes'
         - do_orchestrate: set to True to include the orchestrate phase during PNDA installation, this is required when
                           performing an operation that affects the Hadoop cluster, e.g. increasing the number of datanodes
        '''
        if not self._no_config_check:
            self._check_config(self._keyfile)
        self.pre_expand_pnda(node_counts)
        self._expand_pnda(do_orchestrate)
        self.post_expand_pnda()

        instance_map = self.get_instance_map()
        return instance_map[self._cluster + '-' + self._node_config['console-instance']]['private_ip_address']

    def destroy(self):
        '''
        Destroy an existing PNDA deployment
        '''
        self.pre_destroy_pnda()
        self._destroy_pnda()
        self.post_destroy_pnda()

    def get_instance_map(self, check_bootstrapped=False):
        '''
        Generate a descriptor of the instances that make up the PNDA cluster
        Parameters:
         - check_bootstrapped: set to True to include a 'bootstrapped' flag on each element that indicated whether that instance is already bootstrapped.
        Notes:
         - The instance map is cached. Use clear_instance_map_cache() to force recalculation otherwise the cached version will be returned.
           This is because the operation is potentially slow if check_bootstrapped is used.
        '''
        if not self._cached_instance_map:
            instance_map = self.fill_instance_map()
            self._ssh_client.set_ip_mappings(instance_map)
            if check_bootstrapped:
                self._check_hosts_bootstrapped(instance_map, self._cluster + '-' + self._node_config['bastion-instance'] in instance_map)

            self._cached_instance_map = instance_map

        return self._cached_instance_map

    def clear_instance_map_cache(self):
        '''
        Clear the instance map cache so that the instance map will be recalculated on the next call to get_instance_map.
        '''
        self._cached_instance_map = None

    ### Methods that may be overridden in implementation class to introduce deployment
    ### specific behaviour
    def check_target_specific_config(self):
        '''
        Perform checks specific to the deployment target in question
        '''
        pass

    def load_node_config(self):
        '''
        Generate a config descriptor that indicates certain special nodes (i.e. console, bastion & saltmaster)
        '''
        pass

    def fill_instance_map(self):
        '''
        Generate a descriptor of the instances that make up the PNDA cluster
        '''
        pass

    def pre_install_pnda(self, node_counts):
        '''
        Hook that is called before PNDA is installed to allow operations specific to the deployment target in question
        '''
        pass

    def post_install_pnda(self):
        '''
        Hook that is called after PNDA is installed to allow operations specific to the deployment target in question
        '''
        pass

    def pre_expand_pnda(self, node_counts):
        '''
        Hook that is called before PNDA is expanded to allow operations specific to the deployment target in question
        '''
        pass

    def post_expand_pnda(self):
        '''
        Hook that is called after PNDA is expanded to allow operations specific to the deployment target in question
        '''
        pass

    def pre_destroy_pnda(self):
        '''
        Hook that is called before PNDA is destroyed to allow operations specific to the deployment target in question
        '''
        pass

    def post_destroy_pnda(self):
        '''
        Hook that is called after PNDA is destroyed to allow operations specific to the deployment target in question
        '''
        pass
    ### END (Methods that should be overridden in implementation class) ###

    def _ship_certs(self, saltmaster_ip):
        platform_certs_tarball = None
        try:
            local_certs_path = self._pnda_env['security']['SECURITY_MATERIAL_PATH']
            platform_certs_tarball = '%s.tar.gz' % str(uuid.uuid1())
            if self._pnda_env['security']['SECURITY_MODE'] == 'enforced':
                self._ensure_certs()
            with tarfile.open(platform_certs_tarball, mode='w:gz') as archive:
                # Exclude CA's private key
                keys = glob.glob(os.path.join(local_certs_path, '*.key'))
                if len(keys) == 1:
                    skip = os.path.normpath(os.path.join('security-certs', os.path.basename(keys[0])))
                    filter_function = lambda tarinfo: None if os.path.normpath(tarinfo.name) == skip else tarinfo
                else:
                    filter_function = None

                archive.add(local_certs_path, arcname='security-certs', recursive=True, filter=filter_function)
        except Exception as exception:
            if self._pnda_env['security']['SECURITY_MODE'] == 'permissive':
                LOG.warning(exception)
                return None
            else:
                CONSOLE.error(exception)
                raise PNDAConfigException("Error: %s must contain certificates" % local_certs_path)

        self._ssh_client.scp([platform_certs_tarball], saltmaster_ip)
        os.remove(platform_certs_tarball)

        return platform_certs_tarball

    def _call(self, cmd):
        ret_val = subprocess_to_log.call(cmd.split(' '), LOG)
        if ret_val != 0:
            raise Exception("Error running %s" % cmd)

    def _ensure_certs(self):
        local_certs_path = self._pnda_env['security']['SECURITY_MATERIAL_PATH']
        exts = ['key', 'crt']
        if self._has_certs(local_certs_path, exts):
            exts = ['key', 'crt', 'yaml']
            if self._has_all_certs(local_certs_path, exts):
                # Proceed with the provided security material
                return
            else:
                # Some security material is missing
                raise Exception("Security material is missing in %s" % local_certs_path)
        else:
            # Generate the security material
            cakey, cacert = self._ensure_ca_cert(local_certs_path)
            self._generate_host_certs(local_certs_path, cakey, cacert)

    def _ensure_ca_cert(self, local_certs_path):
        keys = glob.glob(os.path.join(local_certs_path, '*.key'))
        certs = glob.glob(os.path.join(local_certs_path, '*.crt'))
        if len(keys) == 1 and len(certs) == 1:
            return (keys[0], certs[0])
        if certs and not keys:
            raise Exception("Security material is missing a key in %s" % local_certs_path)
        keyout = os.path.join(local_certs_path, PNDAPROJECTCA+'.key')
        out = os.path.join(local_certs_path, PNDAPROJECTCA+'.crt')
        config = os.path.join(local_certs_path, PNDAPROJECTCA+'.cfg')
        self._generate_ca_conf(config)
        self._call('openssl req -new -x509 -extensions v3_ca -keyout {} -out {} \
-days 3650 -newkey rsa:2048 -sha512 -passout pass:pnda -config {}'.format(keyout, out, config))
        return (keyout, out)

    def _generate_host_certs(self, local_certs_path, cakey, cacert):
        services = [service for service in os.listdir('./platform-certificates') if os.path.isdir(os.path.join('./platform-certificates', service))]
        for service in services:
            sdir = os.path.join(local_certs_path, service)
            if not os.path.isdir(sdir):
                os.makedirs(sdir)
            ymls = glob.glob(os.path.join(sdir, '*.yaml'))
            fqdn = None
            if ymls:
                cfgs = self._load_host_yaml(ymls[0])
                if 'fqdn' in cfgs.keys():
                    fqdn = cfgs['fqdn']
                    CONSOLE.debug('Using detected fqdn:%s', fqdn)
                else:
                    raise Exception("Missing 'fqdn' setting in %s" % ymls[0])
            else:
                fqdn = self._get_fqdn_for_service(service)
                self._generate_host_yaml(os.path.join(sdir, fqdn+'.yaml'), fqdn)
            key_f = os.path.join(sdir, fqdn)
            self._generate_host_conf(key_f+'.cfg', fqdn)
            self._generate_host_ext_conf(key_f+'.ext', fqdn)
            self._call('openssl genrsa -out {key_f}.key 2048'.format(key_f=key_f))
            self._call('openssl req -new -key {key_f}.key -out {key_f}.csr -config {key_f}.cfg'.format(key_f=key_f))
            self._call('openssl x509 -req -days 365 -in {key_f}.csr -extfile {key_f}.ext -CA {cacert} -CAkey {cakey} \
-set_serial {serial} -out {key_f}.crt -sha512 -passin pass:pnda'.format(key_f=key_f, cacert=cacert, cakey=cakey, serial=random.getrandbits(20*8)))

    def _get_role_for_service(self, service):
        role = None
        service_to_role_descriptor = self._get_service_to_role_descriptor()
        if service in service_to_role_descriptor:
            role = service_to_role_descriptor[service]['role']
        return role

    def _get_fqdn_for_service(self, service):
        fqdn = None
        domain = self._pnda_env['domain']['SECOND_LEVEL_DOMAIN'] + '.' + self._pnda_env['domain']['TOP_LEVEL_DOMAIN']
        role = self._get_role_for_service(service)
        if role:
            fqdn = service + '.service.' + domain
        return fqdn

    def _generate_ca_conf(self, path):
        with open(path, 'w') as config_file:
            config_file.write('''
[req]
default_bits=2048
prompt=no
default_md=sha512
distinguished_name=dn
x509_extensions=v3_ca
[ dn ]
O=PNDA Project
OU=Community
emailAddress=info@pndaproject.io
CN=PNDA Certificate Authority
[ v3_ca ]
basicConstraints=critical,CA:true
keyUsage=cRLSign,keyCertSign
''')

    def _generate_host_yaml(self, path, fqdn):
        with open(path, 'w') as config_file:
            data = dict(
                fqdn=fqdn
                )
            yaml.dump(data, config_file, default_flow_style=False)

    def _load_host_yaml(self, path):
        with open(path, 'r') as config_file:
            return yaml.load(config_file)

    def _generate_host_conf(self, path, fqdn):
        with open(path, 'w') as config_file:
            config_file.write('''
[req]
default_bits=2048
prompt=no
default_md=sha512
distinguished_name=dn
[ dn ]
O=PNDA Project
OU=Community
emailAddress=info@pndaproject.io
''')
            config_file.write('CN=%s\n' % fqdn)

    def _generate_host_ext_conf(self, path, fqdn):
        with open(path, 'w') as config_file:
            config_file.write('''
authorityKeyIdentifier=keyid,issuer
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[ alt_names ]
''')
            config_file.write('DNS.1 = %s\n' % fqdn)


    def _has_all_certs(self, local_certs_path, exts):
        ret = True
        roles = [role for role in os.listdir('./platform-certificates') if os.path.isdir(os.path.join('./platform-certificates', role))]
        for role in roles:
            for ext in exts:
                file_name = os.path.join(local_certs_path, role, '*.'+ext)
                files = glob.glob(file_name)
                if not files:
                    CONSOLE.debug('Missing %s', file_name)
                    ret = False
        return ret

    def _has_certs(self, local_certs_path, exts):
        for ext in exts:
            files = glob.glob(os.path.join(local_certs_path, '*', '*.'+ext))
            if files:
                CONSOLE.debug('Security material was detected: %s', files[0])
                return True
        CONSOLE.debug('No security material was detected')
        return False

    def _get_volume_info(self, node_type, config_file):
        volumes = None
        if node_type:
            config_file_list = config_file.split("/")
            config_file_path = "%s/%s" % (config_file_list[0], config_file_list[1])
            template_loader = jinja2.FileSystemLoader(searchpath=config_file_path)
            template_env = jinja2.Environment(loader=template_loader)
            template = template_env.get_template(config_file_list[2])
            volume_config = yaml.safe_load(template.render(pnda_env=self._pnda_env))
            volume_class = volume_config['instances'][node_type]
            volumes = volume_config['classes'][volume_class]

        return volumes

    def _set_up_env_conf(self):
        self._write_pnda_env_sh(self._cluster)
        self._ssh_client.write_ssh_config(self._get_bastion_ip(),
                                          self._pnda_env['infrastructure']['OS_USER'],
                                          os.path.abspath(self._keyfile))

    def _write_pnda_env_sh(self, cluster):
        client_only = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'PLATFORM_GIT_BRANCH']
        with open('cli/pnda_env_%s.sh' % cluster, 'w') as pnda_env_sh_file:
            for section in self._pnda_env:
                for setting in self._pnda_env[section]:
                    if setting not in client_only:
                        val = '"%s"' % self._pnda_env[section][setting] if isinstance(
                            self._pnda_env[section][setting], (list, tuple)) else self._pnda_env[section][setting]
                        pnda_env_sh_file.write('export %s=%s\n' % (setting, val))

    def _bootstrap(self, instance, saltmaster, cluster, flavor, branch,
                   salt_tarball, certs_tarball, error_queue,
                   bootstrap_files=None, bootstrap_commands=None):
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
                            'bootstrap-scripts/base_post.sh',
                            'bootstrap-scripts/volume-mappings.sh',
                            type_script]

            volume_config = 'bootstrap-scripts/%s/%s' % (flavor, 'volume-config.yaml')
            requested_volumes = self._get_volume_info(node_type, volume_config)
            cmds_to_run = ['source /tmp/pnda_env_%s.sh' % cluster,
                           'export PNDA_SALTMASTER_IP=%s' % saltmaster,
                           'export PNDA_CLUSTER=%s' % cluster,
                           'export PNDA_FLAVOR=%s' % flavor,
                           'export PLATFORM_GIT_BRANCH=%s' % branch,
                           'export PLATFORM_SALT_TARBALL=%s' % salt_tarball if salt_tarball is not None else ':',
                           'export SECURITY_CERTS_TARBALL=%s' % certs_tarball if certs_tarball is not None else ':',
                           'sudo chmod a+x /tmp/package-install.sh',
                           'sudo chmod a+x /tmp/base.sh',
                           'sudo chmod a+x /tmp/base_post.sh',
                           'sudo chmod a+x /tmp/volume-mappings.sh']

            if requested_volumes is not None and 'partitions' in requested_volumes:
                cmds_to_run.append('sudo mkdir -p /etc/pnda/disk-config && echo \'%s\' | sudo tee /etc/pnda/disk-config/partitions' % '\n'.join(
                    requested_volumes['partitions']))
            if requested_volumes is not None and 'volumes' in requested_volumes:
                cmds_to_run.append('sudo mkdir -p /etc/pnda/disk-config && echo \'%s\' | sudo tee /etc/pnda/disk-config/requested-volumes' % '\n'.join(
                    requested_volumes['volumes']))

            cmds_to_run.append('(sudo -E /tmp/base.sh 2>&1) | tee -a pnda-bootstrap.log; %s' % THROW_BASH_ERROR)

            if node_type == self._node_config['salt-master-instance'] or "is_saltmaster" in instance:
                cmds_to_run.append('echo \'%s\' | tee /tmp/minions_list' % '\n'.join(self._get_minions_to_bootstrap()))
                files_to_scp.append('bootstrap-scripts/saltmaster-gen-keys.sh')
                cmds_to_run.append('sudo chmod a+x /tmp/saltmaster-gen-keys.sh')
                files_to_scp.append('bootstrap-scripts/saltmaster-common.sh')
                cmds_to_run.append('sudo chmod a+x /tmp/saltmaster-common.sh')
                cmds_to_run.append('(sudo -E /tmp/saltmaster-common.sh 2>&1) | tee -a pnda-bootstrap.log; %s' % THROW_BASH_ERROR)
                if os.path.isfile('git.pem'):
                    files_to_scp.append('git.pem')
                files_to_scp.append(self._keyfile)
            cmds_to_run.append('sudo chmod a+x /tmp/%s.sh' % node_type)
            cmds_to_run.append('(sudo -E /tmp/%s.sh %s 2>&1) | tee -a pnda-bootstrap.log; %s' % (node_type, node_idx, THROW_BASH_ERROR))
            cmds_to_run.append('(sudo -E /tmp/base_post.sh 2>&1) | tee -a pnda-bootstrap.log; %s' % THROW_BASH_ERROR)
            cmds_to_run.append('touch ~/.bootstrap_complete')

            self._ssh_client.scp(files_to_scp, ip_address)
            self._ssh_client.ssh(cmds_to_run, ip_address)

            if bootstrap_files is not None:
                map(bootstrap_files.put, files_to_scp)
                bootstrap_files.put(volume_config)
            if bootstrap_commands is not None:
                map(bootstrap_commands.put, cmds_to_run)

        except:
            ret_val = 'Error for host %s. %s' % (instance['name'], traceback.format_exc())
            CONSOLE.error(ret_val)
            error_queue.put(ret_val)

    def _process_thread_errors(self, action, errors):
        while not errors.empty():
            error_message = errors.get()
            raise Exception("Error %s, error msg: %s. See debug log (%s) for details." % (action, error_message, LOG_FILE_NAME))

    def _wait_on_host_operations(self, action, thread_list, bastion_used, errors):
        # Run the threads in thread_list in sets, waiting for each set to
        # complete before moving onto the next.
        generic_timeout_minutes = 10
        thread_set_size = self._pnda_env['cli']['MAX_SIMULTANEOUS_OUTBOUND_CONNECTIONS']
        thread_sets = [thread_list[x:x+thread_set_size] for x in xrange(0, len(thread_list), thread_set_size)]
        for thread_set in thread_sets:
            for thread in thread_set:
                thread.start()
                if bastion_used:
                    # If there is no bastion, start all threads at once. Otherwise leave a gap
                    # between starting each one to avoid overloading the bastion with too many
                    # inbound connections and possibly having one rejected.
                    wait_seconds = 2
                    CONSOLE.debug('Staggering connections to avoid overloading bastion, waiting %s seconds', wait_seconds)
                    time.sleep(wait_seconds)

            for thread in thread_set:
                thread.join(generic_timeout_minutes * 60)
                if thread.isAlive():
                    raise Exception("Error %s, timeout after %s minutes. See debug log (%s) for details." % (action, generic_timeout_minutes, LOG_FILE_NAME))

        if errors is not None:
            self._process_thread_errors(action, errors)

    def _wait_for_host_connectivity(self, hosts, bastion_used, check_func=None):
        wait_threads = []

        def do_wait(host):
            while True:
                try:
                    CONSOLE.info('Checking connectivity to %s', host)
                    if check_func is not None:
                        check_func()
                    else:
                        self._ssh_client.ssh(['ls ~'], host)
                    break
                except:
                    LOG.debug('Still waiting for connectivity to %s.', host)
                    LOG.info(traceback.format_exc())
                    time.sleep(2)

        for host in hosts:
            thread = Thread(target=do_wait, args=[host])
            thread.daemon = True
            wait_threads.append(thread)

        self._wait_on_host_operations('waiting for host connectivity', wait_threads, bastion_used, None)

    def _restart_minions(self, hosts, bastion_used):
        wait_threads = []

        def do_cmd(host):
            CONSOLE.info('Restarting salt minion on %s', host)
            self._ssh_client.ssh(['sudo service salt-minion restart'], host)

        for host in hosts:
            thread = Thread(target=do_cmd, args=[host])
            thread.daemon = True
            wait_threads.append(thread)

        self._wait_on_host_operations('restarting salt minions', wait_threads, bastion_used, None)
        time.sleep(60)

    def _export_bootstrap_resources(self, cluster, files, commands):
        with tarfile.open('cli/logs/%s_%s_bootstrap-resources.tar.gz' % (cluster, MILLI_TIME()), "w:gz") as tar:
            map(tar.add, files)
            command_text = StringIO.StringIO()
            command_text.write('\n'.join([command for command in commands if command.startswith('export')]))
            command_text.seek(0)
            command_info = tarfile.TarInfo(name="cli/additional_exports.sh")
            command_info.size = len(command_text.buf)
            tar.addfile(tarinfo=command_info, fileobj=command_text)

    def _get_minions_to_bootstrap(self):
        return ['%s %s' % (instance_name, instance_properties['private_ip_address'])
                for instance_name, instance_properties in self.get_instance_map().iteritems()
                if not instance_properties['bootstrapped']]

    def _get_bastion_ip(self):
        bastion_ip = None
        if self._flavor is not None:
            instance_map = self.get_instance_map()
            bastion = self._node_config['bastion-instance']
            bastion_name = self._cluster + '-' + bastion
            if bastion_name in instance_map.keys():
                bastion_ip = instance_map[self._cluster + '-' + bastion]['ip_address']
        return bastion_ip

    def _install_pnda(self):
        to_runfile({'cmdline':sys.argv,
                    'bastion':self._node_config['bastion-instance'],
                    'saltmaster':self._node_config['salt-master-instance']})

        instance_map = self.get_instance_map()
        bastion_ip = self._get_bastion_ip()

        CONSOLE.debug('The PNDA console will come up on: http://%s',
                      instance_map[self._cluster + '-' + self._node_config['console-instance']]['private_ip_address'])

        def prepare_bastion():
            # Configure the bastion with the PNDA mirror and install nc on it
            # nc is required for relaying commands through the bastion
            # to do anything on the other instances
            files_to_scp = ['cli/pnda_env_%s.sh' % self._cluster,
                            'bootstrap-scripts/package-install.sh']

            cmds_to_run = ['source /tmp/pnda_env_%s.sh' % self._cluster,
                           'export PNDA_CLUSTER=%s' % self._cluster,
                           'export PNDA_FLAVOR=%s' % self._flavor,
                           'sudo chmod a+x /tmp/package-install.sh',
                           'sudo -E /tmp/package-install.sh',
                           'sudo yum install -y nc']

            nc_scp_cmd = "scp -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s %s@%s:%s" % (
                self._keyfile, ' '.join(files_to_scp), self._pnda_env['infrastructure']['OS_USER'], bastion_ip, '/tmp')
            CONSOLE.debug(nc_scp_cmd)
            ret_val = subprocess_to_log.call(nc_scp_cmd.split(' '), LOG, log_id=bastion_ip)
            if ret_val != 0:
                raise Exception("Error transferring files to new host %s via SCP. See debug log (%s) for details." % (bastion_ip, LOG_FILE_NAME))

            nc_ssh_cmd = 'ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s' % (
                self._keyfile, self._pnda_env['infrastructure']['OS_USER'], bastion_ip)
            nc_install_cmd = nc_ssh_cmd.split(' ')
            nc_install_cmd.append(' && '.join(cmds_to_run))
            CONSOLE.debug(nc_install_cmd)
            ret_val = subprocess_to_log.call(nc_install_cmd, LOG, log_id=bastion_ip)
            if ret_val != 0:
                raise Exception("Error running ssh commands on host %s. See debug log (%s) for details." % (bastion_ip, LOG_FILE_NAME))

        if bastion_ip:
            self._wait_for_host_connectivity([bastion_ip], False, prepare_bastion)
        self._wait_for_host_connectivity([instance_map[h]['private_ip_address'] for h in instance_map], bastion_ip is not None)

        CONSOLE.info('Bootstrapping saltmaster. Expect this to take a few minutes, check the debug log for progress (%s).', LOG_FILE_NAME)
        saltmaster = instance_map[self._cluster + '-' + self._node_config['salt-master-instance']]
        saltmaster_ip = saltmaster['private_ip_address']

        platform_salt_tarball = None
        if 'PLATFORM_SALT_LOCAL' in self._pnda_env['platform_salt']:
            local_salt_path = self._pnda_env['platform_salt']['PLATFORM_SALT_LOCAL']
            platform_salt_tarball = '%s.tmp' % str(uuid.uuid1())
            with tarfile.open(platform_salt_tarball, mode='w:gz') as archive:
                archive.add(local_salt_path, arcname='platform-salt', recursive=True)
            self._ssh_client.scp([platform_salt_tarball], saltmaster_ip)
            os.remove(platform_salt_tarball)

        platform_certs_tarball = None
        if self._pnda_env['security']['SECURITY_MODE'] != 'disabled':
            platform_certs_tarball = self._ship_certs(saltmaster_ip)

        bootstrap_threads = []
        bootstrap_errors = Queue.Queue()
        bootstrap_files = Queue.Queue()
        bootstrap_commands = Queue.Queue()

        self._bootstrap(saltmaster, saltmaster_ip, self._cluster, self._flavor, self._branch,
                        platform_salt_tarball, platform_certs_tarball,
                        bootstrap_errors, bootstrap_files, bootstrap_commands)
        self._process_thread_errors('bootstrapping saltmaster', bootstrap_errors)

        CONSOLE.info('Bootstrapping other instances. Expect this to take a few minutes, check the debug log for progress (%s).', LOG_FILE_NAME)
        for key, instance in instance_map.iteritems():
            if '-' + self._node_config['salt-master-instance'] not in key:
                thread = Thread(target=self._bootstrap, args=[instance, saltmaster_ip,
                                                              self._cluster, self._flavor, self._branch,
                                                              platform_salt_tarball, None, bootstrap_errors,
                                                              bootstrap_files, bootstrap_commands])
                thread.daemon = True
                bootstrap_threads.append(thread)

        self._wait_on_host_operations('bootstrapping host', bootstrap_threads, bastion_ip is not None, bootstrap_errors)

        self._export_bootstrap_resources(self._cluster, list(set(bootstrap_files.queue)), list(set(bootstrap_commands.queue)))
        time.sleep(30)

        CONSOLE.info('Running salt to install software. Expect this to take 45 minutes or more, check the debug log for progress (%s).', LOG_FILE_NAME)
        # Consul is installed first, before restarting the minion to pick up
        # changes to resolv.conf (see https://github.com/saltstack/salt/issues/21397)
        # We then wait 60 seconds before continuing with highstate to allow the minions to restart
        # An improvement would be running a test.ping and waiting for all expected minions to be ready
        CONSOLE.info('Installing Consul')
        self._ssh_client.ssh(['(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed "*" state.sls consul,consul.dns queue=True 2>&1)'
                              ' | tee -a pnda-salt.log; %s' % THROW_BASH_ERROR], saltmaster_ip)
        CONSOLE.info('Restarting minions')
        self._restart_minions([instance_map[h]['private_ip_address'] for h in instance_map], bastion_ip is not None)
        CONSOLE.info('Refreshing salt mines')
        self._ssh_client.ssh(['(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed "*" mine.update 2>&1) | tee -a pnda-salt.log; %s'
                              % THROW_BASH_ERROR], saltmaster_ip)

        self._register_services(saltmaster_ip)

        CONSOLE.info('Continuing with installation of PNDA')
        self._ssh_client.ssh(['(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed "*"'
                              ' state.highstate queue=True 2>&1) | tee -a pnda-salt.log; %s' % THROW_BASH_ERROR,
                              '(sudo CLUSTER=%s salt-run --log-level=debug state.orchestrate orchestrate.pnda 2>&1) | tee -a pnda-salt.log; %s'
                              % (self._cluster, THROW_BASH_ERROR)], saltmaster_ip)

    def _register_services(self, saltmaster_ip):
        CONSOLE.info('Populating %s with services', self._service_registry.name)
        # Read descriptor
        service_to_role_descriptor = self._get_service_to_role_descriptor()
        # Find hosts with those roles using grains
        instances = self.get_instance_map()
        affected_hosts = []
        for service in service_to_role_descriptor:
            role = service_to_role_descriptor[service]['role']
            port = service_to_role_descriptor[service]['port']
            hosts_for_role = self._get_hosts_for_role(saltmaster_ip, role)
            # Get the addresses for those hosts
            def ip_for_service(name, props):
                return 'private_ip_address' if not props['ip_address'] else 'ip_address'
            addresses_for_service = [instances[host][ip_for_service(service, instances[host])] for host in hosts_for_role]
            # Push records into registry mapping service->address
            affected_hosts.extend(hosts_for_role)
            self._service_registry.register_service_record(service, addresses_for_service, port)
        self._service_registry.commit([instances[host]['private_ip_address'] for host in set(affected_hosts)])

    def _get_service_to_role_descriptor(self):
        rts_filepath = 'bootstrap-scripts/service_to_role.json'
        with open(rts_filepath, 'r') as mapping_file:
            mapping_data = json.loads(mapping_file.read())
        return mapping_data

    def _get_hosts_for_role(self, saltmaster_ip, role):
        output = []
        self._ssh_client.ssh(['(sudo salt-call pnda.get_hosts_for_role %s 2>&1) | tee -a pnda-salt.log; %s' % (role, THROW_BASH_ERROR)], saltmaster_ip, output)
        hosts_for_role = []
        for line in output:
            if line.strip().startswith('-'):
                hosts_for_role.append(line.strip().split('- ')[1])
        CONSOLE.debug('Hosts for role %s are: %s', role, json.dumps(hosts_for_role))
        return hosts_for_role

    def _expand_pnda(self, do_orchestrate):
        instance_map = self.get_instance_map(True)
        bastion_ip = self._get_bastion_ip()
        saltmaster = instance_map[self._cluster + '-' + self._node_config['salt-master-instance']]
        saltmaster_ip = saltmaster['private_ip_address']

        self._ssh_client.ssh(['rm -rf /tmp/%s || true' % self._keyfile], saltmaster_ip)
        self._ssh_client.scp([self._keyfile, 'cli/pnda_env_%s.sh' % self._cluster, 'bootstrap-scripts/saltmaster-gen-keys.sh'], saltmaster_ip)
        self._ssh_client.ssh(['echo \'%s\' | tee /tmp/minions_list' % '\n'.join(self._get_minions_to_bootstrap()),
                              'source /tmp/pnda_env_%s.sh' % self._cluster,
                              'sudo chmod a+x /tmp/saltmaster-gen-keys.sh',
                              'sudo -E /tmp/saltmaster-gen-keys.sh'], saltmaster_ip)

        self._wait_for_host_connectivity([instance_map[h]['private_ip_address'] for h in instance_map], bastion_ip is not None)
        CONSOLE.info('Bootstrapping new instances. Expect this to take a few minutes, check the debug log for progress. (%s)', LOG_FILE_NAME)
        bootstrap_threads = []
        bootstrap_errors = Queue.Queue()
        for _, instance in instance_map.iteritems():
            if instance['node_type'] and not instance['bootstrapped']:
                thread = Thread(target=self._bootstrap,
                                args=[instance, saltmaster_ip, self._cluster, self._flavor, self._branch, None, None, bootstrap_errors])
                bootstrap_threads.append(thread)
                thread.daemon = True

        self._wait_on_host_operations('bootstrapping host', bootstrap_threads, bastion_ip is not None, bootstrap_errors)

        time.sleep(30)

        CONSOLE.info('Running salt to install software. Expect this to take 10 - 20 minutes, check the debug log for progress. (%s)', LOG_FILE_NAME)

        # Consul is installed first, before restarting the minion to pick up
        # changes to resolv.conf (see https://github.com/saltstack/salt/issues/21397)
        # We then wait 60 seconds before continuing with highstate to allow the minions to restart
        # An improvement would be running a test.ping and waiting for all expected minions to be ready
        CONSOLE.info('Installing Consul')
        self._ssh_client.ssh(['(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed'
                              ' -C "G@pnda:is_new_node" state.sls consul,consul.dns queue=True 2>&1)'
                              ' | tee -a pnda-salt.log; %s' % THROW_BASH_ERROR], saltmaster_ip)
        CONSOLE.info('Restarting minions')
        self._restart_minions([instance_map[h]['private_ip_address'] for h in instance_map], bastion_ip is not None)
        CONSOLE.info('Refreshing salt mines')
        self._ssh_client.ssh(['(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed "*" mine.update 2>&1) | tee -a pnda-salt.log; %s'
                              % THROW_BASH_ERROR], saltmaster_ip)

        self._register_public_services(saltmaster_ip)

        CONSOLE.info('Continuing with installation of PNDA')
        expand_commands = ['(sudo salt -v --log-level=debug --timeout=120 --state-output=mixed -C "G@pnda:is_new_node" state.highstate queue=True 2>&1)' +
                           ' | tee -a pnda-salt.log; %s' % THROW_BASH_ERROR]
        if do_orchestrate:
            CONSOLE.info('Including orchestrate because new Hadoop datanodes are being added')
            expand_commands.append('(sudo CLUSTER=%s salt-run --log-level=debug state.orchestrate orchestrate.pnda-expand 2>&1)' % self._cluster +
                                   ' | tee -a pnda-salt.log; %s' % THROW_BASH_ERROR)

        self._ssh_client.ssh(expand_commands, saltmaster_ip)

    def _destroy_pnda(self):
        CONSOLE.info('Removing ssh access scripts')
        socks_proxy_file = 'cli/socks_proxy-%s' % self._cluster
        if os.path.exists(socks_proxy_file):
            os.remove(socks_proxy_file)
        ssh_config_file = 'cli/ssh_config-%s' % self._cluster
        if os.path.exists(ssh_config_file):
            os.remove(ssh_config_file)
        env_sh_file = 'cli/pnda_env_%s.sh' % self._cluster
        if os.path.exists(env_sh_file):
            os.remove(env_sh_file)

    def _check_hosts_bootstrapped(self, instances, bastion_used):
        check_threads = []
        check_results = Queue.Queue()

        def do_check(host_key, host, check_results):
            try:
                CONSOLE.info('Checking bootstrap status for %s', host)
                self._ssh_client.ssh(['ls ~/.bootstrap_complete'], host)
                CONSOLE.debug('Host is bootstrapped: %s.', host)
                check_results.put(host_key)
            except:
                CONSOLE.debug('Host is not bootstrapped: %s.', host)

        for key, instance in instances.iteritems():
            thread = Thread(target=do_check, args=[key, instance['private_ip_address'], check_results])
            thread.daemon = True
            check_threads.append(thread)

        self._wait_on_host_operations('checking bootstrap status', check_threads, bastion_used, None)

        while not check_results.empty():
            host_key = check_results.get()
            instances[host_key]['bootstrapped'] = True

    def _check_config(self, keyfile):
        self._check_private_key_exists(keyfile)
        self._check_pnda_mirror()
        self.check_target_specific_config()
        self._check_data_volume_count()

    def _check_private_key_exists(self, keyfile):
        if not os.path.isfile(keyfile):
            CONSOLE.info('Keyfile.......... ERROR')
            CONSOLE.error('Did not find local file named %s', keyfile)
            sys.exit(1)
        CONSOLE.info('Keyfile.......... OK')


    def _check_pnda_mirror(self):
        def raise_error(reason):
            CONSOLE.info('PNDA mirror...... ERROR')
            CONSOLE.error(reason)
            CONSOLE.error(traceback.format_exc())
            sys.exit(1)

        try:
            mirror = self._pnda_env['mirrors']['PNDA_MIRROR']
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

    def _check_data_volume_count(self):
        data_volume_count = int(self._pnda_env['datanode']['DATA_VOLUME_COUNT'])
        if data_volume_count == 0:
            CONSOLE.error('Datanode volume count should not be zero')
            sys.exit(1)
