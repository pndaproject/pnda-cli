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
#   Purpose: Ssh helper functions
import os
import json
import subprocess_to_log
import pnda_cli_utils as utils

utils.init_logging()
CONSOLE = utils.CONSOLE_LOGGER
LOG = utils.FILE_LOGGER
LOG_FILE_NAME = utils.LOG_FILE_NAME

class SshClient(object):
    '''
    Utility class for running ssh commands on and transfering files with scp to
    hosts in a PNDA cluster.
    '''
    def __init__(self, cluster):
        self._cluster = cluster
        self._bastion_used = False
        self._public_ip_map = {}
        self._private_ip_map = {}

    def write_ssh_config(self, bastion_ip, os_user, keyfile):
        '''
        Generate ssh config required to run commands across a PNDA cluster
        Includes proxing commands via bastion if there is one
        Call this before ssh() or scp()
        '''
        with open('cli/ssh_config-%s' % self._cluster, 'w') as config_file:
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

        self._bastion_used = True
        socks_file_path = 'cli/socks_proxy-%s' % self._cluster
        with open(socks_file_path, 'w') as config_file:
            config_file.write('''
if [ -z "$1" ]; then
    export SOCKS_PORT=9999
else
    export SOCKS_PORT=$1
fi
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
            config_file.write('ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -A -D $SOCKS_PORT %s@%s\n' %
                              (keyfile, os_user, bastion_ip))
        mode = os.stat(socks_file_path).st_mode
        os.chmod(socks_file_path, mode | (mode & 292) >> 2)

    def scp(self, files, host):
        host = self._subsitute_host_if_bastion(host)
        cmd = "scp -F cli/ssh_config-%s %s %s:%s" % (self._cluster, ' '.join(files), host, '/tmp')
        CONSOLE.debug(cmd)
        ret_val = subprocess_to_log.call(cmd.split(' '), LOG, log_id=host)
        CONSOLE.debug("scp result: %s", ret_val)
        if ret_val != 0:
            raise Exception("Error transferring files to new host %s via SCP. See debug log (%s) for details." % (host, LOG_FILE_NAME))

    def ssh(self, cmds, host, output=None):
        host = self._subsitute_host_if_bastion(host)
        cmd = "ssh -F cli/ssh_config-%s %s" % (self._cluster, host)
        parts = cmd.split(' ')
        parts.append(' && '.join(cmds))
        CONSOLE.debug(json.dumps(parts))
        ret_val = subprocess_to_log.call(parts, LOG, log_id=host, output=output, scan_for_errors=[r'lost connection',
                                                                                                  r'\s*Failed:\s*[1-9].*',
                                                                                                  r'\s*Failures:'])
        CONSOLE.debug("ssh result: %s", ret_val)
        if ret_val != 0:
            raise Exception("Error running ssh commands on host %s. See debug log (%s) for details." % (host, LOG_FILE_NAME))

    def set_ip_mappings(self, instance_map):
        self._public_ip_map = {}
        self._private_ip_map = {}
        for _, instance_properties in instance_map.iteritems():
            if instance_properties['ip_address'] and instance_properties['private_ip_address']:
                self._public_ip_map[instance_properties['ip_address']] = instance_properties['private_ip_address']
                self._private_ip_map[instance_properties['private_ip_address']] = instance_properties['ip_address']

    def _subsitute_host_if_bastion(self, host):
        subs_host = host
        if self._bastion_used and host in self._public_ip_map:
            subs_host = self._public_ip_map[host]
            CONSOLE.debug('Switching public IP %s for private IP %s', host, subs_host)
        elif not self._bastion_used and host in self._private_ip_map:
            subs_host = self._private_ip_map[host]
            CONSOLE.debug('Switching private IP %s for public IP %s', host, subs_host)
        return subs_host
