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
#   Purpose: Backend implementation for creating PNDA on a set of existing machines

import json
from backend_base import BaseBackend

class ExistingMachinesBackend(BaseBackend):
    '''
    Deployment specific implementation for existing machines
    '''
    def __init__(self, pnda_env, cluster, no_config_check, flavor, keyname, branch, def_file):
        self._def_file = def_file
        super(ExistingMachinesBackend, self).__init__(pnda_env, cluster, no_config_check, flavor, '%s.pem' % keyname, branch)

    def load_node_config(self):
        '''
        Load a node config descriptor from information in the existing machines definition file
        '''
        config = {'bastion-instance':''}
        existing_machines_def = file(self._def_file)
        existing_machines = json.load(existing_machines_def)
        for node in existing_machines:
            if 'is_bastion' in existing_machines[node] and existing_machines[node]['is_bastion'] is True:
                config['bastion-instance'] = node
            if 'is_saltmaster' in existing_machines[node] and existing_machines[node]['is_saltmaster'] is True:
                config['salt-master-instance'] = node
            if 'is_console' in existing_machines[node] and existing_machines[node]['is_console'] is True:
                config['console-instance'] = node
        existing_machines_def.close()
        return config

    def fill_instance_map(self):
        '''
        Use the the existing machines definition file to generate a list of the target instances
        '''
        instance_map = {}
        existing_machines_def = file(self._def_file)
        existing_machines = json.load(existing_machines_def)
        for node in existing_machines:
            node_detail = existing_machines[node]
            new_instance = {}
            new_instance['bootstrapped'] = False
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
            instance_map[self._cluster + '-' + node] = new_instance
        existing_machines_def.close()
        return instance_map
