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
#   Purpose: Implementation for a Consul service registry

import json

import pnda_cli_utils as utils
from service_registry import ServiceRegistry

utils.init_logging()
CONSOLE = utils.CONSOLE_LOGGER
LOG = utils.FILE_LOGGER
LOG_FILE_NAME = utils.LOG_FILE_NAME


class ServiceRegistryConsul(ServiceRegistry):
    '''
    Base class for registering PNDA service endpoints
    Must to be overridden to support specific registration targets
    '''
    def __init__(self, ssh_client):
        self.name = 'Consul'
        self._ssh_client = ssh_client

    ### Public interface
    def register_service_record(self, service_name, address_list, port):
        '''
        Create a new PNDA service record
        Parameters:
         - service_name: name for the service
         - address_list: addresses to register against service_name
         - port: port to register against service_name
        '''
        CONSOLE.debug('ServiceRegistryConsul:register_service_record: %s => %s : %s', service_name, json.dumps(address_list), port)
        if address_list:
            for address in address_list:
                self._ssh_client.ssh(['sudo mkdir -p /etc/consul.d',
                                      'echo \'{"service": {"name": "%s", "address": "%s", "port": %s}}\''
                                      ' | sudo tee /etc/consul.d/%s.json' % (service_name, address, port, service_name)], address)

    def commit(self, to_commit):
        '''
        Restart consul on any hosts that had services added with register_service_record
        Parameters:
         - to_commit: list of hosts to commit changes to
        '''
        CONSOLE.debug('ServiceRegistryConsul:commit: %s', json.dumps(to_commit))
        for address in set(to_commit):
            self._ssh_client.ssh(['sudo service consul restart'], address)
