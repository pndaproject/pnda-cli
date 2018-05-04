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
#   Purpose: Base implementation for a service registry

class ServiceRegistry(object):
    '''
    Base class for registering PNDA service endpoints
    Must to be overridden to support specific registration targets
    '''
    ### Public interface
    def register_service_record(self, service_name, address_list, port):
        '''
        Create a new PNDA service record
        Parameters:
         - name: name for the service
         - address_list: addresses to register against service_name
         - port: port to register against service_name
        '''
        pass

    def commit(self, to_commit):
        '''
        Commit changes made with register_service_record
        Parameters:
         - to_commit: list of hosts to commit changes to
        '''
        pass
