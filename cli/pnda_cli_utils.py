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
#   Purpose: Utilities used by PNDA CLI to create PNDA

import os
import json
import time
import logging

class PNDAConfigException(Exception):
    pass

RUNFILE = None
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

MILLI_TIME = lambda: int(round(time.time() * 1000))

LOG_FILE_NAME = None
CONSOLE_LOGGER = None
FILE_LOGGER = None

def set_log_level(log_level):
    CONSOLE_LOGGER.setLevel(logging.getLevelName(log_level))
    FILE_LOGGER.setLevel(logging.getLevelName(log_level))

def init_logging():
    global LOG_FILE_NAME
    global CONSOLE_LOGGER
    global FILE_LOGGER
    if LOG_FILE_NAME is None:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        LOG_FILE_NAME = 'logs/pnda-cli.%s.log' % time.time()
        logging.basicConfig(filename=LOG_FILE_NAME,
                            level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        log_formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        FILE_LOGGER = logging.getLogger('everything')
        CONSOLE_LOGGER = logging.getLogger('CONSOLE_LOGGER')
        CONSOLE_LOGGER.addHandler(logging.StreamHandler())
        CONSOLE_LOGGER.handlers[0].setFormatter(log_formatter)

def create_keys(d, key_path, value):
    keys = key_path.split(".")
    for k in keys[:-1]:
        if not k in d: d[k] = {}
        d = d[k]
    d[keys[-1]] = value

if __name__ == "__main__":
    pass
