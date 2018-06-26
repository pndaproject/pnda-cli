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
#   Purpose: Helper tool for generating external certificates for PNDA

import sys
import os
import os.path
import glob
import random
import logging
import time
import yaml
import jinja2
sys.path.append(os.path.abspath('../cli'))
import subprocess_to_log

LOG = None
CONSOLE = None
PNDA_ENV = None
LOG_FILE_NAME = None
PNDAPROJECTCA = "pndaproject-ca"
JINJA_ENV = None

def _call(cmd):
    ret_val = subprocess_to_log.call(cmd.split(' '), LOG)
    if ret_val != 0:
        raise Exception("Error running %s" % cmd)

def _ensure_certs():
    local_certs_path = PNDA_ENV['security']['SECURITY_MATERIAL_PATH']
    exts = ['crt']
    if _missing_material(local_certs_path, exts) is None:
        # A CA certificate was provided
        exts = ['key', 'crt', 'yaml']
        missing = _missing_leaf_material(local_certs_path, exts)
        if missing is None:
            CONSOLE.warning('All certificates are already present. Nothing to generate.')
            return
        else:
            missing = _missing_material(local_certs_path, ['key'])
            if missing is not None:
                # Some security material is missing
                raise Exception("Security material is missing: %s" % missing)

    # Generate the security material
    cakey, cacert = _ensure_ca_cert(local_certs_path)
    _generate_host_certs(local_certs_path, cakey, cacert)

def _ensure_ca_cert(local_certs_path):
    keys = glob.glob(os.path.join(local_certs_path, '*.key'))
    certs = glob.glob(os.path.join(local_certs_path, '*.crt'))
    if len(keys) == 1 and len(certs) == 1:
        LOG.info('Root CA was detected and will be reused.')
        return (keys[0], certs[0])
    if certs and not keys:
        raise Exception("Security material is missing a key in %s" % local_certs_path)
    keyout = os.path.join(local_certs_path, PNDAPROJECTCA+'.key')
    out = os.path.join(local_certs_path, PNDAPROJECTCA+'.crt')
    config = os.path.join(local_certs_path, PNDAPROJECTCA+'.cfg')
    LOG.info('Generating new root CA')
    _generate_ca_conf(config)
    _call('openssl req -new -x509 -extensions v3_ca -keyout {} -out {} \
-days 3650 -newkey rsa:2048 -sha512 -passout pass:pnda -config {}'.format(keyout, out, config))
    CONSOLE.info('When finished, import the new root CA certificate in your browser from: %s', out)
    return (keyout, out)

def _generate_host_certs(local_certs_path, cakey, cacert):
    services = [service for service in os.listdir('./platform-certificates') if os.path.isdir(os.path.join('./platform-certificates', service))]
    for service in services:
        sdir = os.path.join(local_certs_path, service)
        if not os.path.isdir(sdir):
            os.makedirs(sdir)
        ymls = glob.glob(os.path.join(sdir, '*.yaml'))
        fqdn = None
        if ymls:
            cfgs = _load_host_yaml(ymls[0])
            if 'fqdn' in cfgs.keys():
                fqdn = cfgs['fqdn']
                LOG.debug('Using detected fqdn:%s', fqdn)
            else:
                raise Exception("Missing 'fqdn' setting in %s" % ymls[0])
        else:
            fqdn = _internal_fqdn_for_service(service)
            _generate_host_yaml(os.path.join(sdir, fqdn+'.yaml'), fqdn)
        key_f = os.path.join(sdir, fqdn)
        LOG.info('Generating key for %s : %s.key', service, key_f)
        _generate_host_conf(key_f+'.cfg', fqdn)
        _generate_host_ext_conf(key_f+'.ext', fqdn)
        _call('openssl genrsa -out {key_f}.key 2048'.format(key_f=key_f))
        LOG.info('Generating certificate for %s : %s.crt', service, key_f)
        _call('openssl req -new -key {key_f}.key -out {key_f}.csr -config {key_f}.cfg'.format(key_f=key_f))
        _call('openssl x509 -req -days 365 -in {key_f}.csr -extfile {key_f}.ext -CA {cacert} -CAkey {cakey} \
-set_serial {serial} -out {key_f}.crt -sha512 -passin pass:pnda'.format(key_f=key_f, cacert=cacert, cakey=cakey, serial=random.getrandbits(20*8)))

def _internal_fqdn_for_service(service):
    domain = PNDA_ENV['domain']['SECOND_LEVEL_DOMAIN'] + '.' + PNDA_ENV['domain']['TOP_LEVEL_DOMAIN']
    return service + '.service.' + domain

def _generate_ca_conf(path):
    with open(path, 'w') as config_file:
        config_file.write(JINJA_ENV.get_template('pndaproject-ca.cfg').render())
 
def _generate_host_yaml(path, fqdn):
    with open(path, 'w') as config_file:
        data = dict(
            fqdn=fqdn
            )
        yaml.dump(data, config_file, default_flow_style=False)

def _load_host_yaml(path):
    with open(path, 'r') as config_file:
        return yaml.load(config_file)

def _generate_host_conf(path, fqdn):
    with open(path, 'w') as config_file:
        config_file.write(JINJA_ENV.get_template('pndaproject-leaf.cfg').render(CN=fqdn))

def _generate_host_ext_conf(path, fqdn):
    with open(path, 'w') as config_file:
        config_file.write(JINJA_ENV.get_template('pndaproject-leaf.ext').render(CN=fqdn))

def _missing_leaf_material(local_certs_path, exts):
    ret = None
    roles = [role for role in os.listdir('./platform-certificates') if os.path.isdir(os.path.join('./platform-certificates', role))]
    for role in roles:
        ret = _missing_material(os.path.join(local_certs_path, role), exts)
        if ret is not None:
            return ret
    return ret

def _missing_material(local_certs_path, exts):
    ret = None
    for ext in exts:
        file_name = os.path.join(local_certs_path, '*.'+ext)
        files = glob.glob(file_name)
        if not files:
            ret = file_name
        else:
            LOG.info('Detected %s', file_name)
    return ret

def check_config_file():
    if not os.path.exists('pnda_env.yaml'):
        CONSOLE.error('Missing required pnda_env.yaml config file,\
                        make a copy of pnda_env_example.yaml named pnda_env.yaml,\
                        fill it out and try again.')
        sys.exit(1)

def main():

    global CONSOLE, LOG_FILE_NAME, LOG
    LOG_FILE_NAME = 'logs/gen-certs.%s.log' % time.time()
    logging.basicConfig(filename=LOG_FILE_NAME,
                        level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log_formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
    CONSOLE = logging.getLogger('CONSOLE_LOGGER')
    CONSOLE.addHandler(logging.StreamHandler())
    CONSOLE.handlers[0].setFormatter(log_formatter)
    LOG = logging.getLogger('everything')

    CONSOLE.info('Saving debug log to %s', LOG_FILE_NAME)

    if not os.path.basename(os.getcwd()) == "tools":
        CONSOLE.error('Please run from inside the tools directory')
        sys.exit(1)

    global JINJA_ENV
    JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.abspath('templates')))
    os.chdir('../')
    global PNDA_ENV
    CONSOLE.warning('DO NOT USE THIS TOOL IN PRODUCTION DEPLOYMENTS!')
    check_config_file()
    try:
        with open('pnda_env.yaml', 'r') as infile:
            PNDA_ENV = yaml.load(infile)
        _ensure_certs()
    except Exception as exception:
        CONSOLE.error(exception)

if __name__ == "__main__":
    main()
