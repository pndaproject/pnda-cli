"""
Copyright (c) 2016 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Apache License, Version 2.0 (the "License").
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
The code, technical concepts, and all information contained herein, are the property of
Cisco Technology, Inc. and/or its affiliated entities, under various laws including copyright,
international treaties, patent, and/or contract. Any use of the material herein must be in
accordance with the terms of the License.
All rights not expressly granted by the License are reserved.

Unless required by applicable law or agreed to separately in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied.

Purpose:    Routines for input validation

"""

import json
import re
import os

import argparse
from argparse import RawTextHelpFormatter, ArgumentTypeError

class RangeValidator(object):
    '''
    Simple field validator based on rules specification file
    '''

    def __init__(self, flavor):
        self._rules = {}
        self._load(flavor)

    def _load(self, flavor):
        path = '../cloud-formation/%s/validation.json' % flavor
        if os.path.isfile(path):
            with open(path) as validation_file:
                rules = json.load(validation_file)
                # apply transformation applied by argparse so rules are addressable
                for field, rule in rules.iteritems():
                    self._rules[field.replace('-', '_')] = rule

    def _check_validation(self, restriction, value): #pylint: disable=R0911
        if self._rules is None:
            return True

        if restriction.startswith("<="):
            return value <= int(restriction[2:])

        if restriction.startswith(">="):
            return value > int(restriction[2:])

        if restriction.startswith("<"):
            return value < int(restriction[1:])

        if restriction.startswith(">"):
            return value > int(restriction[1:])

        if "-" in restriction:
            restrict_min = int(restriction.split('-')[0])
            restrict_max = int(restriction.split('-')[1])
            return value >= restrict_min and value <= restrict_max

        return value == int(restriction)

    def get_validation_rule(self, field):
        rule = None
        if self._rules is not None:
            rule = self._rules.get(field)
        return rule

    def validate_field(self, field, value):
        restrictions = self.get_validation_rule(field)
        if restrictions is None:
            return True
        for restriction in restrictions.split(','):
            if self._check_validation(restriction, value):
                return True
        return False

class UserInputValidator(object):
    '''
    Encapsulate user input validation for CLI
    '''

    def __init__(self, flavors):
        self._range_validator = None
        self._flavors = flavors

        '''
        Validators
        '''

        identity_func = lambda val: val

        key_validator = {
            'hint':"must be valid filename without extension",
            'func':identity_func,
            'action':identity_func
        }

        name_validator = {"hint" : "may contain only a-z 0-9 and '-'"}
        def _name_validator_func(name):
            if re.match(r"^[\.a-z0-9-]+$", name) is None:
                raise ArgumentTypeError(name_validator['hint'])
            return name
        name_validator['func'] = _name_validator_func
        name_validator['action'] = identity_func

        integer_validator = {"hint" : "must be a positive integer"}
        def _integer_validator_func(val):
            try:
                as_num = int(val)
            except:
                raise ArgumentTypeError(integer_validator['hint'])
            return as_num
        integer_validator['func'] = _integer_validator_func
        integer_validator['action'] = identity_func

        flavor_validator = {'hint' : "must be one of %s" % self._flavors}
        def _flavor_validator_func(val):
            if val not in self._flavors:
                raise ArgumentTypeError(flavor_validator['hint'])
            return val
        flavor_validator['func'] = _flavor_validator_func

        def _flavor_action_func(flavor):
            self._range_validator = RangeValidator(flavor)
        flavor_validator['action'] = _flavor_action_func

        self._validated_fields = {
            "pnda_cluster" : {"validator":name_validator, "group":["create", "expand", "destroy"], "required":True},
            "keyname": {"validator":key_validator, "group":["create", "expand"], "required":True},
            "datanodes" : {"validator":integer_validator, "group":["create", "expand"], "required":False},
            "opentsdb_nodes" : {"validator":integer_validator, "group":["create", "expand"], "required":False},
            "kafka_nodes" : {"validator":integer_validator, "group":["create", "expand"], "required":False},
            "zk_nodes" : {"validator":integer_validator, "group":["create", "expand"], "required":False},
            "flavor" : {"validator":flavor_validator, "group":["create", "expand"], "required":True}
        }

    def _value_or_default(self, field, func, default):
        validator = self._validated_fields.get(field)
        return func(validator) if validator is not None else default

    def _field_validator_func(self, field):
        return self._value_or_default(field, lambda val: val["validator"]["func"], lambda val: val)

    def _field_validator_hint(self, field):
        return self._value_or_default(field, lambda val: val["validator"]["hint"], '')

    def _field_validator_action(self, field):
        return self._value_or_default(field, lambda val: val["validator"]["action"], lambda val: val)

    def _field_validator_required(self, field):
        return self._value_or_default(field, lambda val: val["required"], False)

    def _field_validator_group(self, field):
        return self._value_or_default(field, lambda val: val["group"], [])

    def _get_range_validation_rule(self, field):
        return self._range_validator.get_validation_rule(field) if self._range_validator is not None else None

    def _range_validate_field(self, field, val):
        return self._range_validator.validate_field(field, val) if self._range_validator is not None else True

    def _validate_user_input(self, args):

        # gather arguments via raw_input and run validation and actions in similar fashion to argparse
        def _prompt_user(field, val):
            hint = self._field_validator_hint(field)
            while val is None:
                suffix = " and be in range [%s]" % rule if rule is not None else ""
                try:
                    val = raw_input("Enter a value for %s (%s%s): " % (field, hint, suffix))
                    val = self._field_validator_func(field)(val)
                    if self._range_validate_field(field, val):
                        self._field_validator_action(field)(val)
                    else:
                        print "'%s' not in valid range (%s)" % (val, rule)
                        val = None
                except ArgumentTypeError: # field validator raises this if problem with format
                    print "'%s' %s" % (field, hint)
                    val = None
                except EOFError: # raw_input raises this if no stdin e.g. automation environment
                    raise ArgumentTypeError("%s: must be specified on command line" % field)
            return val

        # build field validation list (filtered by command and ordered by required)
        input_fields = []
        for field, val in args.iteritems():
            if args['command'] in self._field_validator_group(field):
                if self._field_validator_required(field):
                    input_fields.insert(0, (field, val))
                else: input_fields.append((field, val))

        for field, val in input_fields:
            # range validate field if rule present
            rule = self._get_range_validation_rule(field)
            # if value is already specified, failing additional range check is considered fatal
            if val is not None:
                if not self._range_validate_field(field, val):
                    raise ArgumentTypeError("%s: '%s' not in valid range (%s)" % (field, val, rule))
            else: # value not specified
                # if rule specified or field required, prompt user until we have valid value
                if (rule is not None and rule != "0") or self._field_validator_required(field):
                    val = _prompt_user(field, val)
                # if rule specified as zero, default to 0
                elif rule is not None and rule == "0":
                    val = 0 if val is None else val
            args[field] = val
        return args

    def _parse(self):
        epilog = """Examples:

        - Create new cluster, prompting for values:
            pnda-cli.py create
        
        - Destroy existing cluster:
            pnda-cli.py destroy -e squirrel-land
        
        - Expand existing cluster:
            pnda-cli.py expand -e squirrel-land -f standard -s keyname -n 10 -k 5

        Either, or both, kafka (k) and datanodes (n) can be changed. 
        The value specifies the new total number of nodes. 
        Shrinking is not supported - this must be done very carefully to avoid data loss.
        
        - Create cluster without user input:
            pnda-cli.py create -s mykeyname -e squirrel-land -f standard -n 5 -o 1 -k 2 -z 3
            
        """

        def _build_action(func):
            class _WrappedFuncAction(argparse.Action): #pylint: disable=R0903
                def __call__(self, parser, args, values, option_string=None):
                    setattr(args, self.dest, values)
                    func(values)
            return _WrappedFuncAction

        parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,
                                         description='PNDA CLI',
                                         epilog=epilog)

        parser.add_argument('command',
                            help='Mode of operation',
                            choices=['create', 'expand', 'destroy'])
        parser.add_argument('-e', '--pnda-cluster',
                            type=self._field_validator_func("pnda_cluster"),
                            help='Namespaced environment for machines in this cluster')
        parser.add_argument('-n', '--datanodes',
                            type=self._field_validator_func("datanodes"),
                            help='How many datanodes for the hadoop cluster')
        parser.add_argument('-o', '--opentsdb-nodes',
                            type=self._field_validator_func("opentsdb_nodes"),
                            help='How many Open TSDB nodes for the hadoop cluster')
        parser.add_argument('-k', '--kafka-nodes',
                            type=self._field_validator_func("kafka_nodes"),
                            help='How many kafka nodes for the databus cluster')
        parser.add_argument('-z', '--zk-nodes',
                            type=self._field_validator_func("zk_nodes"),
                            help='How many zookeeper nodes for the databus cluster')
        parser.add_argument('-f', '--flavor',
                            type=self._field_validator_func("flavor"),
                            help='PNDA flavor: %s' % self._flavors,
                            action=_build_action(self._field_validator_action("flavor")))
        parser.add_argument('-s', '--keyname',
                            help='Keypair name')
        parser.add_argument('-x', '--no-config-check',
                            action='store_true',
                            help='Skip config verifiction checks')
        parser.add_argument('-b', '--branch',
                            help='Branch of platform-salt to use. Overrides value in pnda_env.yaml')
        parser.add_argument('-d', '--dry-run',
                            action='store_true',
                            help=('Output final Cloud Formation template but do not apply it. '
                                  'Useful for checking against existing Cloud formation template '
                                  ' to gain confidence before running the expand operation.'))
        parser.add_argument('-m', '--x-machines-definition',
                            help='File describing topology of target server cluster')

        args = parser.parse_args()

        return args

    def parse_user_input(self):
        '''
        Parse and validate user input
        '''
        args = self._parse()
        validated_fields = self._validate_user_input(vars(args))
        return validated_fields

    def get_range_validator(self):
        '''
        Access flavor specific range validator object
        '''
        return self._range_validator
