# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
from enum import Enum
from glob import glob

from wazuh.core import common
from wazuh.core.exception import WazuhError
from wazuh.core.utils import load_wazuh_xml, add_dynamic_detail

REQUIRED_FIELDS = ['id']
RULE_REQUIREMENTS = ['pci_dss', 'gdpr', 'hipaa', 'nist_800_53', 'gpg13', 'tsc', 'mitre']
SORT_FIELDS = ['filename', 'relative_dirname', 'description', 'id', 'level', 'status']
DYNAMIC_OPTIONS = {'regex', 'field', 'match', 'action', 'extra_data', 'hostname', 'id', 'location', 'match',
                   'program_name', 'protocol', 'user', 'url', 'srcport', 'dstport', 'status', 'system_name',
                   'extra_data', 'srcgeoip', 'dstgeoip'}
RULE_FIELDS = ['description', 'details', 'filename', 'gdpr', 'groups', 'id', 'level', 'relative_dirname', 'pci_dss',
               'status', 'gpg13', 'hipaa', 'nist_800_53', 'tsc', 'mitre']
RULE_FILES_FIELDS = ['filename', 'relative_dirname', 'status']
RULE_FILES_REQUIRED_FIELDS = ['filename']


class Status(Enum):
    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'


def add_detail(detail: str, value: str, details: dict):
    """Add a rule detail (i.e. category, noalert, etc.).

    Parameters
    ----------
    detail : str
        Detail name.
    value : str
        Detail value.
    details : dict
        Details dict.
    """
    if detail in details:
        # If it was an element, we create a list.
        if type(details[detail]) is not list:
            element = details[detail]
            details[detail] = [element]

        details[detail].append(value)
    else:
        details[detail] = value


def check_status(status: str) -> str:
    """Check status is a value of the Status enumeration.

    Parameters
    ----------
    status: str
        Status to check.

    Raises
    ------
    WazuhError(1202)
        If the status is not one of the enumeration.

    Returns
    -------
    str
        Status.
    """
    if status is None:
        return Status.S_ALL.value
    elif status in [Status.S_ALL.value, Status.S_ENABLED.value, Status.S_DISABLED.value]:
        return status
    else:
        raise WazuhError(1202)


def set_groups(groups: list, general_groups: list, rule: dict):
    """Add specific and general groups to a specific rule.

    Parameters
    ----------
    groups : list
        Groups to add to the rule.
    general_groups : list
        General groups to add to the rule.
    rule : dict
        Rule to be updated.
    """
    groups.extend(general_groups)
    for group in groups:
        # These characters are the ones Core replaces when reading XML tags
        group = group.strip()
        group = re.sub('[\n\r]+', '', group)
        for req in RULE_REQUIREMENTS:
            if group.startswith(req):
                # We add the requirement to the rule
                rule[req].append(group[len(req) + 1:]) if group[len(req) + 1:] not in rule[req] else None
                break
        else:
            # If a requirement is not found we add it to the rule as group
            rule['groups'].append(group) if group != '' else None


def load_rules_from_file(rule_filename: str, rule_relative_path: str, rule_status: str) -> list:
    """Load rules given its file name.

    Parameters
    ----------
    rule_filename : str
        Name of the rule file.
    rule_relative_path : str
        Relative path to the rule file.
    rule_status : str
        Rule status.

    Raises
    ------
    WazuhError(1201)
        Error reading rule files.
    WazuhError(1207)
        Error reading rule files, wrong permissions.

    Returns
    -------
    list
        List of rules.
    """
    try:
        rules = list()
        root = load_wazuh_xml(os.path.join(common.WAZUH_PATH, rule_relative_path, rule_filename))

        # Get variables in dict format {varname: value} (will only be used for id and level for now)
        variables = {}
        for vari in root.findall('var'):
            name = "$" + vari.attrib.get('name')
            value = vari.text
            variables[name] = value

        for xml_group in list(root):
            if xml_group.tag.lower() == "group":
                general_groups = xml_group.attrib['name'].split(',')
                for xml_rule in list(xml_group):
                    # New rule
                    if xml_rule.tag.lower() == "rule":
                        groups = list()

                        # Replace values of id and level if variables exist
                        id_value = int(variables.get(xml_rule.attrib['id'], xml_rule.attrib['id']))
                        level_value = int(variables.get(xml_rule.attrib['level'], xml_rule.attrib['level']))

                        rule = {'filename': rule_filename, 'relative_dirname': rule_relative_path,
                                'id': id_value, 'level': level_value, 'status': rule_status,
                                'details': dict(), 'pci_dss': list(), 'gpg13': list(), 'gdpr': list(),
                                'hipaa': list(), 'nist_800_53': list(), 'tsc': list(), 'mitre': list(),
                                'groups': list(), 'description': ''}
                        for k in xml_rule.attrib:
                            if k != 'id' and k != 'level':
                                rule['details'][k] = xml_rule.attrib[k]

                        for xml_rule_tags in list(xml_rule):
                            tag = xml_rule_tags.tag.lower()
                            value = xml_rule_tags.text
                            attribs = xml_rule_tags.attrib
                            if value is None:
                                value = ''
                            if tag == "group":
                                groups.extend(value.split(","))
                            elif tag == "mitre":
                                for mitre_id in list(xml_rule_tags):
                                    groups.append(f'mitre_{mitre_id.text}')
                            elif tag == "description":
                                rule['description'] += value
                            elif tag in ("list", "info"):
                                list_detail = {'name': value}
                                for attrib, attrib_value in attribs.items():
                                    list_detail[attrib] = attrib_value
                                add_detail(tag, list_detail, rule['details'])
                            # show rule variables
                            elif tag in DYNAMIC_OPTIONS:
                                if value != '' and value[0] == '$':
                                    for variable in filter(lambda x: x.get('name') == value[1:], root.findall('var')):
                                        value = variable.text
                                if tag == 'field':
                                    tag = xml_rule_tags.attrib.pop('name')
                                add_dynamic_detail(tag, value, attribs, rule['details'])
                            else:
                                add_detail(tag, value, rule['details'])

                        # Set groups
                        set_groups(groups=groups, general_groups=general_groups, rule=rule)
                        rules.append(rule)
    except OSError as e:
        if e.errno == 2:
            raise WazuhError(1201)
        elif e.errno == 13:
            raise WazuhError(1207)
        else:
            raise e

    return rules


def _remove_files(tmp_data, parameters):
    data = list(tmp_data)
    for d in tmp_data:
        for key, value in parameters.items():
            if key == 'status':
                value and value != Status.S_ALL.value and value != d[key] and data.remove(d)
            elif value and value != d[key] and d in data:
                data.remove(d)

    return data


def item_format(data, all_items, exclude_filenames):
    for item in glob(all_items):
        item_name = os.path.basename(item)
        item_dir = os.path.relpath(os.path.dirname(item), start=common.WAZUH_PATH)
        item_status = Status.S_DISABLED.value if item_name in exclude_filenames else Status.S_ENABLED.value
        data.append({'filename': item_name, 'relative_dirname': item_dir, 'status': item_status})


def _create_rule_decoder_dir_dict(ruleset_conf, tag, exclude_filenames, data):
    items = ruleset_conf[tag] if type(ruleset_conf[tag]) is list else [ruleset_conf[tag]]
    for item_dir in items:
        all_rules = f"{common.WAZUH_PATH}/{item_dir}/*.xml"
        item_format(data, all_rules, exclude_filenames)


def _create_dict(ruleset_conf, tag, exclude_filenames, data):
    item_status = Status.S_DISABLED.value if tag == 'rule_exclude' or tag == 'decoder_exclude' \
        else Status.S_ENABLED.value
    items = ruleset_conf[tag] if type(ruleset_conf[tag]) is list else [ruleset_conf[tag]]
    for item in items:
        item_name = os.path.basename(item)
        full_dir = os.path.dirname(item)
        item_dir = os.path.relpath(full_dir if full_dir else common.RULES_PATH, start=common.WAZUH_PATH)
        exclude_filenames.append(item_name) if tag == 'rule_exclude' or tag == 'decoder_exclude' else \
            data.append({'filename': item_name, 'relative_dirname': item_dir, 'status': item_status})


def format_rule_decoder_file(ruleset_conf, parameters, tags):
    tmp_data, exclude_filenames = list(), list()
    for tag in tags:
        if tag in ruleset_conf:
            if tag == 'rule_dir' or tag == 'decoder_dir':
                _create_rule_decoder_dir_dict(ruleset_conf, tag, exclude_filenames, tmp_data)
            else:
                _create_dict(ruleset_conf, tag, exclude_filenames, tmp_data)

    return _remove_files(tmp_data, parameters)
