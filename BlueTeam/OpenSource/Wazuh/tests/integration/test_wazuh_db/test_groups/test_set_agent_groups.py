'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the set_agent_groups command used for changing the agent's group data and for the
       cluster's database sync procedures.

tier: 0

modules:
    - wazuh_db

components:
    - manager

daemons:
    - wazuh-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html

tags:
    - wazuh_db
'''
from pathlib import Path
import time
import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.database import query_wdb
from wazuh_testing.utils import configuration
from wazuh_testing.utils.db_queries.global_db import get_agent_info

from . import TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_set_agent_groups.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)


# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


def insert_agent_in_db(id=1, name='TestAgent', ip='any', registration_time=0, connection_status=0,
                       disconnection_time=0):
    """
    Write agent in global.db
    """
    insert_command = f'global insert-agent {{"id":{id},"name":"{name}","ip":"{ip}","date_add":{registration_time}}}'
    update_command = f'global sql UPDATE agent SET connection_status = "{connection_status}",\
                       disconnection_time = "{disconnection_time}" WHERE id = {id};'
    try:
        query_wdb(insert_command)
        query_wdb(update_command)
    except Exception:
        raise Exception(f"Unable to add agent {id}")


# Tests
@pytest.mark.parametrize('test_metadata', t_config_metadata, ids=t_case_ids)
def test_set_agent_groups(clean_databases, daemons_handler, test_metadata, create_groups):
    '''
    description: Check that every input message using the 'set_agent_groups' command in wazuh-db socket generates
                 the proper output to wazuh-db socket. To do this, it performs a query to the socket with a command
                 taken from the list of test_metadata's 'input' field, and compare the result with the test_metadata's
                 'output' and 'expected_group' fields.

    wazuh_min_version: 4.4.0

    parameters:
        - clean_databases:
            type: fixture
            brief: Delete databases.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - create_groups:
            type: fixture:
            brief: Create required groups.

    assertions:
        - Verify that the socket response matches the expected output.
        - Verify that the agent has the expected_group assigned.

    input_description:
        - Test cases are defined in the set_agent_groups.yaml file. This file contains the command to insert the agents
          groups, with different modes and combinations, as well as the expected outputs and results.

    expected_output:
        - f"Assertion Error - expected {output}, but got {response}"
        - 'Unable to add agent'
        - 'did not recieve expected groups in Agent.'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    output = test_metadata['output']
    agent_id = test_metadata['agent_id']

    # Insert test Agent
    response = insert_agent_in_db(id=agent_id, connection_status='disconnected', disconnection_time=str(time.time()))

    # Apply preconditions
    if 'pre_input' in test_metadata:
        query_wdb(test_metadata['pre_input'])

    # Add tested group
    response = query_wdb(test_metadata["input"])

    # validate output
    assert response == output, f"Assertion Error - expected {output}, but got {response}"

    # Check warnings
    if 'expected_warning' in test_metadata:
        log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
        log_monitor.start(callback=callbacks.generate_callback(test_metadata['expected_warning']), timeout=20)
        assert log_monitor.callback_result


    # get agent data and validate agent's groups
    response = get_agent_info(agent_id)

    assert test_metadata['expected_group_sync_status'] == response[0]['group_sync_status']

    if test_metadata["expected_group"] == 'None':
        assert 'group' not in response[0], "Agent has groups data and it was expecting no group data"
    else:
        assert test_metadata["expected_group"] == response[0]['group'], "Did not receive the expected groups in the agent."
