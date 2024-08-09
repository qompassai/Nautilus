'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logtest' tool allows the testing and verification of rules and decoders against provided log examples
       remotely inside a sandbox in 'wazuh-analysisd'. This functionality is provided by the manager, whose work
       parameters are configured in the ossec.conf file in the XML rule_test section. Test logs can be evaluated through
       the 'wazuh-logtest' tool or by making requests via RESTful API. These tests will check if the logtest
       configuration is valid. Also checks rules, decoders, decoders, alerts matching logs correctly.

components:
    - logtest

suite: remove_old_sessions

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/wazuh-logtest/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html
    - https://documentation.wazuh.com/current/user-manual/reference/internal-options.html#analysisd

tags:
    - logtest_configuration
'''
import pytest
from pathlib import Path
from time import sleep
from json import dumps

from wazuh_testing.constants.paths.sockets import LOGTEST_SOCKET_PATH
from wazuh_testing import session_parameters
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd.configuration import ANALYSISD_DEBUG
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import configuration
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.modules.analysisd import patterns

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration
t_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_old_sessions.yaml')
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_old_session_for_inactivity.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)
t_configurations = configuration.load_configuration_template(t_config_path, t_config_parameters, t_config_metadata)

# Variables
receiver_sockets_params = [(LOGTEST_SOCKET_PATH, 'AF_UNIX', 'TCP')]
receiver_sockets = None
local_internal_options = {ANALYSISD_DEBUG: '1'}
create_session_data = {'version': 1, 'command': 'log_processing',
                       'parameters': {'event': 'Oct 15 21:07:56 linux-agent sshd[29205]: Invalid user blimey '
                                      'from 18.18.18.18 port 48928',
                                      'log_format': 'syslog',
                                      'location': 'master->/var/log/syslog'}}
msg_create_session = dumps(create_session_data)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

wazuh_log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)


# Test
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t_configurations, t_config_metadata), ids=t_case_ids)
def test_remove_old_session_for_inactivity(configure_local_internal_options, test_configuration,
                                           test_metadata, set_wazuh_configuration, daemons_handler,
                                           wait_for_logtest_startup, connect_to_sockets):
    '''
    description: Check if 'wazuh-logtest' correctly detects and handles the situation where trying to remove old
                 sessions due to inactivity. To do this, it creates more sessions than allowed and waits session_timeout
                 seconds, then checks that 'wazuh-logtest' has removed the session due to inactivity.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - test_configuration:
            type: data
            brief: Configuration used in the test.
        - test_metadata:
            type: data
            brief: Configuration cases.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.
        - connect_to_sockets:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.

    assertions:
        - Verify that the session is created.
        - Verify that the old session is removed after 'session_timeout' delay due to inactivity.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'wazuh_conf.yaml' and the session creation data from the module.

    expected_output:
        - 'Session initialization event not found'
        - 'Session removal event not found'
        - r'Error when executing .* in daemon .*. Exit status: .*'

    tags:
        - inactivity
        - analysisd
    '''
    session_timeout = int(test_metadata['timeout'])

    receiver_sockets[0].send(msg_create_session, True)
    msg_recived = receiver_sockets[0].receive()[4:]
    msg_recived = msg_recived.decode()

    wazuh_log_monitor.start(timeout=session_parameters.default_timeout,
                      callback=generate_callback(patterns.LOGTEST_SESSION_INIT))
    assert wazuh_log_monitor.callback_result, "Session initialization event not found"

    sleep(session_timeout)

    wazuh_log_monitor.start(timeout=session_parameters.default_timeout,
                      callback=generate_callback(patterns.LOGTEST_REMOVE_SESSION))
    assert wazuh_log_monitor.callback_result, "Session removal event not found"
