"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that the different security resources (users, roles, policies, and rules)
       can be correctly removed. The 'RBAC' capability allows users accessing the API to be assigned a role that
       will define the privileges they have.

components:
    - api

suite: rbac

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-db
    - wazuh-execd
    - wazuh-analysisd
    - wazuh-remoted
    - wazuh-modulesd

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
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Security
    - https://en.wikipedia.org/wiki/Role-based_access_control

tags:
    - api
"""
import pytest
from pathlib import Path

from . import TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import TARGET_ROUTE_MAP
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import manage_security_resources
from wazuh_testing.utils.configuration import get_test_cases_data


# Marks
pytestmark = pytest.mark.server

# Paths
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_remove_resource.yaml')

# Configurations
_, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(_, test_metadata), ids=test_cases_ids)
def test_remove_resource(test_configuration, test_metadata, truncate_monitored_files, daemons_handler,
                         wait_for_api_start, set_security_resources):
    """
    description: Check if relationships between security resources stay the same after removing the linked resource.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Truncate monitored files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
            - Configure the security resources using the API
        - test:
            - Check if the related resource can be obtained and store it
            - Check if the relation still existing
            - Remove target resource
            - Check if the relation does not exist anymore
        - teardown:
            - Truncate monitored files
            - Stop daemons defined in `daemons_handler_configuration` in this module
            - Clean added resources

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration data from the test case.
        - test_metadata:
            type: dict
            brief: Metadata from the test case.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.
        - wait_for_api_start:
            type: fixture
            brief: Monitor the API log file to detect whether it has been started or not.
        - set_security_resources:
            type: fixture
            brief: Configure the security resources using the API and clean the added resources.

    assertions:
        - Check if the related resource can be obtained and store it
        - Check if the relation still existing
        - Check if the relation does not exist anymore

    input_description: Different test cases are contained in an external YAML file which includes API configuration
                       parameters.

    expected_output:
        - 0 (No errors)
        - Non-empty list of relations
        - 0 (No errors)
        - 0 (No errors)
        - Empty list (No relations)

    tags:
        - rbac
    """
    target_resource_name = test_metadata['target_resource']['name']
    target_resource_id = test_metadata['target_resource']['id']
    if target_resource_name == 'user_ids':
        related_resource_name = test_metadata['relationships'][target_resource_name]
    else:
        related_resource_name = list(test_metadata['relationships'].keys())[0]
    related_resource_id = test_metadata['resources_ids'][related_resource_name][0]

    # Check if the related resource can be obtained and store it
    response = manage_security_resources(params_values={related_resource_name: related_resource_id}).json()
    assert response['error'] == 0, f"Couldn't get related resource.\nFull response: {response}"
    old_response = response['data']['affected_items'][0]
    # Check if the relation still existing
    relation = old_response[TARGET_ROUTE_MAP[target_resource_name]]
    assert relation != [], f"The relation was removed.\nExpected: [...]\nCurrent: {relation}"

    # Remove target resource
    response = manage_security_resources('delete', params_values={target_resource_name: target_resource_id}).json()
    assert response['error'] == 0, f"Couldn't remove target resource.\nFull response: {response}"

    response = manage_security_resources(params_values={related_resource_name: related_resource_id}).json()
    assert response['error'] == 0, f"Couldn't get related resource.\nFull response: {response}"
    new_response = response['data']['affected_items'][0]
    # Check if the relation does not exist anymore
    relation = new_response[TARGET_ROUTE_MAP[target_resource_name]]
    assert relation == [], f"The relation should be removed.\nExpected: []\nCurrent: {relation}"
