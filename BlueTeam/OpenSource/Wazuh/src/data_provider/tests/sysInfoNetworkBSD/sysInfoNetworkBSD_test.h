/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSINFO_NETWORK_BSD_TEST_H
#define _SYSINFO_NETWORK_BSD_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoNetworkBSDTest : public ::testing::Test
{

    protected:

        SysInfoNetworkBSDTest() = default;
        virtual ~SysInfoNetworkBSDTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_NETWORK_BSD_TEST_H