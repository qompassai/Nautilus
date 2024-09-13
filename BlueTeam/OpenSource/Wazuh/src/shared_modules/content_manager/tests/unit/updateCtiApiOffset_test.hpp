/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATE_CTI_API_OFFSET_TEST_HPP
#define _UPDATE_CTI_API_OFFSET_TEST_HPP

#include "conditionSync.hpp"
#include "updateCtiApiOffset.hpp"
#include "updaterContext.hpp"
#include "utils/rocksDBWrapper.hpp"
#include "utils/timeHelper.h"
#include "gtest/gtest.h"
#include <filesystem>

const auto DATABASE_FOLDER {std::filesystem::temp_directory_path() / "test_db"};

/**
 * @brief Runs unit tests for UpdateCtiApiOffset
 */
class UpdateCtiApiOffsetTest : public ::testing::Test
{
protected:
    UpdateCtiApiOffsetTest() = default;
    ~UpdateCtiApiOffsetTest() override = default;

    /**
     * @brief Context used on the content manager orchestration.
     */
    std::shared_ptr<UpdaterContext> m_spUpdaterContext;

    /**
     * @brief Context used on the content manager orchestration.
     */
    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext;

    /**
     * @brief Instance of the class to test.
     */
    std::shared_ptr<UpdateCtiApiOffset> m_spUpdateCtiApiOffset;

    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)}; ///< Stop condition wrapper

    /**
     * @brief Sets up the test fixture.
     */
    void SetUp() override
    {
        // Initialize contexts
        m_spUpdaterBaseContext = std::make_shared<UpdaterBaseContext>(m_spStopActionCondition);
        m_spUpdaterBaseContext->spRocksDB = std::make_unique<Utils::RocksDBWrapper>(DATABASE_FOLDER);
        m_spUpdaterBaseContext->spRocksDB->createColumn(Components::Columns::CURRENT_OFFSET);
        m_spUpdaterBaseContext->spRocksDB->put(
            Utils::getCompactTimestamp(std::time(nullptr)), "0", Components::Columns::CURRENT_OFFSET);

        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;

        // Instance of the class to test
        m_spUpdateCtiApiOffset = std::make_shared<UpdateCtiApiOffset>();
    }

    /**
     * @brief Tears down the test fixture.
     */
    void TearDown() override
    {
        if (m_spUpdaterBaseContext->spRocksDB)
        {
            m_spUpdaterBaseContext->spRocksDB->deleteAll();
        }

        std::filesystem::remove_all(DATABASE_FOLDER);
    }
};

#endif //_UPDATE_CTI_API_OFFSET_TEST_HPP
