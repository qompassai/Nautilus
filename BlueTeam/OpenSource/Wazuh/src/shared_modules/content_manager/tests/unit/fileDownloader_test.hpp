/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILE_DOWNLOADER_TEST_HPP
#define _FILE_DOWNLOADER_TEST_HPP

#include "conditionSync.hpp"
#include "fakes/fakeServer.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <memory>

/**
 * @brief Runs unit tests for FileDownloader
 *
 */
class FileDownloaderTest : public ::testing::Test
{
protected:
    FileDownloaderTest() = default;
    ~FileDownloaderTest() override = default;

    std::shared_ptr<UpdaterContext> m_spUpdaterContext;         ///< Context used in tests.
    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext; ///< Base context used in tests.
    const std::filesystem::path m_outputFolder {std::filesystem::temp_directory_path() /
                                                "FileDownloaderTest"}; ///< Output folder for tests.
    inline static std::unique_ptr<FakeServer> m_spFakeServer;          ///< Fake HTTP server used in tests.
    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)}; ///< Stop condition wrapper

    /**
     * @brief Setup routine for the test suite.
     *
     */
    static void SetUpTestSuite();

    /**
     * @brief Teardown routine for the test suite.
     *
     */
    static void TearDownTestSuite();

    /**
     * @brief Setup routine for each test fixture.
     *
     */
    void SetUp() override;

    /**
     * @brief Teardown routine for each test fixture.
     *
     */
    void TearDown() override;
};

#endif //_FILE_DOWNLOADER_TEST_HPP
