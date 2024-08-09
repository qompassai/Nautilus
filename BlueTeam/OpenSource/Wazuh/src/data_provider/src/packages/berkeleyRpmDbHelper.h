/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BERKELEY_RPM_DB_HELPER_H
#define _BERKELEY_RPM_DB_HELPER_H

#include <string>
#include <memory>
#include <map>
#include <vector>
#include <algorithm>
#include "byteArrayHelper.h"
#include "berkeleyDbWrapper.h"

#define TAG_NAME        1000
#define TAG_VERSION     1001
#define TAG_RELEASE     1002
#define TAG_EPOCH       1003
#define TAG_SUMMARY     1004
#define TAG_ITIME       1008
#define TAG_SIZE        1009
#define TAG_VENDOR      1011
#define TAG_GROUP       1016
#define TAG_SOURCE      1044
#define TAG_ARCH        1022

constexpr auto RPM_DATABASE {"/var/lib/rpm/Packages"};
constexpr unsigned int FIRST_ENTRY_OFFSET { 8u };
constexpr unsigned int ENTRY_SIZE { 16u };
constexpr int INT32_TYPE { 4 };
constexpr int STRING_TYPE { 6 };
constexpr int STRING_VECTOR_TYPE { 9 };

//This constant is defined with this value in the RPM source code (header.c)
constexpr int HEADER_TAGS_MAX { 65535 };

struct BerkeleyHeaderEntry final
{
    std::string tag;
    int type;
    int offset;
    int count;
};

const std::vector<std::pair<int32_t, std::string>> TAG_NAMES =
{
    { std::make_pair(TAG_NAME, "name") },
    { std::make_pair(TAG_ARCH, "architecture") },
    { std::make_pair(TAG_SUMMARY, "description") },
    { std::make_pair(TAG_SIZE, "size") },
    { std::make_pair(TAG_EPOCH, "epoch") },
    { std::make_pair(TAG_RELEASE, "release") },
    { std::make_pair(TAG_VERSION, "version") },
    { std::make_pair(TAG_VENDOR, "vendor") },
    { std::make_pair(TAG_ITIME, "install_time") },
    { std::make_pair(TAG_GROUP, "group") }
};

class BerkeleyRpmDBReader final
{
    private:
        bool m_firstIteration;
        std::shared_ptr<IBerkeleyDbWrapper> m_dbWrapper;

        std::vector<BerkeleyHeaderEntry> parseHeader(const DBT& data)
        {
            auto bytes { reinterpret_cast<uint8_t*>(data.data) };
            std::vector<BerkeleyHeaderEntry> retVal;
            constexpr auto BYTE_SIZE_INT32{ sizeof(int32_t) };

            if (data.size >= FIRST_ENTRY_OFFSET)
            {
                const auto indexSize { Utils::toInt32BE(bytes) };

                const auto dataSize { Utils::toInt32BE(bytes + BYTE_SIZE_INT32) };

                const auto estimatedHeaderTagSize { FIRST_ENTRY_OFFSET + indexSize* ENTRY_SIZE + dataSize };

                if (indexSize > 0 && indexSize < HEADER_TAGS_MAX && estimatedHeaderTagSize <= data.size)
                {
                    bytes = &bytes[FIRST_ENTRY_OFFSET];

                    retVal.resize(indexSize);

                    auto ucp { reinterpret_cast<uint8_t*>(bytes) };

                    // Read all indexes
                    for (auto i = 0; i < indexSize; ++i)
                    {
                        const auto tag { Utils::toInt32BE(ucp) };
                        ucp += BYTE_SIZE_INT32;

                        const auto it
                        {
                            std::find_if(TAG_NAMES.begin(),
                                         TAG_NAMES.end(),
                                         [tag](const auto & pair)
                            {
                                return tag == pair.first;
                            })
                        };

                        if (TAG_NAMES.end() != it)
                        {
                            retVal[i].tag = it->second;

                            retVal[i].type = Utils::toInt32BE(ucp);
                            ucp += BYTE_SIZE_INT32;

                            retVal[i].offset = Utils::toInt32BE(ucp);
                            ucp += BYTE_SIZE_INT32;

                            retVal[i].count = Utils::toInt32BE(ucp);
                            ucp += BYTE_SIZE_INT32;
                        }
                        else
                        {
                            ucp += ENTRY_SIZE - BYTE_SIZE_INT32;
                        }
                    }
                }
            }

            return retVal;
        }

        std::string parseBody(const std::vector<BerkeleyHeaderEntry>& header, const DBT& data)
        {
            std::string retVal;

            if (!header.empty())
            {
                auto bytes { reinterpret_cast<char*>(data.data) + FIRST_ENTRY_OFFSET + (ENTRY_SIZE * header.size()) };

                for (const auto& TAG : TAG_NAMES)
                {
                    const auto it
                    {
                        std::find_if(header.begin(),
                                     header.end(),
                                     [&TAG](const auto & headerEntry)
                        {
                            return TAG.second.compare(headerEntry.tag) == 0;
                        })
                    };

                    if (it != header.end())
                    {
                        auto ucp { &bytes[it->offset] };

                        if (STRING_TYPE == it->type)
                        {
                            retVal += ucp;
                        }
                        else if (INT32_TYPE == it->type)
                        {
                            retVal += std::to_string(Utils::toInt32BE(reinterpret_cast<uint8_t*>(ucp)));
                        }
                        else if (STRING_VECTOR_TYPE == it->type)
                        {
                            retVal += ucp;
                        }
                    }

                    retVal += "\t";
                }

                retVal += "\n";
            }

            return retVal;
        }

    public:
        std::string getNext()
        {
            std::string retVal;
            DBT key, data;
            int cursorRet;

            if (m_firstIteration)
            {
                if (cursorRet = m_dbWrapper->getRow(key, data), cursorRet == 0)
                {
                    m_firstIteration = false;
                }
            }

            if (cursorRet = m_dbWrapper->getRow(key, data), cursorRet == 0)
            {
                retVal = parseBody(parseHeader(data), data);
            }

            return retVal;
        }
        explicit BerkeleyRpmDBReader(std::shared_ptr<IBerkeleyDbWrapper> dbWrapper)
            : m_firstIteration { true }
            , m_dbWrapper { dbWrapper }
        { }

        ~BerkeleyRpmDBReader() { }
};
#endif // _BERKELEY_RPM_DB_HELPER_H
