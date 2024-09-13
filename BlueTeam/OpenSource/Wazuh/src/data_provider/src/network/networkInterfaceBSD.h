/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_BSD_H
#define _NETWORK_BSD_H

#include "inetworkInterface.h"
#include "inetworkWrapper.h"

class FactoryBSDNetwork
{
    public:
        static std::shared_ptr<IOSNetwork>create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper);
};

template <unsigned short osNetworkType>
class BSDNetworkImpl final : public IOSNetwork
{
        const std::shared_ptr<INetworkInterfaceWrapper> m_interfaceAddress;
    public:
        explicit BSDNetworkImpl(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceAddress)
            : m_interfaceAddress(interfaceAddress)
        { }
        void buildNetworkData(nlohmann::json& /*network*/) override
        {
            throw std::runtime_error { "Non implemented specialization." };
        }
};

#endif // _NETWORK_BSD_H
