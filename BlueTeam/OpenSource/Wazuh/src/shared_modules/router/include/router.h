/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_H
#define _ROUTER_H

// Define EXPORTED for any platform

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "logging_helper.h"

#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * @brief Represents the handle associated with router manipulation.
     */
    typedef void* ROUTER_PROVIDER_HANDLE;

    /**
     * @brief Log callback function.
     *
     * @param level Log level.
     * @param log Log message.
     * @param tag Log tag.
     */
    typedef void((*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag));

    /**
     * @brief Initialize router mechanism.
     *
     * @param callbackLog Log callback function.
     */
    EXPORTED int router_initialize(log_callback_t callbackLog);

    /**
     * @brief Start router mechanism.
     *
     */
    EXPORTED int router_start();

    /**
     * @brief Stop router mechanism.
     *
     */
    EXPORTED int router_stop();

    /**
     * @brief Create a router provider.
     *
     * @param name Name of the router provider.
     * @param isLocal True if the router provider is local, false otherwise.
     * @return ROUTER_PROVIDER_HANDLE Handle to the router provider.
     */
    EXPORTED ROUTER_PROVIDER_HANDLE router_provider_create(const char* name, bool isLocal);

    /**
     * @brief Send a message to the router provider.
     *
     * @param handle Handle to the router provider.
     * @param message Message to send.
     * @param message_size Size of the message.
     * @return true if the message was sent successfully.
     * @return false if the message was not sent successfully.
     */
    EXPORTED int router_provider_send(ROUTER_PROVIDER_HANDLE handle, const char* message, unsigned int message_size);

    /**
     * @brief Send a message to the router provider using flatbuffers.
     *
     * @param handle Handle to the router provider.
     * @param message Message to send.
     * @param schema Schema of the message.
     * @return true if the message was sent successfully.
     * @return false if the message was not sent successfully.
     */
    EXPORTED int router_provider_send_fb(ROUTER_PROVIDER_HANDLE handle, const char* message, const char* schema);

    /**
     * @brief Destroy a router provider.
     *
     * @param handle Handle to the router provider.
     */
    EXPORTED void router_provider_destroy(ROUTER_PROVIDER_HANDLE handle);

#ifdef __cplusplus
}
#endif

typedef int (*router_initialize_func)(log_callback_t callbackLog);

typedef int (*router_start_func)();

typedef int (*router_stop_func)();

typedef ROUTER_PROVIDER_HANDLE (*router_provider_create_func)(const char* name, bool isLocal);

typedef bool (*router_provider_send_func)(ROUTER_PROVIDER_HANDLE handle,
                                          const char* message,
                                          unsigned int message_size);
typedef bool (*router_provider_send_fb_func)(ROUTER_PROVIDER_HANDLE handle,
                                          const char* message,
                                          const char* schema);


typedef void (*router_provider_destroy_func)(ROUTER_PROVIDER_HANDLE handle);

#endif // _ROUTER_H
