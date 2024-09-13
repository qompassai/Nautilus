/*
 * Wazuh Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * December, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#include "wazuh_modules/wmodules.h"

static const char *XML_TIMEOUT = "timeout";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_DISABLED = "disabled";

static const char *XML_LOG_ANALYTICS = "log_analytics";
static const char *XML_GRAPH = "graph";
static const char *XML_STORAGE = "storage";

static const char *XML_AUTH_PATH = "auth_path";
static const char *XML_TENANTDOMAIN = "tenantdomain";
static const char *XML_REQUEST = "request";

static const char *XML_TAG = "tag";
static const char *XML_CONTAINER = "container";
static const char *XML_CONTAINER_NAME = "name";
static const char *XML_CONTAINER_BLOBS = "blobs";
static const char *XML_CONTAINER_TYPE="content_type";
static const char *XML_PATH = "path";

static const char *XML_REQUEST_QUERY = "query";
static const char *XML_TIME_OFFSET = "time_offset";
static const char *XML_WORKSPACE = "workspace";

static int wm_azure_api_read(const OS_XML *xml, XML_NODE nodes, wm_azure_api_t * api_config);
static int wm_azure_request_read(XML_NODE nodes, wm_azure_request_t * request, unsigned int type);
static int wm_azure_storage_read(const OS_XML *xml, XML_NODE nodes, wm_azure_storage_t * storage);
static int wm_azure_container_read(XML_NODE nodes, wm_azure_container_t * container);

static void wm_clean_api(wm_azure_api_t * api_config);
static void wm_clean_request(wm_azure_request_t * request);
static void wm_clean_storage(wm_azure_storage_t * storage);
static void wm_clean_container(wm_azure_container_t * container);

// Parse XML

int wm_azure_read(const OS_XML *xml, xml_node **nodes, wmodule *module)
{
    int i = 0;
    wm_azure_t *azure;
    wm_azure_api_t *api_config = NULL;
    wm_azure_api_t *api_config_prev = NULL;
    wm_azure_storage_t *storage = NULL;
    wm_azure_storage_t *storage_prev = NULL;

    // Create module

    os_calloc(1, sizeof(wm_azure_t), azure);
    azure->flags.enabled = 1;
    azure->flags.run_on_start = 1;
    sched_scan_init(&(azure->scan_config));
    azure->scan_config.interval = WM_DEF_INTERVAL;
    module->context = &WM_AZURE_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = azure;

    if (!nodes) {
        merror("Empty configuration at module '%s'.", WM_AZURE_CONTEXT.name);
        return OS_INVALID;
    }

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        XML_NODE children = NULL;

        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            azure->timeout = atol(nodes[i]->content);

            if (azure->timeout <= 0 || azure->timeout >= UINT_MAX) {
                merror("At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                azure->flags.run_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                azure->flags.run_on_start = 0;
            else {
                merror("At module '%s': Invalid content for tag '%s'.", WM_AZURE_CONTEXT.name, XML_RUN_ON_START);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                azure->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                azure->flags.enabled = 1;
            else {
                merror("At module '%s': Invalid content for tag '%s'.", WM_AZURE_CONTEXT.name, XML_DISABLED);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_LOG_ANALYTICS)) {

            if (api_config) {
                os_calloc(1, sizeof(wm_azure_api_t), api_config->next);
                api_config_prev = api_config;
                api_config = api_config->next;
            } else {
                // First API configuration block
                os_calloc(1, sizeof(wm_azure_api_t), api_config);
                azure->api_config = api_config;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                merror(XML_INVELEM, nodes[i]->element);
                return OS_INVALID;
            }

            api_config->type = LOG_ANALYTICS;
            if (wm_azure_api_read(xml, children, api_config) < 0) {
                wm_clean_api(api_config);
                if (api_config_prev) {
                    api_config = api_config_prev;
                    api_config->next = NULL;
                } else {
                    azure->api_config = api_config = NULL;
                }
            }

            OS_ClearNode(children);

        } else if (!strcmp(nodes[i]->element, XML_GRAPH)) {

            if (api_config) {
                os_calloc(1, sizeof(wm_azure_api_t), api_config->next);
                api_config_prev = api_config;
                api_config = api_config->next;
            } else {
                // First API configuration block
                os_calloc(1, sizeof(wm_azure_api_t), api_config);
                azure->api_config = api_config;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                merror(XML_INVELEM, nodes[i]->element);
                return OS_INVALID;
            }

            api_config->type = GRAPHS;
            if (wm_azure_api_read(xml, children, api_config) < 0) {
                wm_clean_api(api_config);
                if (api_config_prev) {
                    api_config = api_config_prev;
                    api_config->next = NULL;
                } else {
                    azure->api_config = api_config = NULL;
                }
            }

            OS_ClearNode(children);

        } else if (!strcmp(nodes[i]->element, XML_STORAGE)) {

            if (storage) {
                os_calloc(1, sizeof(wm_azure_storage_t), storage->next);
                storage_prev = storage;
                storage = storage->next;
            } else {
                // First API configuration block
                os_calloc(1, sizeof(wm_azure_storage_t), storage);
                azure->storage = storage;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                merror(XML_INVELEM, nodes[i]->element);
                return OS_INVALID;
            }

            if (wm_azure_storage_read(xml, children, storage) < 0) {
                wm_clean_storage(storage);
                if (storage_prev) {
                    storage = storage_prev;
                    storage->next = NULL;
                } else {
                    azure->storage = storage = NULL;
                }
            }

            OS_ClearNode(children);

        } else if (is_sched_tag(nodes[i]->element)) {
            // Do nothing
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_AZURE_CONTEXT.name);
            return OS_INVALID;
        }
    }

    const int sched_read = sched_scan_read(&(azure->scan_config), nodes, module->context->name);
    if ( sched_read != 0 ) {
        return OS_INVALID;
    }

    return 0;
}

int wm_azure_api_read(const OS_XML *xml, XML_NODE nodes, wm_azure_api_t * api_config) {

    int i = 0;
    wm_azure_request_t *request = NULL;
    wm_azure_request_t *request_prev = NULL;

    api_config->auth_path = NULL;
    api_config->tenantdomain = NULL;

    for (i = 0; nodes[i]; i++) {
        XML_NODE children = NULL;

        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;

        } else if (!nodes[i]->content) {
            merror(XML_VALUENULL, nodes[i]->element);
            return OS_INVALID;

        } else if (!strcmp(nodes[i]->element, XML_AUTH_PATH)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, api_config->auth_path);
        } else if (!strcmp(nodes[i]->element, XML_TENANTDOMAIN)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, api_config->tenantdomain);
        } else if (!strcmp(nodes[i]->element, XML_REQUEST)) {

            if (request) {
                os_calloc(1, sizeof(wm_azure_request_t), request->next);
                request_prev = request;
                request = request->next;
            } else {
                // First request block
                os_calloc(1, sizeof(wm_azure_request_t), request);
                api_config->request = request;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                merror(XML_INVELEM, nodes[i]->element);
                return OS_INVALID;
            }

            if (wm_azure_request_read(children, request, api_config->type) < 0) {
                wm_clean_request(request);
                if (request_prev) {
                    request = request_prev;
                    request->next = NULL;
                } else {
                    api_config->request = request = NULL;
                }
            }

            OS_ClearNode(children);

        } else {
            merror(XML_INVELEM, nodes[i]->element);
            return OS_INVALID;
        }
    }

    /* Validation process */
    if (!api_config->auth_path) {
        merror("At module '%s': No authentication method provided. Skipping block...", WM_AZURE_CONTEXT.name);
        return OS_INVALID;
    }

    if (!api_config->tenantdomain) {
        merror("At module '%s': No tenant domain defined. Skipping block...", WM_AZURE_CONTEXT.name);
        return OS_INVALID;
    }

    if (!api_config->request) {
        merror("At module '%s': No request defined. Skipping block...", WM_AZURE_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}

int wm_azure_request_read(XML_NODE nodes, wm_azure_request_t * request, unsigned int type) {

    int i = 0;

    request->tag = NULL;
    request->query = NULL;
    request->time_offset = NULL;
    request->workspace = NULL;

    for (i = 0; nodes[i]; i++) {

        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;

        } else if (!nodes[i]->content) {
            merror(XML_VALUENULL, nodes[i]->element);
            return OS_INVALID;

        } else if (!strcmp(nodes[i]->element, XML_TAG)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, request->tag);
        } else if (!strcmp(nodes[i]->element, XML_REQUEST_QUERY)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, request->query);
        } else if (!strcmp(nodes[i]->element, XML_TIME_OFFSET)) {
            char *endptr;
            unsigned int offset = strtoul(nodes[i]->content, &endptr, 0);

            if (offset <= 0 || offset >= UINT_MAX) {
                merror("At module '%s': Invalid time offset.", WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }

            if (*endptr != 'm' && *endptr != 'h' && *endptr != 'd') {
                merror("At module '%s': Invalid time offset: It should be specified minutes, hours or days.", WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content, request->time_offset);

        } else if (!strcmp(nodes[i]->element, XML_WORKSPACE)) {
            if (type == LOG_ANALYTICS) {
                if (*nodes[i]->content != '\0')
                    os_strdup(nodes[i]->content, request->workspace);
            } else {
                minfo("At module '%s': Workspace ID only available for Log Analytics API. Skipping it...", WM_AZURE_CONTEXT.name);
            }
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            request->timeout = atol(nodes[i]->content);

            if (request->timeout <= 0 || request->timeout >= UINT_MAX) {
                merror("At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            merror(XML_INVELEM, nodes[i]->element);
            return OS_INVALID;
        }
    }

    /* Validation process */
    if (!request->tag) {
        mdebug2("At module '%s': No request tag defined. Setting it randomly...", WM_AZURE_CONTEXT.name);
        int random_id = os_random();
        char * rtag;

        os_calloc(OS_SIZE_128, sizeof(char), rtag);

        if (random_id < 0)
            random_id = -random_id;

        snprintf(rtag, OS_SIZE_128, "request_%d", random_id);
        os_strdup(rtag, request->tag);
        free(rtag);
    }

    if (!request->query) {
        merror("At module '%s': No query defined. Skipping request block...", WM_AZURE_CONTEXT.name);
        return OS_INVALID;
    }

    if (!request->workspace && type == LOG_ANALYTICS) {
        merror("At module '%s': No Workspace ID defined. Skipping request block...", WM_AZURE_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}

int wm_azure_storage_read(const OS_XML *xml, XML_NODE nodes, wm_azure_storage_t * storage) {

    int i = 0;
    wm_azure_container_t *container = NULL;
    wm_azure_container_t *container_prev = NULL;

    storage->auth_path = NULL;
    storage->tag = NULL;

    for (i = 0; nodes[i]; i++) {
        XML_NODE children = NULL;

        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;

        } else if (!nodes[i]->content && (strcmp(nodes[i]->element, XML_CONTAINER) != 0)) {
            merror(XML_VALUENULL, nodes[i]->element);
            return OS_INVALID;

        } else if (!strcmp(nodes[i]->element, XML_CONTAINER)) {

            if (container) {
                os_calloc(1, sizeof(wm_azure_container_t), container->next);
                container_prev = container;
                container = container->next;
            } else {
                // First request block
                os_calloc(1, sizeof(wm_azure_container_t), container);
                storage->container = container;
            }

            // Read name attribute
            if (nodes[i]->attributes) {
                if (!strcmp(nodes[i]->attributes[0], XML_CONTAINER_NAME) && *nodes[i]->values[0] != '\0') {
                    os_strdup(nodes[i]->values[0], container->name);
                } else {
                    minfo("At module '%s': Invalid container name. Skipping container...", WM_AZURE_CONTEXT.name);
                    wm_clean_container(container);
                    if (container_prev) {
                        container = container_prev;
                        container->next = NULL;
                    } else {
                        storage->container = container = NULL;
                    }
                    continue;
                }
            } else {
                minfo("At module '%s': Container name not found. Skipping container...", WM_AZURE_CONTEXT.name);
                wm_clean_container(container);
                if (container_prev) {
                    container = container_prev;
                    container->next = NULL;
                } else {
                    storage->container = container = NULL;
                }
                continue;
            }

            if ((children = OS_GetElementsbyNode(xml, nodes[i]))) {
                if (wm_azure_container_read(children, container) < 0) {
                    wm_clean_container(container);
                    if (container_prev) {
                        container = container_prev;
                        container->next = NULL;
                    } else {
                        storage->container = container = NULL;
                    }
                }
                OS_ClearNode(children);
            }

        } else if (nodes[i]->content != NULL && *nodes[i]->content != '\0') {
            if (!strcmp(nodes[i]->element, XML_AUTH_PATH)) {
                os_strdup(nodes[i]->content, storage->auth_path);
            } else if (!strcmp(nodes[i]->element, XML_TAG)) {
                os_strdup(nodes[i]->content, storage->tag);
            } else {
                merror(XML_INVELEM, nodes[i]->element);
                return OS_INVALID;
            }

        } else {
            merror(XML_VALUENULL, nodes[i]->element);
            return OS_INVALID;
        }
    }

    /* Validation process */
    if (!storage->auth_path) {
        merror("At module '%s': No authentication method provided. Skipping block...", WM_AZURE_CONTEXT.name);
        return OS_INVALID;
    }

    if (!storage->tag) {
        mdebug2("At module '%s': No storage tag defined. Setting it randomly...", WM_AZURE_CONTEXT.name);
        int random_id = os_random();
        char * rtag;

        os_calloc(OS_SIZE_128, sizeof(char), rtag);

        if (random_id < 0)
            random_id = -random_id;

        snprintf(rtag, OS_SIZE_128, "storage_%d", random_id);
        os_strdup(rtag, storage->tag);
        free(rtag);
    }

    if (!storage->container) {
        merror("At module '%s': No container defined. Skipping block...", WM_AZURE_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}

int wm_azure_container_read(XML_NODE nodes, wm_azure_container_t * container) {

    int i = 0;

    container->blobs = NULL;
    container->time_offset = NULL;
    container->content_type = NULL;
    container->path = NULL;

    for (i = 0; nodes[i]; i++) {

        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;

        } else if (!nodes[i]->content) {
            merror(XML_VALUENULL, nodes[i]->element);
            return OS_INVALID;

        } else if (!strcmp(nodes[i]->element, XML_CONTAINER_BLOBS)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, container->blobs);
        } else if (!strcmp(nodes[i]->element, XML_CONTAINER_TYPE)) {
            if (strncmp(nodes[i]->content, "json_file", 9) && strncmp(nodes[i]->content, "json_inline", 11) && strncmp(nodes[i]->content, "text", 4)) {
                merror("At module '%s': Invalid content type. It should be 'json_file', 'json_inline' or 'text'.", WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }
            os_strdup(nodes[i]->content, container->content_type);
        } else if (!strcmp(nodes[i]->element, XML_TIME_OFFSET)) {
            char *endptr;
            unsigned int offset = strtoul(nodes[i]->content, &endptr, 0);

            if (offset <= 0 || offset >= UINT_MAX) {
                merror("At module '%s': Invalid time offset.", WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }

            if (*endptr != 'm' && *endptr != 'h' && *endptr != 'd') {
                merror("At module '%s': Invalid time offset: It should be specified minutes, hours or days.", WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content, container->time_offset);

        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            container->timeout = atol(nodes[i]->content);

            if (container->timeout <= 0 || container->timeout >= UINT_MAX) {
                merror("At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }

        } else if (!strcmp(nodes[i]->element, XML_PATH)) {
            if (strlen(nodes[i]->content) != 0) {
                os_strdup(nodes[i]->content, container->path);
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty content for tag '%s' at module '%s'", XML_PATH, WM_AZURE_CONTEXT.name);
                return OS_INVALID;
            }

        } else {
            merror(XML_INVELEM, nodes[i]->element);
            return OS_INVALID;
        }
    }


    return 0;
}


void wm_clean_api(wm_azure_api_t * api_config) {

    wm_azure_request_t *curr_request = NULL;
    wm_azure_request_t *next_request = NULL;

    if (api_config->auth_path)
        free(api_config->auth_path);
    if (api_config->tenantdomain)
        free(api_config->tenantdomain);

    for (curr_request = api_config->request; curr_request; curr_request = next_request) {

        next_request = curr_request->next;
        wm_clean_request(curr_request);
    }

    free(api_config);
}

void wm_clean_request(wm_azure_request_t * request) {

    if (request->tag)
        free(request->tag);
    if (request->query)
        free(request->query);
    if (request->workspace)
        free(request->workspace);
    if (request->time_offset)
        free(request->time_offset);

    free(request);
}


void wm_clean_storage(wm_azure_storage_t * storage) {

    wm_azure_container_t *curr_container = NULL;
    wm_azure_container_t *next_container = NULL;

    if (storage->auth_path)
        free(storage->auth_path);
    if (storage->tag)
        free(storage->tag);

    for (curr_container = storage->container; curr_container; curr_container = next_container) {

        next_container = curr_container->next;
        wm_clean_container(curr_container);
    }

    free(storage);
}

void wm_clean_container(wm_azure_container_t * container) {

    if (container->name)
        free(container->name);
    if (container->blobs)
        free(container->blobs);
    if (container->content_type)
        free(container->content_type);
    if (container->time_offset)
        free(container->time_offset);

    free(container);
}

#endif
