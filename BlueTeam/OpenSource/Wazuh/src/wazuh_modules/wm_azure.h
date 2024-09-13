/*
 * Wazuh Module for Azure
 * Copyright (C) 2015, Wazuh Inc.
 * September, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AZURE
#define WM_AZURE

#define WM_AZURE_LOGTAG ARGV0 ":" AZ_WM_NAME
#define WM_AZURE_SCRIPT_PATH "wodles/azure/azure-logs"

#define LOG_ANALYTICS   0
#define GRAPHS          1

#define WM_AZURE_DEF_TIMEOUT 3600

typedef struct wm_azure_flags_t {
    unsigned int enabled:1;
    unsigned int run_on_start:1;
} wm_azure_flags_t;

typedef struct wm_azure_state_t {
    time_t next_time;               // Absolute time for next scan
} wm_azure_state_t;

typedef struct wm_azure_request_t {
    char * tag;             // Request tag
    char * workspace;       // Workspace ID
    char * query;           // SQL Query
    char * time_offset;     // Offset to look for logs (minutes, hours, days)
    unsigned int timeout;   // Timeout for a single request
    struct wm_azure_request_t *next;
} wm_azure_request_t;

typedef struct wm_azure_api_t {
    unsigned int type:1;        // Type of API defined (Log analytics or graph)
    char * auth_path;           // Authentication file with application ID and key
    char * tenantdomain;        // Domain
    wm_azure_request_t *request;  // Requests (linked list)
    struct wm_azure_api_t *next;
} wm_azure_api_t;

typedef struct wm_azure_container_t {
    char * name;            // Container name
    char * blobs;           // Blobs
    char * content_type;    // Content type (plain | inline | file)
    char * time_offset;     // Offset to look for logs (minutes, hours, days)
    char * path;          // Prefix to search into
    unsigned int timeout;   // Timeout for a single container
    struct wm_azure_container_t *next;
} wm_azure_container_t;

typedef struct wm_azure_storage_t {
    char * auth_path;       // Authentication file with account name and key
    char * tag;             // Storage tag
    wm_azure_container_t *container;  // Storage container
    struct wm_azure_storage_t *next;
} wm_azure_storage_t;

typedef struct wm_azure_t {
    unsigned int timeout;           // Default execution time limit (seconds)
    wm_azure_flags_t flags;           // Default flags
    wm_azure_state_t state;           // Running state
    wm_azure_api_t *api_config;     // Log Analytics and Graphs (linked list)
    wm_azure_storage_t *storage;    // Storage (linked list)
    sched_scan_config scan_config;  // Scheduling configuration
} wm_azure_t;

extern const wm_context WM_AZURE_CONTEXT;   // Context

// Parse XML configuration
int wm_azure_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif
