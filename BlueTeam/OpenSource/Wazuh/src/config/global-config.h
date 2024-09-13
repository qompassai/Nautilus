/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CCONFIG_H
#define CCONFIG_H

#include "shared.h"

#define EPS_LIMITS_DEFAULT_TIMEFRAME 10
#define EPS_LIMITS_MAX_TIMEFRAME 3600
#define EPS_LIMITS_MIN_TIMEFRAME 1
#define EPS_LIMITS_MAX_EPS 100000
#define EPS_LIMITS_MIN_EPS 0

#define CTI_URL_DEFAULT "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0"

typedef struct __eps {
    // EPS limits configuration
    unsigned int maximum;
    unsigned int timeframe;
    bool maximum_found;
} _eps;

/* Configuration structure */
typedef struct __Config {
    u_int8_t logall;
    u_int8_t logall_json;
    u_int8_t stats;
    u_int8_t integrity;
    u_int8_t syscheck_auto_ignore;
    int syscheck_ignore_frequency;
    int syscheck_ignore_time;
    u_int8_t syscheck_alert_new;
    u_int8_t rootcheck;
    u_int8_t hostinfo;
    u_int8_t mailbylevel;
    u_int8_t logbylevel;
    u_int8_t logfw;
    u_int8_t update_check;
    int decoder_order_size;

    /* Agent's disconnection global parameters */
    long agents_disconnection_time;
    long agents_disconnection_alert_time;

    /* Prelude support */
    u_int8_t prelude;
    /* which min. level the alert must be sent to prelude */
    u_int8_t prelude_log_level;
    /* prelude profile name */
    char *prelude_profile;

    /* GeoIP DB */
    char *geoipdb_file;

    /* ZEROMQ Export */
    u_int8_t zeromq_output;
    char *zeromq_output_uri;
    char *zeromq_output_server_cert;
    char *zeromq_output_client_cert;

    /* JSONOUT Export */
    u_int8_t jsonout_output;

    /* Standard alerts output */
    u_int8_t alerts_log;

    /* Not currently used */
    u_int8_t keeplogdate;

    /* Mail alerting */
    short int mailnotify;

    /* Custom Alert output*/
    short int custom_alert_output;
    char *custom_alert_output_format;

    /* For the active response */
    int ar;

    /* For the correlation */
    int memorysize;

    /* List of files to ignore (syscheck) */
    char **syscheck_ignore;

    /* List of ips to never block */
    os_ip **white_list;

    /* List of hostnames to never block */
    OSMatch **hostname_white_list;

    /* List of rules */
    char **includes;

    /* List of Lists */
    char **lists;

    /* List of decoders */
    char **decoders;

    /* Global rule hash */
    OSHash *g_rules_hash;

    /* Vector of targets forwarder */
    char** forwarders_list;

    /* Vector of socket configuration from ossec.conf <socket/> */
    socket_forwarder *socket_list;


#ifdef LIBGEOIP_ENABLED
    /* GeoIP support */
    u_int8_t loggeoip;
    char *geoip_db_path;
    char *geoip6_db_path;
    int geoip_jsonout;
#endif

    wlabel_t *labels; /* null-ended label set */
    int label_cache_maxage;
    int show_hidden_labels;

    // Cluster configuration
    char *cluster_name;
    char *node_name;
    char *node_type;
    unsigned char hide_cluster_info;

    int rotate_interval;
    int min_rotate_interval;
    ssize_t max_output_size;
    long queue_size;

    // EPS limits configuration
    _eps eps;

    // CTI URL
    char *cti_url;
} _Config;


void config_free(_Config *config);

#endif /* CCONFIG_H */
