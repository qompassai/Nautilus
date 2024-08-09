/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CAR_H
#define CAR_H

/* Active response commands */
typedef struct _ar_command {
    int timeout_allowed;

    char *name;
    char *executable;
    char *extra_args;

} ar_command;

/* Active response data */
typedef struct _ar {
    int timeout;
    int location;
    int level;
    char *name;
    char *command;
    char *agent_id;
    char *rules_id;
    char *rules_group;

    ar_command *ar_cmd;
} active_response;

/* Active response flag */
extern int ar_flag;

#endif /* CAR_H */
