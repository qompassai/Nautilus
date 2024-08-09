/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read PostgreSQL logs */

#include "shared.h"
#include "logcollector.h"
#include "os_crypto/sha1/sha1_op.h"


/* Send pgsql message and check the return code */
static void __send_pgsql_msg(logreader *lf, int drop_it, char *buffer) {
    mdebug2("Reading PostgreSQL message: '%s'", buffer);

    /* Check ignore and restrict log regex, if configured. */
    if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, buffer)) {
        /* Send message to queue */
        w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
    }
}

/* Read PostgreSQL log files */
void *read_postgresql_log(logreader *lf, int *rc, int drop_it) {
    size_t str_len = 0;
    int need_clear = 0;
    char *p;
    char str[OS_MAX_LOG_SIZE] = {0};
    char buffer[OS_MAX_LOG_SIZE] = {0};
    int lines = 0;

    *rc = 0;

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t current_position = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, current_position);

    /* Get new entry */
    while (can_read() && fgets(str, sizeof(str), lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)) {

        lines++;
        /* Get buffer size */
        str_len = strlen(str);

        if (is_valid_context_file) {
            OS_SHA1_Stream(context, NULL, str);
        }

        /* Check str_len size. Very useless, but just to make sure.. */
        if (str_len >= sizeof(buffer) - 2) {
            str_len = sizeof(buffer) - 10;
        }

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';

            /* If need_clear is set, we just get the line and ignore it. */
            if (need_clear) {
                need_clear = 0;
                continue;
            }
        } else {
            need_clear = 1;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on Windows) */
        if (str_len <= 1) {
            continue;
        }

        /* Windows can have comment on their logs */
        if (str[0] == '#') {
            continue;
        }
#endif

        /* PostgreSQL messages have the following format:
         * [2007-08-31 19:17:32.186 ADT] 192.168.2.99:db_name
         */
        if ((str_len > 32) &&
                (str[0] == '[') &&
                (str[5] == '-') &&
                (str[8] == '-') &&
                (str[11] == ' ') &&
                (str[14] == ':') &&
                (str[17] == ':') &&
                isdigit((int)str[1]) &&
                isdigit((int)str[12])) {

            /* If the saved message is empty, set it and continue */
            if (buffer[0] == '\0') {
                snprintf(buffer, sizeof(buffer), "%s", str);
                continue;
            }

            /* If not, send the saved one and store the new one for later */
            else {
                __send_pgsql_msg(lf, drop_it, buffer);
                /* Store current one at the buffer */
                snprintf(buffer, sizeof(buffer), "%s", str);
            }
        }

        /* Query logs can be in multiple lines
         * They always start with a tab in the additional ones
         */
        else if ((str_len > 2) && (buffer[0] != '\0') &&
                 (str[0] == '\t')) {
            /* Size of the buffer */
            size_t buffer_len = strlen(buffer);

            p = str + 1;

            /* Remove extra spaces and tabs */
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* Add additional message to the saved buffer */
            if (sizeof(buffer) - buffer_len > str_len) {
                /* Here we make sure that the size of the buffer
                 * minus what was used (strlen) is greater than
                 * the length of the received message.
                 */
                buffer[buffer_len] = ' ';
                buffer[buffer_len + 1] = '\0';
                strncat(buffer, str, str_len + 3);
            }
        }

    }

    /* Send whatever is stored */
    if (buffer[0] != '\0') {
        __send_pgsql_msg(lf, drop_it, buffer);
    }

    current_position = w_ftell(lf->fp);
    if (is_valid_context_file) {
        w_update_file_status(lf->file, current_position, context);
    } else {
        EVP_MD_CTX_free(context);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
