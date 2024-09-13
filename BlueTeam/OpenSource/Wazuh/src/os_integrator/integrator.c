/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2014 Daniel B. Cid
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */
#include "shared.h"
#include "integrator.h"
#include <external/cJSON/cJSON.h>
#include "os_net/os_net.h"


void OS_IntegratorD(IntegratorConfig **integrator_config)
{
    int s = 0;
    int tries = 0;
    int temp_file_created = 0;
    int opt_file_created = 0;
    unsigned int alert_level = 0;
    unsigned int rule_id = 0;
    char integration_path[2048 + 1];
    char exec_tmp_file[2048 + 1];
    char exec_full_cmd[4096 + 1];
    char opt_tmp_file[2048 + 1];
    FILE *fp;

    file_queue jfileq;
    cJSON *al_json = NULL;
    cJSON *json_object;
    cJSON *json_field;
    cJSON *location;
    cJSON *rule;
    cJSON *data;

    integration_path[2048] = 0;
    exec_tmp_file[2048] = 0;
    exec_full_cmd[4096] = 0;

    /* Initing file queue JSON - to read the alerts */
    jqueue_init(&jfileq);

    for (tries = 1; tries < 100 && jqueue_open(&jfileq, 1) < 0; tries++) {
        sleep(1);
    }

    if (tries == 100) {
        merror("Could not open JSON queue after %d tries.", tries);
    } else {
        mdebug1("JSON file queue connected.");
    }

    /* Connecting to syslog. */
    while(integrator_config[s])
    {
        integrator_config[s]->enabled = 1;

        snprintf(integration_path, 2048 -1, "%s/%s", INTEGRATORDIR, integrator_config[s]->name);
        if(File_DateofChange(integration_path) > 0)
        {
            os_strdup(integration_path, integrator_config[s]->path);
        }
        else
        {
            integrator_config[s]->enabled = 0;
            merror("Unable to enable integration for: '%s'. File not found inside '%s'.", integrator_config[s]->name, INTEGRATORDIR);
            s++;
            continue;
        }

        if(strcmp(integrator_config[s]->name, "slack") == 0)
        {
            if(!integrator_config[s]->hookurl)
            {
                integrator_config[s]->enabled = 0;
                merror("Unable to enable integration for: '%s'. Missing hook URL.", integrator_config[s]->name);
                s++;
                continue;
            }
        }
        else if(strcmp(integrator_config[s]->name, "shuffle") == 0)
        {
            if(!integrator_config[s]->hookurl)
            {
                integrator_config[s]->enabled = 0;
                merror("Unable to enable integration for: '%s'. Missing hook URL.", integrator_config[s]->name);
                s++;
                continue;
            }
        }
        else if(strcmp(integrator_config[s]->name, "pagerduty") == 0)
        {
            if(!integrator_config[s]->apikey)
            {
                integrator_config[s]->enabled = 0;
                merror("Unable to enable integration for: '%s'. Missing API Key.", integrator_config[s]->name);
                s++;
                continue;
            }
        }
		else if(strcmp(integrator_config[s]->name, "virustotal") == 0)
        {
            if(!integrator_config[s]->apikey)
            {
                integrator_config[s]->enabled = 0;
                merror("Unable to enable integration for: '%s'. Missing API Key.", integrator_config[s]->name);
                s++;
                continue;
            }
        }
        else if(strcmp(integrator_config[s]->name, "maltiverse") == 0)
        {
            if(!integrator_config[s]->hookurl)
            {
                integrator_config[s]->enabled = 0;
                merror("Unable to enable integration for: '%s'. Missing hook URL.", integrator_config[s]->name);
                s++;
                continue;
            }
            if(!integrator_config[s]->apikey)
            {
                integrator_config[s]->enabled = 0;
                merror("Unable to enable integration for: '%s'. Missing API Key.", integrator_config[s]->name);
                s++;
                continue;
            }
        }
        else if(strncmp(integrator_config[s]->name, "custom-", 7) == 0)
        {
        }

        else
        {
            integrator_config[s]->enabled = 0;
            merror("Invalid integration: '%s'. Not currently supported.", integrator_config[s]->name);
        }

        if(integrator_config[s]->enabled == 1)
        {
            minfo("Enabling integration for: '%s'.",
                   integrator_config[s]->name);
        }
        s++;
    }

    /* Infinite loop reading the alerts and inserting them. */
    while(FOREVER())
    {

        /* Get JSON message if available (timeout of 5 seconds) */
        mdebug2("jqueue_next()");
        al_json = jqueue_next(&jfileq);
        if(!al_json) {
            sleep(1);
            continue;
        }

        mdebug1("Sending new alert.");
        temp_file_created = 0;

        /* If JSON does not contain rule block, continue */
        if (rule = cJSON_GetObjectItem(al_json, "rule"), !rule){
                s++;
                mdebug2("Skipping: Alert does not contain a rule block.");
                cJSON_Delete(al_json);
                continue;
        }

        /* Sending to the configured integrations */
        s = 0;
        while(integrator_config[s])
        {
            if(integrator_config[s]->enabled == 0)
            {
                s++;
                mdebug2("Skipping: Integration disabled");
                continue;
            }

            /* Looking if location is set */
            if(integrator_config[s]->location)
            {

                if (location = cJSON_GetObjectItem(al_json, "location"), !location) {
                    s++; continue;
                }
                if(!OSMatch_Execute(location->valuestring,
                                   strlen(location->valuestring),
                                   integrator_config[s]->location))
                {
                    mdebug2("Skipping: Location doesn't match");
                    s++; continue;
                }
            }

            /* Looking for the level */
            if(integrator_config[s]->level)
            {
                if (json_field = cJSON_GetObjectItem(rule,"level"), !json_field) {
                    s++; continue;
                }
                alert_level = json_field->valueint;
                if(alert_level < integrator_config[s]->level)
                {
                    mdebug2("Skipping: Alert level is too low");
                    s++; continue;
                }
            }

            /* Looking for the group */
            if(integrator_config[s]->group)
            {
                int found = 0;
                char * group;
                char * end;

                if (json_object = cJSON_GetObjectItem(rule,"groups"), json_object) {
                    for (group = integrator_config[s]->group; group && *group && !found; group = end ? end + 1 : NULL) {
                        if (end = strchr(group, ','), end) {
                            *end = '\0';
                        }

                        cJSON_ArrayForEach(json_field, json_object) {
                            if (strcmp(json_field->valuestring, group) == 0) {
                                found++;
                                break;
                            }
                        }

                        if (end) {
                            *end = ',';
                        }
                    }
                }

                if (!found) {
                    mdebug2("Skipping: Group doesn't match.");
                    s++; continue;
                }
            }

            /* Looking for the rule */
            if(integrator_config[s]->rule_id)
            {
                /* match any rule in array */
                int id_i = 0;
                int rule_match = -1;

                if (json_field = cJSON_GetObjectItem(rule,"id"), !json_field) {
                    mdebug2("Skipping: Alert does not containg rule id.");
                    s++; continue;
                }
                rule_id = atoi(json_field->valuestring);

                while(integrator_config[s]->rule_id[id_i])
                {
                    if(rule_id == integrator_config[s]->rule_id[id_i])
                    {
                        rule_match = id_i;
                        break;
                    }

                    id_i++;
                }

                /* skip integration if none are matched */
                if(rule_match == -1)
                {
                    mdebug2("Skipping: Rule doesn't match.");
                    s++; continue;
                }
            }

            /* Create temp file once per alert and integration. */
            snprintf(exec_tmp_file, 2048, "/tmp/%s-%d-%ld.alert",
                        integrator_config[s]->name, (int)time(0), (long int)os_random());

            fp = wfopen(exec_tmp_file, "w");
            if(!fp)
            {
                mdebug2("File %s couldn't be created.", exec_tmp_file);
                exec_tmp_file[0] = '\0';
            }
            else
            {
                if(integrator_config[s]->alert_format != NULL && strncmp(integrator_config[s]->alert_format, "json", 4) == 0){
                    char * unformatted = cJSON_PrintUnformatted(al_json);
                    fprintf(fp, "%s\n", unformatted);
                    temp_file_created = 1;
                    mdebug2("File %s was written.", exec_tmp_file);
                    fclose(fp);
                    free(unformatted);
                }else{
                    int log_count = 0;
                    char *srcip = NULL;
                    json_field = cJSON_GetObjectItem(al_json, "full_log");
                    char *full_log = json_field ? json_field->valuestring : "";
                    char *tmpstr = full_log;

                    while(*tmpstr != '\0')
                    {
                        if(*tmpstr == '\'')
                        {
                            *tmpstr = ' ';
                        }
                        else if(*tmpstr == '\\')
                        {
                            *tmpstr = '/';
                        }
                        else if(*tmpstr == '`')
                        {
                            *tmpstr = ' ';
                        }
                        else if(*tmpstr == '"')
                        {
                            *tmpstr = ' ';
                        }
                        else if(*tmpstr == ';')
                        {
                            *tmpstr = ',';
                        }
                        else if(*tmpstr == '!')
                        {
                            *tmpstr = ' ';
                        }
                        else if(*tmpstr == '$')
                        {
                            *tmpstr = ' ';
                        }

                        else if(*tmpstr < 32 || *tmpstr > 122)
                        {
                            *tmpstr = ' ';
                        }
                        log_count++;
                        tmpstr++;

                        if(log_count >= (int)integrator_config[s]->max_log)
                        {
                            *tmpstr='\0';
                            *(tmpstr -1)='.';
                            *(tmpstr -2)='.';
                            *(tmpstr -3)='.';
                            break;
                        }
                    }
                    if (data = cJSON_GetObjectItem(al_json,"data"), data)
                    {
                        if (json_field = cJSON_GetObjectItem(data,"srcip"), json_field)
                        {
                            srcip = json_field->valuestring;
                            tmpstr = srcip;

                            while(*tmpstr != '\0')
                            {
                                if(*tmpstr == '\'')
                                {
                                    *tmpstr = ' ';
                                }
                                else if(*tmpstr == '\\')
                                {
                                    *tmpstr = ' ';
                                }
                                else if(*tmpstr == '`')
                                {
                                    *tmpstr = ' ';
                                }
                                else if(*tmpstr == ' ')
                                {
                                }
                                else if(*tmpstr < 46 || *tmpstr > 122)
                                {
                                    *tmpstr = ' ';
                                }

                                tmpstr++;
                            }
                        }
                    }
                    char *date = NULL;
                    char *location = NULL;
                    char *rule_id = NULL;
                    int alert_level;
                    char *rule_description = NULL;

                    json_field = cJSON_GetObjectItem(al_json,"timestamp");
                    date = json_field ? json_field->valuestring : "";

                    json_field = cJSON_GetObjectItem(al_json,"location");
                    location = json_field ? json_field->valuestring : "";

                    json_field = cJSON_GetObjectItem(rule,"id");
                    rule_id = json_field ? json_field->valuestring : "";

                    json_field = cJSON_GetObjectItem(rule,"level");
                    alert_level = json_field ? json_field->valueint : 0;

                    json_field = cJSON_GetObjectItem(rule,"description");
                    rule_description = json_field ? json_field->valuestring : "";


                    fprintf(fp, "alertdate='%s'\nalertlocation='%s'\nruleid='%s'\nalertlevel='%d'\nruledescription='%s'\nalertlog='%s'\nsrcip='%s'", date, location, rule_id, alert_level, rule_description, full_log, srcip == NULL?"":srcip);
                    temp_file_created = 1;
                    mdebug2("File %s was written.", exec_tmp_file);
                    fclose(fp);

                }
            }

            /* Create temp file for integration options. */
            if (integrator_config[s]->options != NULL) {
                snprintf(opt_tmp_file, 2048, "/tmp/%s-%d-%ld.options",
                            integrator_config[s]->name, (int)time(0), (long int) os_random());

                fp = wfopen(opt_tmp_file, "w");
                if (!fp) {
                    mdebug2("File %s couldn't be created.", opt_tmp_file);
                    opt_tmp_file[0] = '\0';
                }
                else {
                    fprintf(fp, "%s\n", integrator_config[s]->options);
                    opt_file_created = 1;
                    mdebug2("File %s was written.", opt_tmp_file);
                    fclose(fp);
                }
            }

            int dbg_lvl = isDebug();
            os_snprintf(exec_full_cmd, 4095, "%s %s %s %s %s %s %d %d",
                INTEGRATORDIR,
                exec_tmp_file,
                integrator_config[s]->apikey == NULL ? "" : integrator_config[s]->apikey,
                integrator_config[s]->hookurl == NULL ? "" : integrator_config[s]->hookurl,
                dbg_lvl <= 0 ? "" : "debug",
                opt_file_created == 0 ? "" : opt_tmp_file,
                integrator_config[s]->timeout,
                integrator_config[s]->retries);

            if (dbg_lvl <= 0) strcat(exec_full_cmd, " > /dev/null 2>&1");

            char **cmd = OS_StrBreak(' ', exec_full_cmd, 9);

            if (cmd) {
                wfd_t * wfd = wpopenv(integrator_config[s]->path, cmd, W_BIND_STDOUT | W_BIND_STDERR | W_CHECK_WRITE);
                if (wfd) {
                    char buffer[4096];
                    while (fgets(buffer, sizeof(buffer), wfd->file_out)) {
                        mdebug2("%s", buffer);
                    }
                    int wp_closefd = wpclose(wfd);
                    if ( WIFEXITED(wp_closefd) ) {
                        int wstatus = WEXITSTATUS(wp_closefd);
                        if (wstatus == 127) {
                            // 127 means error in exec
                            merror("Couldn't execute command (%s). Check file and permissions.", exec_full_cmd);
                        } else if(wstatus != 0){
                            merror("Unable to run integration for %s -> %s",  integrator_config[s]->name, INTEGRATORDIR);
                            merror("While running %s -> %s. Output: %s ",  integrator_config[s]->name, INTEGRATORDIR, buffer);
                            merror("Exit status was: %d", wstatus);
                        } else {
                            mdebug1("Command ran successfully.");
                        }
                    } else {
                        merror("Command (%s) execution exited abnormally.", exec_full_cmd);
                    }

                } else {
                    merror("Could not launch command %s (%d)", strerror(errno), errno);
                }
                free_strarray(cmd);
            }
            s++;

            /* Clearing the memory */
            if (temp_file_created == 1) {
                unlink(exec_tmp_file);
                temp_file_created = 0;
            }
            if (opt_file_created == 1) {
                unlink(opt_tmp_file);
                opt_file_created = 0;
            }

        }

        if (al_json) {
            cJSON_Delete(al_json);
        }
    }
}
