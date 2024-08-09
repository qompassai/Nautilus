/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OSSECHIDS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"
#include "os_xml/os_xml.h"
#include "rootcheck.h"


/* Evaluate boolean with two arguments
 * str: input string, "yes"|"no"
 * default_val: 1(yes)|0(no)
 */
short eval_bool2(char *str, short default_val)
{
    short ret = default_val;

    if (str == NULL) {
        return (ret);
    } else if (strcmp(str, "yes") == 0) {
        ret = 1;
    } else if (strcmp(str, "no") == 0) {
        ret = 0;
    }

    free(str);
    return (ret);
}

/* Read the rootcheck config */
int Read_Rootcheck_Config(const char *cfgfile)
{
    OS_XML xml;

    /* XML Definitions */
    const char *(xml_base_dir[]) = {xml_rootcheck, "base_directory", NULL};
    const char *(xml_workdir[]) = {xml_rootcheck, "work_directory", NULL};
    const char *(xml_rootkit_files[]) = {xml_rootcheck, "rootkit_files", NULL};
    const char *(xml_rootkit_trojans[]) = {xml_rootcheck, "rootkit_trojans", NULL};
    const char *(xml_rootkit_unixaudit[]) = {xml_rootcheck, "system_audit", NULL};
    const char *(xml_rootkit_winaudit[]) = {xml_rootcheck, "windows_audit", NULL};
    const char *(xml_rootkit_winapps[]) = {xml_rootcheck, "windows_apps", NULL};
    const char *(xml_rootkit_winmalware[]) = {xml_rootcheck, "windows_malware", NULL};
    const char *(xml_scanall[]) = {xml_rootcheck, "scanall", NULL};
    const char *(xml_readall[]) = {xml_rootcheck, "readall", NULL};
#ifdef OSSECHIDS
    const char *(xml_time[]) = {xml_rootcheck, "frequency", NULL};
    char *str = NULL;
#endif
    const char *(xml_check_dev[]) = {xml_rootcheck, "check_dev", NULL};
    const char *(xml_check_files[]) = {xml_rootcheck, "check_files", NULL};
    const char *(xml_check_if[]) = {xml_rootcheck, "check_if", NULL};
    const char *(xml_check_pids[]) = {xml_rootcheck, "check_pids", NULL};
    const char *(xml_check_ports[]) = {xml_rootcheck, "check_ports", NULL};
    const char *(xml_check_sys[]) = {xml_rootcheck, "check_sys", NULL};
    const char *(xml_check_trojans[]) = {xml_rootcheck, "check_trojans", NULL};
#ifdef WIN32
    const char *(xml_check_winapps[]) = {xml_rootcheck, "check_winapps", NULL};
    const char *(xml_check_winaudit[]) = {xml_rootcheck, "check_winaudit", NULL};
    const char *(xml_check_winmalware[]) = {xml_rootcheck, "check_winmalware", NULL};
#else
    const char *(xml_check_unixaudit[]) = {xml_rootcheck, "check_unixaudit", NULL};
#endif

#ifdef OSSECHIDS
    /* :) */
    xml_time[2] = NULL;
#endif

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        mterror(ARGV0, "config_op: XML error: %s", xml.err);
        return (OS_INVALID);
    }

    if (!OS_RootElementExist(&xml, xml_rootcheck)) {
        OS_ClearXML(&xml);
        mterror(ARGV0, "Rootcheck configuration not found.");
        return (-1);
    }


#ifdef OSSECHIDS
    /* time  */
    str = OS_GetOneContentforElement(&xml, xml_time);
    if (str) {
        if (!OS_StrIsNum(str)) {
            mterror(ARGV0, "Invalid frequency time '%s' for the rootkit detection (must be int).", str);
            return (OS_INVALID);
        }

        rootcheck.time = atoi(str);
        free(str);
        str = NULL;
    }
#endif /* OSSECHIDS */

    /* Scan all flags */
    if (!rootcheck.scanall) {
        rootcheck.scanall = eval_bool2(OS_GetOneContentforElement(&xml, xml_scanall), 0);
    }

    /* Read all flags */
    if (!rootcheck.readall) {
        rootcheck.readall = eval_bool2(OS_GetOneContentforElement(&xml, xml_readall), 0);
    }

    /* Get work directory */
    if (!rootcheck.workdir) {
        rootcheck.workdir  = OS_GetOneContentforElement(&xml, xml_workdir);
    }

    rootcheck.rootkit_files  = OS_GetOneContentforElement
                               (&xml, xml_rootkit_files);
    rootcheck.rootkit_trojans  = OS_GetOneContentforElement
                                 (&xml, xml_rootkit_trojans);
    rootcheck.unixaudit = OS_GetContents
                          (&xml, xml_rootkit_unixaudit);
    rootcheck.winaudit  = OS_GetOneContentforElement
                          (&xml, xml_rootkit_winaudit);
    rootcheck.winapps  = OS_GetOneContentforElement
                         (&xml, xml_rootkit_winapps);
    rootcheck.winmalware  = OS_GetOneContentforElement
                            (&xml, xml_rootkit_winmalware);
    rootcheck.basedir  = OS_GetOneContentforElement(&xml, xml_base_dir);
    rootcheck.checks.rc_dev = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_dev), 1);
    rootcheck.checks.rc_files = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_files), 1);
    rootcheck.checks.rc_if = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_if), 1);
    rootcheck.checks.rc_pids = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_pids), 1);
    rootcheck.checks.rc_ports = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_ports), 1);
    rootcheck.checks.rc_sys = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_sys), 1);
    rootcheck.checks.rc_trojans = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_trojans), 1);
#ifdef WIN32
    rootcheck.checks.rc_winapps = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_winapps), 1);
    rootcheck.checks.rc_winaudit = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_winaudit), 1);
    rootcheck.checks.rc_winmalware = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_winmalware), 1);
#else
    rootcheck.checks.rc_unixaudit = eval_bool2(OS_GetOneContentforElement(&xml, xml_check_unixaudit), 1);
#endif /* WIN32 */
    OS_ClearXML(&xml);


    return (0);
}
#endif
