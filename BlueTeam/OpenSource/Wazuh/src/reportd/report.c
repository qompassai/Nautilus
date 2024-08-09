/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

/* Prototypes */
static void help_reportd(char * home_path) __attribute__((noreturn));


/* Print help statement */
static void help_reportd(char * home_path)
{
    print_header();
    print_out("  Generate reports (via stdin)");
    print_out("  %s: -[Vhdtns] [-u user] [-g group] [-D dir] [-f filter value] [-r filter value]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -n          Create description for the report");
    print_out("    -s          Show the alert dump");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot and chdir into (default: %s)", home_path);
    print_out("    -f <filter> <value> Filter the results");
    print_out("    -r <filter> <value> Show related entries");
    print_out("    Filters allowed: group, rule, level, location,");
    print_out("                     user, srcip, filename");
    print_out("  Examples:");
    print_out("     -f group authentication_success (to filter on login success)");
    print_out("     -f level 10 (to filter on level >= 10)");
    print_out("     -f group authentication -r user srcip (to show srcip for all users)");
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0;
    uid_t uid;
    gid_t gid;
    const char *user = USER;
    const char *group = GROUPGLOBAL;

    const char *filter_by = NULL;
    const char *filter_value = NULL;

    const char *related_of = NULL;
    const char *related_values = NULL;
    report_filter r_filter;

    /* Set the name */
    OS_SetName(ARGV0);

    char * home_path = w_homedir(argv[0]);

    r_filter.group = NULL;
    r_filter.rule = NULL;
    r_filter.level = NULL;
    r_filter.location = NULL;
    r_filter.srcip = NULL;
    r_filter.user = NULL;
    r_filter.files = NULL;
    r_filter.show_alerts = 0;

    r_filter.related_group = 0;
    r_filter.related_rule = 0;
    r_filter.related_level = 0;
    r_filter.related_location = 0;
    r_filter.related_srcip = 0;
    r_filter.related_user = 0;
    r_filter.related_file = 0;

    r_filter.report_type = 0;
    r_filter.report_name = NULL;

    while ((c = getopt(argc, argv, "Vdhstu:g:D:f:v:n:r:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_reportd(home_path);
                break;
            case 'd':
                nowDebug();
                break;
            case 'n':
                if (!optarg) {
                    merror_exit("-n needs an argument");
                }
                r_filter.report_name = optarg;
                break;
            case 'r':
                if (!optarg || !argv[optind]) {
                    merror_exit("-r needs two argument");
                }
                related_of = optarg;
                related_values = argv[optind];

                if (os_report_configfilter(related_of, related_values,
                                           &r_filter, REPORT_RELATED)) {
                    merror_exit(CONFIG_ERROR, "user argument");
                }
                optind++;
                break;
            case 'f':
                if (!optarg) {
                    merror_exit("-f needs two argument");
                }
                filter_by = optarg;
                filter_value = argv[optind];

                if (os_report_configfilter(filter_by, filter_value,
                                           &r_filter, REPORT_FILTER)) {
                    merror_exit(CONFIG_ERROR, "user argument");
                }
                optind++;
                break;
            case 'u':
                if (!optarg) {
                    merror_exit("-u needs an argument");
                }
                user = optarg;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument");
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    merror_exit("-D needs an argument");
                }
                os_free(home_path);
                os_strdup(optarg, home_path);
                break;
            case 't':
                test_config = 1;
                break;
            case 's':
                r_filter.show_alerts = 1;
                break;
            default:
                help_reportd(home_path);
                break;
        }

    }

    mdebug1(WAZUH_HOMEDIR, home_path);

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }
    nowChroot();

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    mdebug1(PRIVSEP_MSG, home_path, user);

    os_free(home_path);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* The real stuff now */
    os_ReportdStart(&r_filter);

    exit(0);
}
