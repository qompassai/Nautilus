/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "dbd.h"

#ifndef ARGV0
#define ARGV0 "wazuh-dbd"
#endif

/* Prototypes */
static void print_db_info(void);
static void cleanup();
static void handler(int signum);
static void help_dbd(char *home_path) __attribute__((noreturn));

/* Print information regarding enabled databases */
static void print_db_info()
{
#ifdef MYSQL_DATABASE_ENABLED
    print_out("    Compiled with MySQL support");
#endif

#ifdef PGSQL_DATABASE_ENABLED
    print_out("    Compiled with PostgreSQL support");
#endif

#if !defined(MYSQL_DATABASE_ENABLED) && !defined(PGSQL_DATABASE_ENABLED)
    print_out("    Compiled without any database support");
#endif
}

/* Print help statement */
static void help_dbd(char *home_path)
{
    print_header();
    print_out("  %s: -[Vhdtfv] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", OSSECCONF);
    print_out("    -D <dir>    Directory to chroot and chdir into (default: %s)", home_path);
    print_out(" ");
    print_out("  Database Support:");
    print_db_info();
    print_out(" ");
    os_free(home_path);
    exit(1);
}

int main (int argc, char **argv) {
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    unsigned int d;

    /* Use USER (read only) */
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = OSSECCONF;
    char *home_path = w_homedir(argv[0]);

    /* Database Structure */
    DBConfig db_config;
    db_config.error_count = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_dbd(home_path);
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
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
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_dbd(home_path);
                break;
        }
    }

    /* Change working directory */
    if (chdir(home_path) == -1) {
        merror(CHDIR_ERROR, home_path, errno, strerror(errno));
        os_free(home_path);
        exit(1);
    }

    /* Setup random */
    srandom_init();

    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, user, group, strerror(errno), errno);
    }

    /* Read configuration */
    if ((c = OS_ReadDBConf(test_config, cfg, &db_config)) < 0) {
        merror_exit(CONFIG_ERROR, OSSECCONF);
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    if (!run_foreground) {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }

    // Signal manipulation
    {
        struct sigaction action = { .sa_handler = handler, .sa_flags = SA_RESTART };
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);

        action.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &action, NULL);
    }

    atexit(cleanup);

    /* Create pid */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    /* Not configured */
    if (c == 0) {
        minfo("Database not configured. Clean exit.");
        exit(0);
    }

    /* Maybe disable this debug? */
    mdebug1("Connecting to '%s', using '%s', '%s', '%s', %d,'%s'.",
           db_config.host, db_config.user,
           db_config.pass, db_config.db, db_config.port, db_config.sock);

    /* Set config pointer */
    osdb_setconfig(&db_config);

    /* Get maximum reconnect attempts */
    db_config.maxreconnect = (unsigned int) getDefine_Int("dbd",
                             "reconnect_attempts", 1, 9999);

    /* Connect to the database */
    d = 0;
    while (d <= (db_config.maxreconnect * 10)) {
        db_config.conn = osdb_connect(db_config.host, db_config.user,
                                      db_config.pass, db_config.db,
                                      db_config.port, db_config.sock);

        /* If we are able to reconnect, keep going */
        if (db_config.conn) {
            break;
        }

        d++;
        sleep(d * 60);
    }

    /* If after the maxreconnect attempts, it still didn't work, exit here */
    if (!db_config.conn) {
        merror(DB_CONFIGERR);
        merror_exit(CONFIG_ERROR, OSSECCONF);
    }

    /* We must notify that we connected -- easy debugging */
    minfo("Connected to database '%s' at '%s'.",
            db_config.db, db_config.host);

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Create location hash */
    db_config.location_hash = OSHash_Create();
    if (!db_config.location_hash) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(home_path) < 0) {
        merror_exit(CHROOT_ERROR, home_path, errno, strerror(errno));
    }

    /* Now in chroot */
    nowChroot();

    /* Insert server info into the db */
    db_config.server_id = OS_Server_ReadInsertDB(&db_config);
    if (db_config.server_id <= 0) {
        merror_exit(CONFIG_ERROR, OSSECCONF);
    }

    /* Read rules and insert into the db */
    if (OS_InsertRulesDB(&db_config) < 0) {
        merror_exit(CONFIG_ERROR, OSSECCONF);
    }

    /* Change user */
    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    /* Basic start up completed */
    mdebug1(PRIVSEP_MSG, home_path, user);
    os_free(home_path);

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* The real daemon now */
    OS_DBD(&db_config);

    return (0);
}

void cleanup() {
    DeletePID(ARGV0);
}

void handler(int signum) {
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        minfo(SIGNAL_RECV, signum, strsignal(signum));
        exit(EXIT_SUCCESS);
    default:
        merror("unknown signal (%d)", signum);
    }
}
