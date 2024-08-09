/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2022, Wazuh Inc.
 *
 * December, 2022.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _agent (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT,
    register_ip TEXT,
    internal_key TEXT,
    os_name TEXT,
    os_version TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_codename TEXT,
    os_build TEXT,
    os_platform TEXT,
    os_uname TEXT,
    os_arch TEXT,
    version TEXT,
    config_sum TEXT,
    merged_sum TEXT,
    manager_host TEXT,
    node_name TEXT DEFAULT 'unknown',
    date_add INTEGER NOT NULL,
    last_keepalive INTEGER,
    `group` TEXT DEFAULT 'default',
    group_hash TEXT default NULL,
    group_sync_status TEXT NOT NULL CHECK (group_sync_status IN ('synced', 'syncreq')) DEFAULT 'synced',
    sync_status TEXT NOT NULL CHECK (sync_status IN ('synced', 'syncreq')) DEFAULT 'synced',
    connection_status TEXT NOT NULL CHECK (connection_status IN ('pending', 'never_connected', 'active', 'disconnected')) DEFAULT 'never_connected',
    disconnection_time INTEGER DEFAULT 0,
    group_config_status TEXT NOT NULL CHECK (group_config_status IN ('synced', 'not synced')) DEFAULT 'not synced',
    status_code INTEGER DEFAULT 0
);

BEGIN;

INSERT INTO _agent (id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add, last_keepalive, `group`, sync_status, connection_status) SELECT id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, date_add, last_keepalive, `group`, sync_status, connection_status FROM agent;

END;

DROP TABLE IF EXISTS agent;
ALTER TABLE _agent RENAME TO agent;
CREATE INDEX IF NOT EXISTS agent_name ON agent (name);
CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip);
CREATE INDEX IF NOT EXISTS agent_group_hash ON agent (group_hash);

UPDATE metadata SET value = '5' where key = 'db_version';
