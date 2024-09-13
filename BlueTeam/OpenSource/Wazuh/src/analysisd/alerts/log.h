/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic logging operations */

#ifndef LOG_H
#define LOG_H

#include "eventinfo.h"

#define FWDROP "drop"
#define FWALLOW "accept"

void OS_Log(Eventinfo *lf, FILE * fp);
void OS_CustomLog(const Eventinfo *lf, const char *format);
void OS_Store(const Eventinfo *lf);
void OS_Log_Flush();
void OS_CustomLog_Flush();
void OS_Store_Flush();
int FW_Log(Eventinfo *lf);

#endif /* LOG_H */
