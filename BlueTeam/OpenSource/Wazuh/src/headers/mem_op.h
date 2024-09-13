/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MEM_H
#define MEM_H

#include <stdlib.h>

#ifdef WIN32
#define win_alloc(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define win_free(x) HeapFree(GetProcessHeap(), 0, (x))
#endif

#define w_FreeArray(x) if (x) {char **x_it = x; for (; *x_it; (x_it)++) {os_free(*x_it);}}
#define w_FreeDoubleArray(y) if (y) {char ***y_it = y; for (; *y_it; (y_it)++) {w_FreeArray(*y_it); os_free(*y_it);}}
void **os_AddPtArray(void *pt, void **array);
char **os_AddStrArray(const char *str, char **array);
void   os_FreeArray(char *ch1, char **ch2);
int    os_IsStrOnArray(const char *str, char **array);
char  *os_LoadString(char *at, const char *str) __attribute__((nonnull(2)));
void  *memset_secure(void *v, int c, size_t n) __attribute__((nonnull));

#endif /* MEM_H */
