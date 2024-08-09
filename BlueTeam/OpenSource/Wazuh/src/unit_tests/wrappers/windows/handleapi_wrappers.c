/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "handleapi_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

WINBOOL wrap_CloseHandle(HANDLE hObject) {
    check_expected(hObject);
    return mock();
}

void expect_CloseHandle_call(HANDLE object, int ret) {
    expect_value(wrap_CloseHandle, hObject, object);
    will_return(wrap_CloseHandle, ret);
}
