/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sddl_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

WINBOOL wrap_ConvertSidToStringSid(__UNUSED_PARAM(PSID Sid),
                                   LPSTR *StringSid) {
    *StringSid = mock_type(LPSTR);
    return mock();
}

void expect_ConvertSidToStringSid_call(LPSTR StringSid, int ret_value) {
    will_return(wrap_ConvertSidToStringSid, StringSid);
    will_return(wrap_ConvertSidToStringSid, ret_value);
}
