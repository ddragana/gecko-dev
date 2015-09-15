/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef HELPFUNCTIONS_CLIENT_SIDE_H__
#define HELPFUNCTIONS_CLIENT_SIDE_H__

#include "nsError.h"
#include "prerror.h"
#include "nsString.h"

namespace NetworkPath {

nsresult ErrorAccordingToNSPR(const char *aType);
nsresult ErrorAccordingToNSPRWithCode(PRErrorCode errCode, const char *aType);

int LogErrorWithCode(PRErrorCode errCode, const char *aType);
int LogError(const char *aType);
} // namespace NetworkPath
#endif
