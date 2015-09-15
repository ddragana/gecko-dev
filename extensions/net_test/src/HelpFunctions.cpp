/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "HelpFunctions.h"
#include "prerror.h"
#include "prmem.h"
#include "nsString.h"
#include "prlog.h"

namespace NetworkPath {
extern PRLogModuleInfo* gClientTestLog;
#define LOG(args) PR_LOG(gClientTestLog, PR_LOG_DEBUG, args)

nsresult
ErrorAccordingToNSPR(const char *aType)
{
  PRErrorCode errCode = PR_GetError();
  return ErrorAccordingToNSPRWithCode(errCode, aType);
}

nsresult
ErrorAccordingToNSPRWithCode(PRErrorCode errCode, const char *aType)
{
  int errLen = PR_GetErrorTextLength();
  nsAutoCString errStr;
  if (errLen > 0) {
    errStr.SetLength(errLen);
    PR_GetErrorText(errStr.BeginWriting());
  }
  LOG(("NetworkTest %s client: Error: %x %s, %x", aType, errCode,
       errStr.BeginWriting(), PR_GetOSError()));

  nsresult rv = NS_ERROR_FAILURE;
  switch (errCode) {
    case PR_WOULD_BLOCK_ERROR:
      rv = NS_BASE_STREAM_WOULD_BLOCK;
      break;
    case PR_CONNECT_ABORTED_ERROR:
    case PR_CONNECT_RESET_ERROR:
      rv = NS_ERROR_NET_RESET;
      break;
    case PR_END_OF_FILE_ERROR: // XXX document this correlation
      rv = NS_ERROR_NET_INTERRUPT;
      break;
    case PR_CONNECT_REFUSED_ERROR:
    case PR_NETWORK_UNREACHABLE_ERROR:
    case PR_HOST_UNREACHABLE_ERROR:
    case PR_ADDRESS_NOT_AVAILABLE_ERROR:
    case PR_NO_ACCESS_RIGHTS_ERROR:
      rv = NS_ERROR_CONNECTION_REFUSED;
      break;
    case PR_ADDRESS_NOT_SUPPORTED_ERROR:
      rv = NS_ERROR_SOCKET_ADDRESS_NOT_SUPPORTED;
      break;
    case PR_IO_TIMEOUT_ERROR:
    case PR_CONNECT_TIMEOUT_ERROR:
      rv = NS_ERROR_NET_TIMEOUT;
      break;
    case PR_OUT_OF_MEMORY_ERROR:
    case PR_PROC_DESC_TABLE_FULL_ERROR:
    case PR_SYS_DESC_TABLE_FULL_ERROR:
    case PR_INSUFFICIENT_RESOURCES_ERROR:
      rv = NS_ERROR_OUT_OF_MEMORY;
      break;
    case PR_ADDRESS_IN_USE_ERROR:
      rv = NS_ERROR_SOCKET_ADDRESS_IN_USE;
      break;
    case PR_FILE_NOT_FOUND_ERROR:
      rv = NS_ERROR_FILE_NOT_FOUND;
      break;
    case PR_IS_DIRECTORY_ERROR:
      rv = NS_ERROR_FILE_IS_DIRECTORY;
      break;
    case PR_LOOP_ERROR:
      rv = NS_ERROR_FILE_UNRESOLVABLE_SYMLINK;
      break;
    case PR_NAME_TOO_LONG_ERROR:
      rv = NS_ERROR_FILE_NAME_TOO_LONG;
      break;
    case PR_NO_DEVICE_SPACE_ERROR:
      rv = NS_ERROR_FILE_NO_DEVICE_SPACE;
      break;
    case PR_NOT_DIRECTORY_ERROR:
      rv = NS_ERROR_FILE_NOT_DIRECTORY;
      break;
    case PR_READ_ONLY_FILESYSTEM_ERROR:
      rv = NS_ERROR_FILE_READ_ONLY;
      break;
    default:
      break;
  }
  return rv;
}

int
LogErrorWithCode(PRErrorCode errCode, const char *aType)
{
  int errLen = PR_GetErrorTextLength();
  char *errStr = (char*)PR_MALLOC(errLen);
  if (errLen > 0) {
    PR_GetErrorText(errStr);
  }
  LOG(("NetworkTest %s server side:  error %x %s, %x", aType, errCode, errStr,
       PR_GetOSError()));
  delete [] errStr;
  return errCode;
}

int
LogError(const char *aType)
{
  PRErrorCode errCode = PR_GetError();
  return LogErrorWithCode(errCode, aType);
}

} // namespace NetworkPath

