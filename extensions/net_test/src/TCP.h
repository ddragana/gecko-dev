/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef TEST_TCP_CLIENT_SIDE_H__
#define TEST_TCP_CLIENT_SIDE_H__

#include "prio.h"
#include "FileWriter.h"

namespace NetworkPath {
class TCP
{
public:
  TCP(PRNetAddr *aAddr);
  ~TCP();
  nsresult Start(int aTestType, nsCString aFileName);
  nsresult SendResult(nsCString aFileName);
  uint64_t GetRate() { return mPktPerSec; }
private:
  nsresult Init();
  nsresult Run();
  void LogLogFormat();

  PRNetAddr mNetAddr;
  PRFileDesc *mFd;
  int mTestType;
  uint64_t mPktPerSec;
  FileWriter mLogFile;
  // File name [16 random]_test[test number]_itr[iteration number]
  //char mFileName[FILE_NAME_LEN];
  nsCString mLogFileName;
  char mLogstr[80];
};
} // namespace NetworkPath
#endif
