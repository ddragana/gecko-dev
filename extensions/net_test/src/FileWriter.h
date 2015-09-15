/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef NETWORK_TESTS_FILE_WRITER_H__
#define NETWORK_TESTS_FILE_WRITER_H__

#include "prio.h"
#include "prerror.h"
#include "config.h"
#include "nspr.h"
 #include <atomic>

#define BUF_SIZE 3000

namespace NetworkPath {

class FileWriter
{
public:
  FileWriter();
  ~FileWriter();
  nsresult Init(nsCString aFileName);
  void WriteNonBlocking(char* buf, int size);
  void WriteBlocking(char* buf, int size);
  int ReadData(char* buf, int size);
  int64_t FileSize();
  bool Finished() {return mFinished;};
  void Done();

  int WriteData();

  char mBuf[BUF_SIZE];
  int mToWrite;
  PRFileDesc *mFd;
  PRLock* mLock;
  PRCondVar* mBufReadCondVar;
  PRCondVar* mBufWriteCondVar;
  bool mIOLimit;
  std::atomic<bool> mFinished;
  PRThread *mFileWriterThread;
};

} // namespace NetworkPath
#endif
