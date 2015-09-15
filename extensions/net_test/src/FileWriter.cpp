/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "FileWriter.h"
#include "HelpFunctions.h"
#include "nsCOMPtr.h"
#include "nsDirectoryServiceUtils.h"
#include <cstring>
#include <stdio.h>

namespace NetworkPath {
extern PRLogModuleInfo* gClientTestLog;
#define LOG(args) PR_LOG(gClientTestLog, PR_LOG_DEBUG, args)

class AutoLock
{
public:
  AutoLock(PRLock *aLock)
  {
    mLock = aLock;
    PR_Lock(mLock);
  }
  ~AutoLock()
  {
    PR_Unlock(mLock);
  } 

private:
  PRLock * mLock;
};

static void PR_CALLBACK
FileWriteRun(void *_writer)
{
  FileWriter *writer = (FileWriter*)_writer;
  while (true) {
    AutoLock lock(writer->mLock);
    while (!writer->Finished() && (writer->mToWrite == 0)) {
      PR_WaitCondVar(writer->mBufReadCondVar, PR_INTERVAL_NO_TIMEOUT);
    }

    //  Write into the file what is in the buffer and terminate.
    if (writer->Finished() && (writer->mToWrite == 0)) {
      return;
    }

    int written = writer->WriteData();
    if (written < 0) {
      PRErrorCode code = PR_GetError();
      if (code == PR_WOULD_BLOCK_ERROR) {
        continue;
      }
      LogErrorWithCode(code, "");
      PR_Close(writer->mFd);
      writer->mFd = nullptr;
      break;
    }

    PR_NotifyCondVar(writer->mBufWriteCondVar);
  }
}

FileWriter::FileWriter()
  : mToWrite(0)
  , mFd(nullptr)
  , mIOLimit(false)
  , mFinished(false)
  , mFileWriterThread(nullptr)

{
  mLock = PR_NewLock();
  mBufReadCondVar = PR_NewCondVar(mLock);
  mBufWriteCondVar = PR_NewCondVar(mLock);
}

nsresult
FileWriter::Init(nsCString aFileName)
{
  mToWrite = 0;
  mIOLimit = false;
  mFinished = false;

  nsCOMPtr<nsIFile> tmpFile;
  nsresult rv = NS_GetSpecialDirectory("TmpD", getter_AddRefs(tmpFile));

  rv = tmpFile->AppendNative(NS_LITERAL_CSTRING("network_tests"));
  if (NS_FAILED(rv)) {
    return rv;
  }
  rv = tmpFile->Create(nsIFile::DIRECTORY_TYPE, 0777);
  if (rv != NS_ERROR_FILE_ALREADY_EXISTS && NS_FAILED(rv)) {
    return rv;
  }

  rv = tmpFile->AppendNative(aFileName);
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = tmpFile->CreateUnique(nsIFile::NORMAL_FILE_TYPE, 0666);
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = tmpFile->OpenNSPRFileDesc(PR_RDWR,
                                 PR_IRWXU, &mFd);
  if (NS_FAILED(rv)) {
    return rv;
  }

  mFileWriterThread = PR_CreateThread(PR_USER_THREAD, FileWriteRun,
                                      (void *)this, PR_PRIORITY_NORMAL,
                                      PR_LOCAL_THREAD,PR_JOINABLE_THREAD, 0);
  if (!mFileWriterThread) {
    LOG(("NetworkTest client side: Error creating writer thread"));
    LogError("FileWriter");
    PR_Close(mFd);
    mFd = nullptr;
    return NS_ERROR_FAILURE;
  }
  return NS_OK;
}

FileWriter::~FileWriter()
{
  LOG(("NetworkTest client side - destroy writer"));
  Done();

  if (mFd) {
    PR_Close(mFd);
  }

  PR_DestroyCondVar(mBufReadCondVar);
  PR_DestroyCondVar(mBufWriteCondVar);
  PR_DestroyLock(mLock);
}

void
FileWriter::WriteNonBlocking(char* buf, int size)
{
  AutoLock lock(mLock);

  if (!mFd && !mFinished) {
    return;
  }

  if ((mToWrite + size) <= BUF_SIZE) {
    memcpy(mBuf + mToWrite, buf, size);
    mToWrite += size;
    if (mToWrite == size) {
      PR_NotifyCondVar(mBufReadCondVar);
    }
  } else {
    mIOLimit = true;
  }
}

// This is use for results transfer.
void
FileWriter::WriteBlocking(char* buf, int size)
{
  AutoLock lock(mLock);

  if (!mFd && !mFinished) {
    return;
  }

  while ((mToWrite + size) > BUF_SIZE) {
    PR_WaitCondVar(mBufWriteCondVar, PR_INTERVAL_NO_TIMEOUT);
  }
  memcpy(mBuf + mToWrite, buf, size);
  mToWrite += size;
  if (mToWrite == size) {
    PR_NotifyCondVar(mBufReadCondVar);
  }
}

int
FileWriter::WriteData()
{
  int written = PR_Write(mFd, mBuf, mToWrite);
  if (written > 0) {
    memmove(mBuf, mBuf + written, mToWrite - written);
    mToWrite -= written;

    if (mIOLimit) {
      memcpy(mBuf + mToWrite, "IO LIMIT\n",
             ((BUF_SIZE - mToWrite) > sizeof("IO LOMIT\n") ?
             sizeof("IO LOMIT\n") : (BUF_SIZE - mToWrite)));
    }
  }
  return written;
}

void
FileWriter::Done()
{
  {
    AutoLock lock(mLock);
    if (mFinished) {
      return;
    }

    mFinished = true;
    PR_NotifyCondVar(mBufReadCondVar);
  }

  if (mFileWriterThread) {
    LOG(("NetworkTest client side - destroy writer thread   "));
    PR_JoinThread(mFileWriterThread);

    mFileWriterThread = nullptr;
  }
}

} // namespace NetworkPath
