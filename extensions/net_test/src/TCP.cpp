/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "TCP.h"
#include "prerror.h"
#include "prrng.h"
#include "nsIInputStream.h"
#include "nsIFileStreams.h"
#include "nsNetUtil.h"

namespace NetworkPath {

extern PRLogModuleInfo* gClientTestLog;
#define LOG(args) PR_LOG(gClientTestLog, PR_LOG_DEBUG, args)

// after this short interval, we will return to PR_Poll
#define NS_SOCKET_CONNECT_TIMEOUT PR_MillisecondsToInterval(400)
#define SNDBUFFERSIZE 12582912

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

TCP::TCP(PRNetAddr *aNetAddr)
  : mFd(nullptr)
{
  memcpy(&mNetAddr, aNetAddr, sizeof(PRNetAddr));
}

TCP::~TCP()
{
  if (mFd) {
    PR_Close(mFd);
  }
}

nsresult
TCP::Start(int aTestType, nsCString aFileName)
{
  mTestType = aTestType;
  nsresult rv = Init();
  if (NS_FAILED(rv)) {
    if(mFd) {
      PR_Close(mFd);
      mFd = nullptr;
    }
    return rv;
  }

  if (aTestType == 3) {
    mLogFileName = aFileName;
    //  We collect data on the receiver side
    nsresult rv = mLogFile.Init(mLogFileName);
    if (NS_FAILED(rv)) {
      if (mFd) {
        PR_Close(mFd);
        mFd = nullptr;
      }
    }
    LogLogFormat();
  } else if (aTestType == 4) {
    mLogFileName = aFileName;
  }

  rv = Run();
  if (NS_FAILED(rv)) {
    if(mFd) {
      PR_Close(mFd);
      mFd = nullptr;
    }
  }
  mLogFile.Done();
  return rv;
}

nsresult
TCP::Init()
{
  LOG(("NetworkTest TCP client: Open socket"));
  char host[164] = {0};
  PR_NetAddrToString(&mNetAddr, host, sizeof(host));
  LOG(("NetworkTest TCP client: Host: %s", host));
  LOG(("NetworkTest TCP client: AF: %d", mNetAddr.raw.family));
  int port = 0;
  if (mNetAddr.raw.family == AF_INET) {
    port = mNetAddr.inet.port;
  } else if (mNetAddr.raw.family == AF_INET6) {
    port = mNetAddr.ipv6.port;
  }
  LOG(("NetworkTest TCP client: port: %d", ntohs(port)));

  mFd = PR_OpenTCPSocket(mNetAddr.raw.family);
  if (!mFd) {
    return ErrorAccordingToNSPR("TCP");
  }

  LOG(("NetworkTest TCP client: Set Options"));
  PRStatus status;
  PRSocketOptionData opt;
  opt.option = PR_SockOpt_Nonblocking;
  opt.value.non_blocking = true;
  status = PR_SetSocketOption(mFd, &opt);
  if (status != PR_SUCCESS) {
    PR_Close(mFd);
    mFd = nullptr;
    return ErrorAccordingToNSPR("TCP");
  }

  opt.option = PR_SockOpt_NoDelay;
  opt.value.no_delay = true;
  status = PR_SetSocketOption(mFd, &opt);
  if (status != PR_SUCCESS) {
    PR_Close(mFd);
    mFd = nullptr;
    return ErrorAccordingToNSPR("TCP");
  }

  opt.option = PR_SockOpt_SendBufferSize;
  opt.value.send_buffer_size = SNDBUFFERSIZE;
  PR_SetSocketOption(mFd, &opt);
  if (status != PR_SUCCESS) {
    PR_Close(mFd);
    mFd = nullptr;
    return ErrorAccordingToNSPR("TCP");
  }

  LOG(("NetworkTest TCP client: Connect..."));
  status = PR_Connect(mFd, &mNetAddr, NS_SOCKET_CONNECT_TIMEOUT);
  if (status != PR_SUCCESS) {
    PRErrorCode errCode = PR_GetError();
    if (PR_IS_CONNECTED_ERROR == errCode) {
      LOG(("NetworkTest TCP client: It is connected"));
      return NS_OK;
    } else if ((PR_WOULD_BLOCK_ERROR == errCode) ||
               (PR_IN_PROGRESS_ERROR == errCode) ||
               (PR_ALREADY_INITIATED_ERROR  == errCode)) {
      PRPollDesc pollElem;
      pollElem.fd = mFd;
      pollElem.in_flags = PR_POLL_WRITE | PR_POLL_EXCEPT;
      LOG(("NetworkTest TCP client: Poll for a connection."));
      while (1) {
        pollElem.out_flags = 0;
        PR_Poll(&pollElem, 1, PR_INTERVAL_NO_WAIT);
        if ( pollElem.out_flags & PR_POLL_WRITE ) {
          LOG(("NetworkTest TCP client: Connected."));
          return NS_OK;
        } else if (pollElem.out_flags &
                   (PR_POLL_ERR | PR_POLL_HUP | PR_POLL_NVAL)) {
          errCode = PR_GetError();
          if ((PR_WOULD_BLOCK_ERROR == errCode) ||
               (PR_IN_PROGRESS_ERROR == errCode)) {
            continue;
          }
          LOG(("NetworkTest TCP client: Could not connect."));
          PR_Close(mFd);
          mFd = nullptr;
          return ErrorAccordingToNSPR("TCP");
        }
      }
    }
    PR_Close(mFd);
    mFd = nullptr;
    return ErrorAccordingToNSPRWithCode(errCode, "TCP");
  }
  return NS_OK;
}

nsresult
TCP::Run()
{
  PRPollDesc pollElem;
  pollElem.fd = mFd;
  pollElem.in_flags = PR_POLL_WRITE | PR_POLL_EXCEPT;
  uint64_t readBytes = 0;
  uint64_t writtenBytes = 0;
  uint64_t recvBytesForRate = 0;
  PRIntervalTime timeFirstPktReceived = 0;
  PRIntervalTime startRateCalc = 0;
  uint16_t bufLen = PAYLOADSIZE;
  char buf[bufLen];
  PR_GetRandomNoise(&buf, sizeof(buf));
  switch (mTestType) {
    case 2:
      memcpy(buf + TCP_TYPE_START, TCP_reachability, TCP_TYPE_LEN);
      break;
    case 3:
      memcpy(buf + TCP_TYPE_START, TCP_performanceFromServerToClient,
             TCP_TYPE_LEN);
      break;
    case 4:
      memcpy(buf + TCP_TYPE_START, TCP_performanceFromClientToServer,
             TCP_TYPE_LEN);
      memcpy(buf + TCP_FILE_NAME_START, mLogFileName.get(), FILE_NAME_LEN);
      break;
    default:
      PR_Close(mFd);
      mFd = nullptr;
      return NS_ERROR_FAILURE;
  }

  LOG(("NetworkTest TCP client: Poll"));
  while (1) {
    pollElem.out_flags = 0;
    int rv = PR_Poll(&pollElem, 1, 10000);
    if (rv < 0) {
      LOG(("NetworkTest TCP client: Poll error: read bytes %lu", readBytes));
      PR_Close(mFd);
      mFd = nullptr;
      return ErrorAccordingToNSPR("TCP");
    } else if (rv == 0) {
      LOG(("NetworkTest TCP client: Closing, timeout: read bytes %lu",
           readBytes));
      PR_Close(mFd);
      mFd = nullptr;
      return ErrorAccordingToNSPR("TCP");
    }
    if (pollElem.out_flags & (PR_POLL_ERR | PR_POLL_HUP | PR_POLL_NVAL)) {
      PRErrorCode errCode = PR_GetError();
      LOG(("NetworkTest TCP client: Connection error. read bytes %lu",
           readBytes));
      if (!(pollElem.out_flags & PR_POLL_NVAL)) {
        PR_Close(mFd);
        mFd = nullptr;
      }
      return ErrorAccordingToNSPRWithCode(errCode, "TCP");
    }

    if (pollElem.out_flags & PR_POLL_WRITE) {
      //LOG(("NetworkTest TCP client: Sending data for test %d.", mTestType));

      int written = 0;
      if (writtenBytes < bufLen) {
        // The first packet must be sent as it is so that server can read
        // exact positions in the buffer. Actually only the first bytes are
        // important, but we are sending it complete.
        written = PR_Write(mFd, buf + writtenBytes,
                           bufLen - writtenBytes);
        if (mTestType == 3) {
          sprintf(mLogstr, "%lu START TEST 3 %lu\n",
                  (unsigned long)PR_IntervalToMilliseconds(PR_IntervalNow()),
                  (unsigned long)written);
          mLogFile.WriteBlocking(mLogstr, strlen(mLogstr));
        }
      } else {
        written = PR_Write(mFd, buf, bufLen);
      }

      if (written < 0) {
        PRErrorCode code = PR_GetError();
        if (code == PR_WOULD_BLOCK_ERROR) {
          continue;
        }
        PR_Close(mFd);
        mFd = nullptr;
        return ErrorAccordingToNSPRWithCode(code, "TCP");
      }

      writtenBytes += written;

      if (writtenBytes >= bufLen) {
        if (mTestType == 2 || mTestType == 3) {
          // Test 2 and 3 are waiting for data from the server.
          pollElem.in_flags = PR_POLL_READ | PR_POLL_EXCEPT;
        } else if (mTestType == 4) {
          // Test 4 is sending data, until it receives FINISH packet.
          pollElem.in_flags = PR_POLL_READ | PR_POLL_WRITE | PR_POLL_EXCEPT;
        }
      }
    }
    if (pollElem.out_flags & PR_POLL_READ) {
      int read = 0;
      if (mTestType == 3) {
        read = PR_Read(mFd, buf, bufLen);
      } else {
        read = PR_Read(mFd, buf + readBytes, bufLen - readBytes);
      }
      if (read < 1) {
        PRErrorCode code = PR_GetError();
        if (code == PR_WOULD_BLOCK_ERROR) {
          continue;
        }
        PR_Close(mFd);
        mFd = nullptr;
        return ErrorAccordingToNSPR("TCP");
      }
      readBytes += read;

      if (!timeFirstPktReceived) {
        timeFirstPktReceived = PR_IntervalNow();
      }
      switch (mTestType) {
        case 2:
          if (readBytes >= bufLen) {
            LOG(("NetworkTest TCP client: Closing: read enough bytes - %lu",
                 readBytes));
            PR_Close(mFd);
            mFd = nullptr;
            return NS_OK;
          }
        case 3:
          // Log data.
          sprintf(mLogstr, "%lu RECV %lu\n",
                  (unsigned long)PR_IntervalToMilliseconds(PR_IntervalNow()),
                  (unsigned long)read);
          mLogFile.WriteNonBlocking(mLogstr, strlen(mLogstr));

          if (PR_IntervalToSeconds(PR_IntervalNow() - timeFirstPktReceived) >=
              2) {
            recvBytesForRate += read;
            if (!startRateCalc) {
              startRateCalc = PR_IntervalNow();
            }
          }

          // Check whether we have received enough data.
          if ((readBytes >= MAXBYTES) &&
              (PR_IntervalToSeconds(PR_IntervalNow() - timeFirstPktReceived)
               >= MAXTIME)) {

            if (PR_IntervalToSeconds(PR_IntervalNow() - startRateCalc)) {
              mPktPerSec = (double)recvBytesForRate / PAYLOADSIZEF /
                (double)PR_IntervalToMilliseconds(PR_IntervalNow() - startRateCalc) *
                1000.0;
            }
            LOG(("NetworkTest TCP client: Closing, observed rate: %llu",
                 mPktPerSec));
            LOG(("Test 3 finished: time %lu, first packet sent %lu, "
                 "duration %lu, received %llu max to received %llu, received "
                 "bytes for rate calc %llu, duration for calc %lu",
                 PR_IntervalNow(),
                 timeFirstPktReceived,
                 PR_IntervalToMilliseconds(PR_IntervalNow() - timeFirstPktReceived),
                 readBytes, MAXBYTES, recvBytesForRate,
                 PR_IntervalNow() - startRateCalc));

            // Log data.
            sprintf(mLogstr, "%lu FINISH\n",
                    (unsigned long)PR_IntervalToMilliseconds(PR_IntervalNow()));
            mLogFile.WriteBlocking(mLogstr, strlen(mLogstr));

            PR_Close(mFd);
            mFd = nullptr;
            mLogFile.Done();
            return NS_OK;
          }
          break;
        case 4:
          if (readBytes >= bufLen) {
            LOG(("NetworkTest TCP client: Closing: read enough bytes - %lu",
                 readBytes));
            uint64_t rate;
            PR_STATIC_ASSERT(sizeof(rate) == 8);
            memcpy(&rate, buf, sizeof(rate));
            mPktPerSec = ntohll(rate);
            PR_Close(mFd);
            mFd = nullptr;
            return NS_OK;
          }
      }
    }
  }
  PR_Close(mFd);
  mFd = nullptr;
  return NS_OK;
}

void
TCP::LogLogFormat()
{
  char line1[] = "Data pkt has been recevied: [timestamp pkt received] RECV [bytes received]\n";
  mLogFile.WriteBlocking(line1, strlen(line1));

  char line2[] = "The last packet has been sent: [timestamp pkt sent] RECV [bytes sent]\n";
  mLogFile.WriteBlocking(line2, strlen(line2));
}

nsresult
TCP::SendResult(nsCString aFileName)
{
  nsCOMPtr<nsIFile> tmpFile;
  nsresult rv = NS_GetSpecialDirectory("TmpD", getter_AddRefs(tmpFile));

  rv = tmpFile->AppendNative(NS_LITERAL_CSTRING("network_tests"));
  if (NS_FAILED(rv)) {
    return rv;
  }
  rv = tmpFile->Create(nsIFile::DIRECTORY_TYPE, 0700);
  if (rv != NS_ERROR_FILE_ALREADY_EXISTS && NS_FAILED(rv)) {
    return rv;
  }

  rv = tmpFile->AppendNative(aFileName);
  if (NS_FAILED(rv)) {
    return rv;
  }

  int64_t size;
  rv = tmpFile->GetFileSize(&size);
  if (NS_FAILED(rv) || (size <= 0)) {
    return rv;
  }

  nsCOMPtr<nsIInputStream> inputStream;
  rv = NS_NewLocalFileInputStream(getter_AddRefs(inputStream),
                                   tmpFile,
                                   PR_RDONLY, 0600,
                                   nsIFileInputStream::DELETE_ON_CLOSE);
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = Init();
  if (NS_FAILED(rv)) {
    if(mFd) {
      PR_Close(mFd);
      mFd = nullptr;
    }
    inputStream->Close();
    return rv;
  }

  PRPollDesc pollElem;
  pollElem.fd = mFd;
  pollElem.in_flags = PR_POLL_WRITE | PR_POLL_EXCEPT;
  uint16_t bufLen = PAYLOADSIZE;
  char buf[bufLen];
  memcpy(buf + TCP_TYPE_START, SENDRESULTS, TCP_TYPE_LEN);
  memcpy(buf + TCP_FILE_NAME_START, aFileName.get(), TCP_FILE_NAME_LEN);

  uint64_t dataLen = htonll(size);

  memcpy(buf + TCP_DATA_LEN_START, &dataLen, TCP_DATA_LEN_LEN);

  uint32_t readData;
  do {
    rv = inputStream->Read(buf + TCP_DATA_START, bufLen - TCP_DATA_START, &readData);
  } while (NS_FAILED(rv) && rv == NS_BASE_STREAM_WOULD_BLOCK);

  if (NS_FAILED(rv)) {
    // We could retry.
    PR_Close(mFd);
    mFd = nullptr;
    inputStream->Close();
    return NS_ERROR_FAILURE;
  }

  int toWrite = TCP_DATA_START + readData;
  size -= readData;
  LOG(("NetworkTest TCP sending resluts: Poll"));
  while (1) {
    pollElem.out_flags = 0;
    int prrv = PR_Poll(&pollElem, 1, 1000);
    if (prrv < 0) {
      LOG(("NetworkTest TCP sending resluts finished."));
      PR_Close(mFd);
      mFd = nullptr;
      inputStream->Close();
      return ErrorAccordingToNSPR("TCP");
    } else if (prrv == 0) {
      LOG(("NetworkTest TCP sending resluts finished - timeout"));
      PR_Close(mFd);
      mFd = nullptr;
      inputStream->Close();
      return ErrorAccordingToNSPR("TCP");
    }
    if (pollElem.out_flags & (PR_POLL_ERR | PR_POLL_HUP | PR_POLL_NVAL)) {
      PRErrorCode errCode = PR_GetError();
      LOG(("NetworkTest TCP sending resluts finished - Connection error"));
      if (!(pollElem.out_flags & PR_POLL_NVAL)) {
        PR_Close(mFd);
        mFd = nullptr;
      }
      inputStream->Close();
      return ErrorAccordingToNSPRWithCode(errCode, "TCP");
    }

    if (pollElem.out_flags & PR_POLL_WRITE) {
      //LOG(("NetworkTest TCP client: Sending data for test %d.", mTestType));

      if (toWrite  != 0) {
        int written = 0;
        written = PR_Write(mFd, buf, toWrite);

        if (written < 0) {
          PRErrorCode code = PR_GetError();
          if (code == PR_WOULD_BLOCK_ERROR) {
            continue;
          }
          PR_Close(mFd);
          mFd = nullptr;
          inputStream->Close();
          return ErrorAccordingToNSPRWithCode(code, "TCP");
        }

        if (written < toWrite) {
          memmove(buf, buf + written, toWrite - written);
        }
        toWrite -= written;
      }

      if (size) {
        int64_t toRead = (size > bufLen - toWrite) ? bufLen - toWrite
                                                       : size;
        rv = inputStream->Read(buf + toWrite, toRead, &readData);
        if (NS_FAILED(rv)) {
          if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
            continue;
          } else {
            PR_Close(mFd);
            mFd = nullptr;
            inputStream->Close();
            return NS_ERROR_FAILURE;
          }
        }
        size -= readData;
        toWrite += readData;
      }

      if (toWrite <= 0) {
        // wait for server to receive all data.
        pollElem.in_flags = PR_POLL_EXCEPT;
      }
    }
  }
  inputStream->Close();
  return NS_OK;
}

} // namespace NetworkPath
