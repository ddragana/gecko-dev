/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "UDP.h"
#include "prerror.h"
#include "HelpFunctions.h"
#include <math.h>
#include <cstring>
#include <stdio.h>
#include "prlog.h"
#include "prrng.h"
#include "nsIFile.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

/**
 *  Packet formats are described in the config.h file.
 *
 *  Test 1:
 *   - send a packet that starts with "pkdID,ts,Test_1" (maybe we move this not
 *     to be at the beginning). Wait for an ack. If no ack is received after
 *     RETRANSMISSION_TIMEOUT, send another packet with the same pktID but
 *     a different timestamp.
 *     Ack will have the same size as the packet it is acking
 *     States: START_TEST -> get ack -> WAIT_FINISH_TIMEOUT -> TEST_FINISHED
 *                        -> no ack -> error
 *
 *  Test 5:
 *   - send a packet that starts with "pkdID,ts,Test_5" followed by a 8 bytes
 *     long rate in packets per second mPktPerSec and a file name (zeroended).
 *     If no packet is received after RETRANSMISSION_TIMEOUT send another packet
 *     with the same pktID but a different timestamp.
 *   - If no packet is received from the server after MAX_RETRANSMISSIONS return
 *     NS_ERROR_FAILURE.
 *   - Receive and ack packets coming from the server. If no packet is received
 *     for NOPKTTIMEOUT close the connection and return NS_OK.
 *     States: START_TEST -> get ack -> RUN_TEST
 *                        -> no ack -> error
 *             RUN_TEST -> receiving data ->(received FINISH) -> WAIT_FINISH_TIMEOUT -> TEST_FINISHED
 *                      -> no packets for some time-> error
 *
 *  Test 6:
 *   - send a packet that start with "pkdID,ts,Test_6".
 *     If no packet is received after RETRANSMISSION_TIMEOUT send another packet
 *     with the same pktID but a different timestamp.
 *   - If no packet is received from the server after MAX_RETRANSMISSIONS return
 *     NS_ERROR_FAILURE.
 *   - Send packet at rate mPktPerSec and receive ack. After max(MAXBYTES, MAXTIME)
 *     packets has been sent, stop sending data and wait for another
 *     SHUTDOWNTIMEOUT for incoming acks. Also send a FINISH_PACKET
 *     States: START_TEST -> get ack -> RUN_TEST
 *                        -> no ack -> error
 *             RUN_TEST -> sending data -> (send enough data) -> FINISH_PACKET
 *                      -> no acks for some time -> error
 *             FINISH_PACKET -> received ack (this ack contains observed rate) -> WAIT_FINISH_TIMEOUT -> TEST_FINISHED
 *                           -> no acks for RETRANSMISSION_TIMEOUT retransmit FINISH_PACKET
 *                           -> no acks for MAX_RETRANSMISSIONS -> error
 *
 *
 */

namespace NetworkPath {

extern PRLogModuleInfo* gClientTestLog;
#define LOG(args) PR_LOG(gClientTestLog, PR_LOG_DEBUG, args)

UDP::UDP(PRNetAddr *aAddr)
  : mFd(nullptr)
  , mTestType(0)
  , mLastReceivedTimeout(0)
  , mNextTimeToDoSomething(0)
  , mSentBytes(0)
  , mRecvBytes(0)
  , mNumberOfRetrans(0)
  , mPktPerSec(0)
  , mPktInterval(0)
  , mNextPktId(0)
  , mLastPktId(0)
  , mError(false)
{

  memcpy(&mNetAddr, aAddr, sizeof(PRNetAddr));
  mNodataTimeout = PR_MillisecondsToInterval(NOPKTTIMEOUT);

  PR_GetRandomNoise(&mSendBuf, sizeof(mSendBuf));

}

UDP::~UDP()
{
  if (mFd) {
    PR_Close(mFd);
  }
  mLogFile.Done();
}

nsresult
UDP::Start(int aTestType, uint64_t aRate, nsCString aFileName,
           bool &aSucceeded)
{
  aSucceeded = false;
  mTestType = aTestType;
  mRate = aRate;
  if (mRate) {
    mPktInterval = 1000000000.0 / mRate; // in nanosecond.
    LOG(("NetworkTest UDP client side: Test %d: rate %llu interval %lf.",
         mTestType, mRate, mPktInterval));
  }
  nsresult rv = Init();
  if (NS_FAILED(rv)) {
    if(mFd) {
      PR_Close(mFd);
      mFd = nullptr;
    }
    return rv;
  }

  if (aTestType == 5) {
    mLogFileName = aFileName;
  } else if (aTestType == 6) {
    mLogFileName = aFileName;
    //  We collect data on the sender side
    rv = mLogFile.Init(aFileName);
    if (NS_FAILED(rv)) {
      if (mFd) {
        PR_Close(mFd);
        mFd = nullptr;
      }
      return rv;
    }
    LogLogFormat();
  }

  rv = Run();
  if(mFd) {
    PR_Close(mFd);
    mFd = nullptr;
  }
  mLogFile.Done();
  if (NS_SUCCEEDED(rv) && !mError) {
    aSucceeded = true;
  }
  return rv;
}

nsresult
UDP::Init()
{

  LOG(("NetworkTest UDP client: Open socket"));

  char host[164] = {0};
  PR_NetAddrToString(&mNetAddr, host, sizeof(host));
  LOG(("NetworkTest UDP client: Remote Host: %s", host));

  int port = 0;
  if (mNetAddr.raw.family == AF_INET) {
    port = mNetAddr.inet.port;
  } else if (mNetAddr.raw.family == AF_INET6) {
    port = mNetAddr.ipv6.port;
  }
  LOG(("NetworkTest UDP client: Remote port: %d", ntohs(port)));

  mFd = PR_OpenUDPSocket(mNetAddr.raw.family);
  if (!mFd) {
    return ErrorAccordingToNSPR("UDP");
  }

  LOG(("NetworkTest UDP client: Set Options"));
  PRSocketOptionData opt;
  opt.option = PR_SockOpt_Nonblocking;
  opt.value.non_blocking = true;
  PRStatus status = PR_SetSocketOption(mFd, &opt);
  if (status != PR_SUCCESS) {
    return ErrorAccordingToNSPR("UDP");
  }

  opt.option = PR_SockOpt_Reuseaddr;
  opt.value.reuse_addr = true;
  status = PR_SetSocketOption(mFd, &opt);
  if (status != PR_SUCCESS) {
    LogError("UDP");
    return ErrorAccordingToNSPR("UDP");
  }
  LOG(("NetworkTest UDP client: Socket options set."));

  return NS_OK;
}

nsresult
UDP::Run()
{
  LOG(("NetworkTest UDP client: Run."));

  mRateObserved = 0;
  mLastReceivedTimeout = 0;
  mNextTimeToDoSomething = PR_IntervalNow();
  mSentBytes = mRecvBytes = 0;
  mAcksToSend.clear();
  mNumberOfRetrans = 0;
  mNumberOfRetransFinish = 0;
  mPktPerSec = 0;
  mNextToSendInns = 0;
  memset(mPktIdFirstPkt, 0, sizeof(mPktIdFirstPkt));

  PR_GetRandomNoise(&mNextPktId, sizeof(mNextPktId));
  while (mNextPktId == 0) {
    PR_GetRandomNoise(&mNextPktId, sizeof(mNextPktId));
  }
  mLastPktId = 0;
  mFirstPktSent = 0;
  mFirstPktReceived = 0;
  mError = false;

  PRPollDesc pollElem;
  pollElem.fd = mFd;
  pollElem.in_flags = PR_POLL_READ | PR_POLL_EXCEPT;

  mPhase = START_TEST;

  nsresult rv = NS_OK;
  while (NS_SUCCEEDED(rv)) {

    // See if we need to send something.
    PRIntervalTime now = PR_IntervalNow();
    if (mNextTimeToDoSomething && mNextTimeToDoSomething < now) {
      nsresult rv = NS_OK;
      switch (mPhase) {
        case START_TEST:
          rv = StartTestSend();
          break;
        case RUN_TEST:
          rv = RunTestSend();
          break;
        case FINISH_PACKET:
          rv = SendFinishPacket();
          break;
        case WAIT_FINISH_TIMEOUT:
          rv = WaitForFinishTimeout();
          break;
        case TEST_FINISHED:
          break;
      }
      if (NS_FAILED(rv)) {
        continue;
      }
    }

    if (mLastReceivedTimeout && mLastReceivedTimeout < now) {
      LOG(("NetworkTest UDP client: Last received timed out."));
      rv = NoDataForTooLong();
    }

    if (mPhase == TEST_FINISHED) {
      LOG(("NetworkTest UDP client: Test finished."));
      mFd = nullptr;
      mLogFile.Done();
      return NS_OK;
    }

    SendAcks();

    // See if we got something.
    pollElem.out_flags = 0;
    PR_Poll(&pollElem, 1, PR_INTERVAL_NO_WAIT);
    if (pollElem.out_flags & (PR_POLL_ERR | PR_POLL_HUP | PR_POLL_NVAL))
    {
      LOG(("NetworkTest UDP client: Closing: read bytes %lu send bytes %lu",
           mSentBytes, mRecvBytes));
      rv = NS_ERROR_FAILURE;
      continue;
    }

    if (pollElem.out_flags & PR_POLL_READ) {
      PRNetAddr prAddr;
      int32_t count;
      count = PR_RecvFrom(mFd, mRecvBuf, sizeof(mRecvBuf), 0, &prAddr,
                          PR_INTERVAL_NO_WAIT);

      if (count < 0) {
        PRErrorCode code = PR_GetError();
        if (code == PR_WOULD_BLOCK_ERROR) {
          continue;
        }
        rv = ErrorAccordingToNSPRWithCode(code, "UDP");
        continue;
      }
      rv = NewPkt(count, mRecvBuf);
    }
  }

  PR_Close(mFd);
  mFd = nullptr;
  mLogFile.Done();
  return rv;
}

nsresult
UDP::StartTestSend()
{
  LOG(("NetworkTest UDP client: retransmissions: %d", mNumberOfRetrans));
  if (mNumberOfRetrans > MAX_RETRANSMISSIONS) {
    mError = true;
    mPhase = PHASE::TEST_FINISHED;
    return NS_OK;
  }

  // Send a packet.
  PRIntervalTime now = PR_IntervalNow();
  FormatStartPkt(PR_IntervalToMilliseconds(now));

  if (mTestType == 6) {
    sprintf(mLogstr, "%lu START TEST 6\n",
            (unsigned long)PR_IntervalToMilliseconds(now));
    mLogFile.WriteBlocking(mLogstr, strlen(mLogstr));
  }
  int payloadsize = PAYLOADSIZE - (200 * mNumberOfRetrans);
  if (payloadsize < 512) {
    payloadsize = 512;
  }
  int count = PR_SendTo(mFd, mSendBuf, payloadsize, 0, &mNetAddr,
                        PR_INTERVAL_NO_WAIT);

  // Overwrite buffer. It would be enough to overwrite "Test_#nb" because if
  // this is present receiver will think that the test is starting again.
  PR_GetRandomNoise(&mSendBuf, sizeof(mSendBuf));

  if (count < 1) {
    PRErrorCode code = PR_GetError();
    if (code == PR_WOULD_BLOCK_ERROR) {
      return NS_OK;
    }
    return ErrorAccordingToNSPRWithCode(code, "UDP");
  }

  LOG(("NetworkTest UDP client: Sent a start packet for test %d.", mTestType));

  mNextTimeToDoSomething = now +
                           PR_MillisecondsToInterval(RETRANSMISSION_TIMEOUT);
  mNumberOfRetrans++;

  return NS_OK;
}

nsresult
UDP::RunTestSend()
{
  PRIntervalTime now;
  switch (mTestType) {
    case 1:
    case 5:
      return NS_ERROR_UNEXPECTED;
    case 6:
      // Here we are sending data from the client to the server until we have
      // sent MAXBYTES or MAXTIME has expired. When test is finished we wait
      // SHUTDOWNTIMEOUT for outstanding acks to be received.
      {
        now = PR_IntervalNow();
        while (mNextTimeToDoSomething < now) {
          now = PR_IntervalNow();
          FormatDataPkt(PR_IntervalToMilliseconds(now));

          if ((mSentBytes >= MAXBYTES) && mFirstPktSent &&
              (PR_IntervalToSeconds(now - mFirstPktSent) >= MAXTIME)) {
            LOG(("Test 6 finished: current time %lu, first packet sent at %lu, "
                 "duration %lu, sent %llu bytes, max bytes to be sent %llu",
                 now, mFirstPktSent,
                 PR_IntervalToMilliseconds(now - mFirstPktSent), mSentBytes,
                 MAXBYTES));
            mLastPktId = mNextPktId;
            FormatFinishPkt();
            mPhase = FINISH_PACKET;
          }
          int count = PR_SendTo(mFd, mSendBuf, PAYLOADSIZE, 0, &mNetAddr,
                                PR_INTERVAL_NO_WAIT);
          if (count < 0) {
            PRErrorCode code = PR_GetError();
            if (code == PR_WOULD_BLOCK_ERROR) {
              return NS_OK;
            }
            return ErrorAccordingToNSPRWithCode(code, "UDP");
          }
          mSentBytes += count;

          if (mPhase != FINISH_PACKET) {
            // Calculate time to do something.
            mNextToSendInns += mPktInterval;
            mNextTimeToDoSomething = mFirstPktSent +
              PR_MicrosecondsToInterval(floor(mNextToSendInns / 1000.0));

            // Log data.
            sprintf(mLogstr, "%lu SEND %lu %lu\n",
                    (unsigned long)PR_IntervalToMilliseconds(now),
                    (unsigned long)mNextPktId,
                    (unsigned long)PR_IntervalToMilliseconds(mNextTimeToDoSomething));
            mLogFile.WriteNonBlocking(mLogstr, strlen(mLogstr));

          } else {
            // Calculate time to do something.
            mNextTimeToDoSomething = now +
              PR_MillisecondsToInterval(RETRANSMISSION_TIMEOUT);

            // Log data.
            sprintf(mLogstr, "%lu FIN %lu expected to send: %lu\n",
                    (unsigned long)PR_IntervalToMilliseconds(now),
                    (unsigned long)mNextPktId,
                    (unsigned long)PR_IntervalToMilliseconds(mNextTimeToDoSomething));
            mLogFile.WriteBlocking(mLogstr, strlen(mLogstr));
          }

          mNextPktId++;
          if (!mFirstPktSent) {
            mFirstPktSent = now;
          }
        }
      }
      break;
    default:
      return NS_ERROR_FAILURE;
  }
  return NS_OK;
}

nsresult
UDP::SendFinishPacket()
{
  LOG(("NetworkTest UDP client: Sending finish packet retransmission %d.",
       mNumberOfRetransFinish));
  if (mNumberOfRetransFinish > MAX_RETRANSMISSIONS) {
    mError = true;
    mPhase = PHASE::TEST_FINISHED;
    return NS_OK;
  }

  PRIntervalTime now = PR_IntervalNow();

  FormatDataPkt(PR_IntervalToMilliseconds(now));
  FormatFinishPkt();
  int count = PR_SendTo(mFd, mSendBuf, PAYLOADSIZE, 0, &mNetAddr,
                        PR_INTERVAL_NO_WAIT);
  if (count < 1) {
    PRErrorCode code = PR_GetError();
    if (code == PR_WOULD_BLOCK_ERROR) {
      return NS_OK;
  }
    return ErrorAccordingToNSPRWithCode(code, "UDP");
  }
  mSentBytes += count;

  sprintf(mLogstr, "%lu FIN\n", (unsigned long)PR_IntervalToMilliseconds(now));
  mLogFile.WriteBlocking(mLogstr, strlen(mLogstr));

  LOG(("NetworkTest UDP client: Sending finish packet for test %d"
       " - sent %lu bytes - received %lu bytes.",
       mTestType, mSentBytes, mRecvBytes));
  mNextTimeToDoSomething = now +
                           PR_MillisecondsToInterval(RETRANSMISSION_TIMEOUT);
  mNumberOfRetransFinish++;
  return NS_OK;
}

nsresult
UDP::NoDataForTooLong()
{
  LOG(("NetworkTest UDP client: No data from the other side for too long - "
       "finish test."));
  mError = true;
  mPhase = PHASE::TEST_FINISHED;
  return NS_OK;
}

nsresult
UDP::SendAcks()
{
  int del = 0;
  for (std::vector<Ack>::iterator it = mAcksToSend.begin();
       it != mAcksToSend.end(); it++) {
    int rv = it->SendPkt(mFd, &mNetAddr);
    if (rv == PR_WOULD_BLOCK_ERROR) {
      break;
    }
    if (rv != 0) {
      return ErrorAccordingToNSPRWithCode(rv, "UDP");;
    }
    del++;
  }
  if (del) {
    mAcksToSend.erase(mAcksToSend.begin(), mAcksToSend.begin() + del);
  }
  return NS_OK;
}

nsresult
UDP::NewPkt(int32_t aCount, char *aBuf)
{
  PRIntervalTime lastReceived = PR_IntervalNow();

  // if we have not received packet for a long time we can assume a broken
  // connection.
  mLastReceivedTimeout = lastReceived + mNodataTimeout;

  // We can receive a data packet(test 5) or an ack(test 6 and test 1) or a
  // packet describing the start of a new test.
  switch (mTestType) {
    case 1:
      LOG(("NetworkTest UDP client: Receiving data for test - UDP "
           "reachability  - received %u bytes.", aCount));
      if (mPhase == PHASE::START_TEST) {
        uint32_t id;
        memcpy(&id, aBuf + PKT_ID_START, PKT_ID_LEN);
        if (mNextPktId != id) {
          LOG(("NetworkTest UDP client: packet with id %lu has been received, "
               "but it should have bin id %lu", mNextPktId, id));
          return NS_OK;
        }
        mPhase = PHASE::WAIT_FINISH_TIMEOUT;
        mNextTimeToDoSomething = PR_IntervalNow() +
                                 PR_MillisecondsToInterval(SHUTDOWNTIMEOUT);
      }
      break;
    case 5:
      mRecvBytes +=aCount;

      if (mPhase == PHASE::START_TEST) {
        mPhase = PHASE::RUN_TEST;
        mNextTimeToDoSomething = 0;
        mFirstPktReceived = lastReceived;
      }

      // Send ack.
      mAcksToSend.push_back(Ack(aBuf, lastReceived));

      if (mPhase == PHASE::RUN_TEST) {
        if (memcmp(aBuf + FINISH_START, FINISH, FINISH_LEN) == 0) {
          mPhase = WAIT_FINISH_TIMEOUT;
          mNextTimeToDoSomething = lastReceived +
                                   PR_MillisecondsToInterval(SHUTDOWNTIMEOUT);

          if (PR_IntervalToSeconds(PR_IntervalNow() - mFirstPktReceived)) {
            mRateObserved = (double)mRecvBytes / PAYLOADSIZEF /
              (double)PR_IntervalToMilliseconds(PR_IntervalNow() - mFirstPktReceived)
              * 1000.0;
          }
          LOG(("Test 5 finished: current time %lu, first packet sent %lu, "
               "duration %lu, received %llu, observed rate: %lf",
               PR_IntervalNow(),
               mFirstPktReceived,
               PR_IntervalToMilliseconds(PR_IntervalNow() - mFirstPktReceived),
               mRecvBytes,
               mRateObserved));
        }
      }
      break;
    case 6:
      {
        // Receiving an ack.
        mRecvBytes +=aCount;

        uint32_t pktId = ReadACKPktAndLog(aBuf,
          PR_IntervalToMilliseconds(lastReceived));

        if (mPhase == PHASE::START_TEST) {
          mPhase = PHASE::RUN_TEST;
        }
        if (mPhase == PHASE::FINISH_PACKET) {
          if (mLastPktId == pktId) {
            mPhase = WAIT_FINISH_TIMEOUT;
            uint64_t rate;
            memcpy(&rate, aBuf + RATE_RECEIVING_PKT_START,
                   RATE_RECEIVING_PKT_LEN);
            mRateObserved = ntohll(rate);
            mNextTimeToDoSomething = lastReceived +
                                     PR_MillisecondsToInterval(SHUTDOWNTIMEOUT);
          }
        }
      }
      break;

    default:
      return NS_ERROR_UNEXPECTED;
  }
  return NS_OK;
}

nsresult
UDP::WaitForFinishTimeout()
{
  LOG(("NetworkTest UDP client: WaitForFinishTimeout "));
  mError = false;
  mPhase = TEST_FINISHED;
  return NS_OK;
}

void
UDP::FormatStartPkt(uint32_t aTS)
{
  memcpy(mSendBuf + PKT_ID_START, &mNextPktId, PKT_ID_LEN);
  memcpy(mSendBuf + TIMESTAMP_START, &aTS, TIMESTAMP_LEN);
  memcpy(mSendBuf + TYPE_START,
         (mTestType == 1) ? UDP_reachability :
         (mTestType == 5) ? UDP_performanceFromServerToClient :
         UDP_performanceFromClientToServer, TYPE_LEN);

  if (mTestType == 5) {
    uint64_t rate = htonll(mRate);
    memcpy(mSendBuf + RATE_TO_SEND_START, &rate, RATE_TO_SEND_LEN);
    memcpy(mSendBuf + FILE_NAME_START, mLogFileName.get(), FILE_NAME_LEN);
  }
}

void
UDP::FormatDataPkt(uint32_t aTS)
{
  // We do not do htonl for pkt id and timestamp because these values will be
  // only read by this host. They are stored in a packet, sent to the receiver,
  // the receiver copies them into an ACK pkt and sends them back to the sender
  // that copies them back into uint32_t variables.

  // Add pkt ID.
  memcpy(mSendBuf + PKT_ID_START, &mNextPktId, PKT_ID_LEN);

  // Add timestamp.
  memcpy(mSendBuf + TIMESTAMP_START, &aTS, TIMESTAMP_LEN);
}

void
UDP::FormatFinishPkt()
{
  memcpy(mSendBuf + FINISH_START, FINISH, FINISH_LEN);
}

uint32_t
UDP::ReadACKPktAndLog(char *aBuf, uint32_t aTS)
{
  // We do not do htonl for pkt id and timestamp because these values will be
  // only read by this host. They are stored in a packet, sent to the receiver,
  // the receiver copies them into an ACK pkt and sends them back to the sender
  // that copies them back into uint32_t variables.

  // Get packet Id.
  uint32_t pktId;
  memcpy(&pktId, aBuf + PKT_ID_START, PKT_ID_LEN);

  // Get timestamp.
  uint32_t ts;
  memcpy(&ts, aBuf + TIMESTAMP_START, TIMESTAMP_LEN);

  // Get the time the pkt was received at the receiver and the time the ACK
  // was sent.
  // The delay at the receiver can be calculated from these values.
  uint32_t usecReceived;
  memcpy(&usecReceived, aBuf + TIMESTAMP_RECEIVED_START,
         TIMESTAMP_RECEIVED_LEN);
  uint32_t usecACKSent;
  memcpy(&usecACKSent, aBuf + TIMESTAMP_ACK_SENT_START, TIMESTAMP_ACK_SENT_LEN);

  sprintf(mLogstr, "%lu ACK %lu %lu %lu %lu\n",
          (unsigned long)aTS,
          (unsigned long)pktId,
          (unsigned long)ts,
          (unsigned long)ntohl(usecReceived),
          (unsigned long)ntohl(usecACKSent));
  mLogFile.WriteNonBlocking(mLogstr, strlen(mLogstr));
  return pktId;
}

void
UDP::LogLogFormat()
{
  char line1[] = "Data pkt has been sent: [timestamp pkt sent] SEND [pkt id] [pkt are sent in \n"
                 "                        equal intervals log time when it should have been\n"
                 "                        sent(this is for the analysis whether the gap between\n"
                 "                        the time it should have been sent and the time it was\n"
                 "                        sent is too large)]\n";
  mLogFile.WriteBlocking(line1, strlen(line1));

  char line2[] = "The last packet has the same format as data packet\n";
  mLogFile.WriteBlocking(line2, strlen(line2));

  char line3[] = "An ACK has been received: [timestamp ack was received] ACK [pkt id]\n"
                 "                          [timestamp data pkt was sent by the sender (this\n"
                 "                          host)] [time when data packet was received by the\n"
                 "                          receiver] [time when ack was sent by the receiver]\n";
  mLogFile.WriteBlocking(line3, strlen(line3));
}

} // namespace NetworkPath
