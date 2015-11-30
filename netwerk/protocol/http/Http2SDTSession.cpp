/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// HttpLog.h should generally be included first
#include "HttpLog.h"

// Log on level :5, instead of default :4.
#undef LOG
#define LOG(args) LOG5(args)
#undef LOG_ENABLED
#define LOG_ENABLED() LOG5_ENABLED()

#include "Http2SDTSession.h"

namespace mozilla {
namespace net {

extern Http2ControlFx sControlFunctions[];

Http2SDTSession::Http2SDTSession(nsISocketTransport *aSocketTransport,
                                 uint32_t version)
  : Http2Session(aSocketTransport, version)
  , mNextHeaderSeqNum(1)
  , mDataSend(0)
{
  mMaxPacketSize = gHttpHandler->SdtChunkSize();
  mFrameHeaderBytes = kFrameLengthBytes + kFrameFlagBytes +  kFrameTypeBytes +
                      kFrameStreamIDBytes + kFrameSeqNumBytes +
                      kFrameSeqNumBytes;
  mMaxFrameData = 0x4000;//mMaxPacketSize - mFrameHeaderBytes;
  Init();
}

// call with data length (i.e. 0 for 0 data bytes - ignore 13 byte header)
// dest must have 13 bytes of allocated space
void
Http2SDTSession::CreateFrameHeader(char *dest, uint16_t frameLength,
                                   uint8_t frameType, uint8_t frameFlags,
                                   uint32_t streamID)
{
  MOZ_ASSERT(frameLength <= mMaxFrameData, "framelength too large");
  MOZ_ASSERT(!(streamID & 0x80000000));

  dest[0] = 0x00;
  NetworkEndian::writeUint16(dest + 1, frameLength);
  dest[3] = frameType;
  dest[4] = frameFlags;
  NetworkEndian::writeUint32(dest + 5, streamID);

  if (frameType != FRAME_TYPE_PADDING) {
    uint32_t frameSeqNum;
    if (!mStreamsNextFrameSeqNum.Get(streamID, &frameSeqNum)) {
      frameSeqNum = 1;
    }
    NetworkEndian::writeUint32(dest + 9, frameSeqNum);
    mStreamsNextFrameSeqNum.Put(streamID, ++frameSeqNum);

    if (frameType == FRAME_TYPE_HEADERS ||
        frameType == FRAME_TYPE_CONTINUATION ||
        frameType == FRAME_TYPE_PUSH_PROMISE) {
      NetworkEndian::writeUint32(dest + 13, mNextHeaderSeqNum++);
    } else {
      memset(dest + 13, 0, 4);
    }
  } else {
    memset(dest + 9, 0, 8);
    memset(dest + 13, 0, 4);
  }

}

void
Http2SDTSession::GeneratePadding(uint32_t aLength)
{
  LOG(("Http2SDTSession::GeneratePadding"));
  if (!aLength) {
    return;
  }
  MOZ_ASSERT(aLength >= mFrameHeaderBytes, "The lengt must be at least the "
                                           "frame header size");
  char *packet = EnsureOutputBuffer(aLength);
  CreateFrameHeader(packet,
                    aLength - mFrameHeaderBytes,
                    Http2Session::FRAME_TYPE_PADDING,
                    0, 0);
  mOutputQueueUsed += aLength;
}

void
Http2SDTSession::FlushOutputQueue()
{
  if (!mSegmentReader || !mOutputQueueUsed)
    return;

  nsresult rv;
  uint32_t countRead;
  uint32_t avail = mOutputQueueUsed - mOutputQueueSent;

  while (avail) {
    if (avail < mMaxPacketSize) {
      GeneratePadding(mMaxPacketSize - avail);
      avail = mMaxPacketSize;
    }
    rv = mSegmentReader->
      OnReadSegment(mOutputQueueBuffer.get() + mOutputQueueSent, mMaxPacketSize,
                    &countRead);
    LOG3(("Http2Session::FlushOutputQueue %p sz=%d rv=%x actual=%d",
          this, avail, rv, countRead));

    // Dont worry about errors on write, we will pick this up as a read error
    // too
    if (NS_FAILED(rv))
      return;

    mDataSend += countRead;
    avail -= countRead;
    mOutputQueueSent += countRead;
  }
  if (!avail) {
    mOutputQueueUsed = 0;
    mOutputQueueSent = 0;
    return;
  }

  // If the output queue is close to filling up and we have sent out a good
  // chunk of data from the beginning then realign it.

  if ((mOutputQueueSent >= kQueueMinimumCleanup) &&
      ((mOutputQueueSize - mOutputQueueUsed) < kQueueTailRoom)) {
    RealignOutputQueue();
  }
}

nsresult
Http2SDTSession::CommitToSegmentSize(uint32_t count, bool forceCommitment)
{
  if (mOutputQueueUsed)
    FlushOutputQueue();

  uint32_t neededPadding = AmountOfPaddingNeeded(count);
  // would there be enough room to buffer this if needed?
  if ((mOutputQueueUsed + count + neededPadding) <=
      (mOutputQueueSize - kQueueReserved)) {
    GeneratePadding(neededPadding);
    return NS_OK;
  }

  // if we are using part of our buffers already, try again later unless
  // forceCommitment is set.
  if (mOutputQueueUsed && !forceCommitment)
    return NS_BASE_STREAM_WOULD_BLOCK;

  if (mOutputQueueUsed) {
    // normally we avoid the memmove of RealignOutputQueue, but we'll try
    // it if forceCommitment is set before growing the buffer.
    RealignOutputQueue();
  }

  // is there enough room now?
  if ((mOutputQueueUsed + count + neededPadding) >
      (mOutputQueueSize - kQueueReserved)) {
    // resize the buffers as needed
    EnsureOutputBuffer(count + neededPadding + kQueueReserved);
  }

  MOZ_ASSERT((mOutputQueueUsed + count) <= (mOutputQueueSize - kQueueReserved),
             "buffer not as large as expected");
  GeneratePadding(neededPadding);
  return NS_OK;
}

uint32_t
Http2SDTSession::AmountOfPaddingNeeded(uint32_t aCount)
{
  uint32_t rest = mMaxPacketSize -
                  (mDataSend + mOutputQueueUsed - mOutputQueueSent) %
                  mMaxPacketSize;
  rest = (rest) ? rest : mMaxPacketSize;

  if ((aCount > rest) ||
      ((rest != aCount) && ((rest - aCount) < mFrameHeaderBytes))) {
    LOG(("Http2SDTSession::AmountOfPaddingNeeded %p needed %u", this, rest));
    return rest;
  }
  return 0;
}

uint32_t
Http2SDTSession::FreePlaceInCurrentPacket(uint32_t aCount)
{
  if (aCount == 0) {
    return 0;
  }
  uint32_t rest = mMaxPacketSize -
                  (mDataSend + mOutputQueueUsed - mOutputQueueSent ) %
                  mMaxPacketSize;
  rest = (rest == mFrameHeaderBytes) ? mMaxPacketSize : rest;

  LOG(("Http2SDTSession::FreePlaceInCurrentPacket %p rest bytes in packet %u "
       "needed space %u",this, rest, aCount));

  if ((rest == (aCount + mFrameHeaderBytes)) ||
      (rest > (aCount + 2 * mFrameHeaderBytes))) {
    return aCount;
  } else if (rest < (aCount + mFrameHeaderBytes)) {
    return rest - mFrameHeaderBytes;
  } else if ((rest - mFrameHeaderBytes) > 0) {
    return rest -= 2 * mFrameHeaderBytes;
  } else {
    return (aCount < mMaxFrameData) ? aCount : mMaxFrameData;
  }
}

void
Http2SDTSession::PreparePlaceInCurrentPacket(uint32_t aCount)
{
  uint32_t rest = mMaxPacketSize -
                  (mDataSend + mOutputQueueUsed - mOutputQueueSent) %
                  mMaxPacketSize;
  rest = (rest) ? rest : mMaxPacketSize;
  LOG(("Http2SDTSession::PreparePlaceInCurrentPacket %p rest bytes in packet "
       "%u needed space %u", this, aCount, rest));

  if ((aCount > rest) ||
      ((aCount != rest) && ((rest - aCount) < mFrameHeaderBytes))) {
    GeneratePadding(rest);
  }
}

} // namespace mozilla::net
} // namespace mozilla
