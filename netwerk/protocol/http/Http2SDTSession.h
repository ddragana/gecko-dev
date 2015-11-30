/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_Http2SDTSession_h
#define mozilla_net_Http2SDTSession_h

#include "ASpdySession.h"
#include "mozilla/Attributes.h"
#include "nsAHttpConnection.h"
#include "nsClassHashtable.h"
#include "nsDataHashtable.h"
#include "nsDeque.h"
#include "nsHashKeys.h"

#include "Http2Compression.h"
#include "Http2Session.h"

class nsISocketTransport;

namespace mozilla {
namespace net {

class Http2SDTSession final : public Http2Session
{
  ~Http2SDTSession() {}

public:
 // NS_DECL_THREADSAFE_ISUPPORTS

  Http2SDTSession(nsISocketTransport *, uint32_t version);

  bool IsHttp2() { return false; }

/*
  HTTP/2 framing

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Length (16)           |   Type (8)    |   Flags (8)   |
  +-+-------------+---------------+-------------------------------+
  |R|                 Stream Identifier (31)                      |
  +-+-------------------------------------------------------------+
  |                     Stream Seq Number                         |
  +-+-------------------------------------------------------------+
  |                     Stream Seq Number                         |
  +-+-------------------------------------------------------------+
  |                     Frame Data (0...)                       ...
  +---------------------------------------------------------------+
*/

  const static uint8_t kFrameSeqNumBytes = 4;

  void CreateFrameHeader(char *dest, uint16_t frameLength,
                         uint8_t frameType, uint8_t frameFlags,
                         uint32_t streamID);

  void GeneratePadding(uint32_t aDataLength);

  void FlushOutputQueue();
  uint32_t FreePlaceInCurrentPacket(uint32_t aCount);
  void PreparePlaceInCurrentPacket(uint32_t aCount);
  nsresult CommitToSegmentSize(uint32_t size, bool forceCommitment);

private:

  uint32_t AmountOfPaddingNeeded(uint32_t aCount);

private:

  // For indexing outgoing frames
  uint32_t mNextHeaderSeqNum;
  nsDataHashtable<nsUint32HashKey, uint32_t> mStreamsNextFrameSeqNum;

  uint64_t mDataSend;
  uint32_t mMaxPacketSize;
};

} // namespace mozilla::net
} // namespace mozilla

#endif // mozilla_net_Http2SDTSession_h
