/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef HTTP2TOSDTLAYER

#define HTTP2TOSDTLAYER

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unordered_map>
#include <map>
#include <memory>
#include <iostream>
#include <list>
#include <vector>

#define SDT_CLEARTEXTPAYLOADSIZE 1336

class Http2ToSdt {
public:

  Http2ToSdt();
  ~Http2ToSdt() {};
  bool HasData() { return !mPacketQueue.empty(); }
  void GetFrame();
  int32_t ReadData(void *aBuf, int32_t aAmount, int aFlags);
  int32_t WriteData(const void *aBuf, int32_t aAmoun);
  void SetFD(PRFileDesc *aFd) { mFd = aFd; }

private:

  class Packet
  {
  public:
    uint32_t mStreamId;
    uint8_t mType;
    uint32_t mFrameSeqNum;
    uint32_t mHeaderSeqNum;
    uint32_t mBufferUsed;
    uint32_t mBufferLength;
    char mBuffer[SDT_CLEARTEXTPAYLOADSIZE];
    Packet() {
      mBufferLength = 0;
      mBufferUsed = 0;
    }
  };

  void HeaderReadTransform(Packet *aPacket);
  void OrderPackets(std::unique_ptr<Packet> aPacket);
  void OrderPacketsWithOrderedHeaders(std::unique_ptr<Packet> aPacket);

  class PacketQueue
  {
  public:
    uint32_t mStreamId;
    uint32_t mNextFrameSeqNum;
    std::map<uint32_t, std::unique_ptr<Packet>> mQueue;
  };

  // For ordering incoming frames
  std::unordered_map<uint32_t, std::unique_ptr<PacketQueue>> mInStreamQueues;
  std::unique_ptr<PacketQueue> mInHeaderFrameQueue;

  // Keeps already ordered packets.
  std::list<std::unique_ptr<Packet>> mPacketQueue;
  PRFileDesc *mFd;
  PRErrorCode mError;

  // For ordering outgoing frames
  std::unordered_map<uint32_t, uint32_t> mOutStreamNextId;
  uint32_t mOutHeaderFrameNextId;
  char mOutBuffer[SDT_CLEARTEXTPAYLOADSIZE];
  uint32_t mOutBufferUsed;
  std::vector<char> mNewFrame;
  uint16_t mNewFrameLen;
  uint16_t mNewFrameFilled;
  uint16_t mNewFrameUsed;

  static const uint8_t kMagicHello[24];
  bool mMagicHelloSent;
};

PRFileDesc *sdt_addHttp2ToSdtLayer(PRFileDesc *aFd);
void Http2ToSdt_ensureInit();

#endif //HTTP2TOSDTLAYER
