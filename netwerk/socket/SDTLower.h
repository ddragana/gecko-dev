/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef SDTLOWERLAYER

#define SDTLOWERLAYER

#include "nsAutoPtr.h"
#include "nsTArray.h"

namespace mozilla {
namespace net {

class SDTLower {
public:
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(SDTLower)

  SDTLower();
  bool HasData() { return mPacketQueue.Length(); }
  bool SocketWritable();
  void GetFrame();
  int32_t ReadData(void *aBuf, int32_t aAmount, int aFlags);
  int32_t WriteData(const void *aBuf, int32_t aAmoun);
  void SetFD(PRFileDesc *aFd) { mFd = aFd; }

private:
  ~SDTLower() {};
  class Packet
  {
  public:
    uint32_t mStreamId;
    uint8_t mType;
    uint32_t mFrameSeqNum;
    uint32_t mHeaderSeqNum;
    uint32_t mBufferUsed;
    uint32_t mBufferLength;
    nsAutoArrayPtr<char> mBuffer;
    Packet(uint32_t aLength) {
      mBufferLength = 0;
      mBufferUsed = 0;
      mBuffer = static_cast<char *>(moz_xmalloc(aLength));
    }
  };

  void ReadHeader(Packet *aPacket);
  void OrderFrames(Packet *aPacket);
  void OrderFramesWithOrderedHeaders(Packet *aPacket);

  class PacketComparator
  {
     public:
       bool Equals(Packet *aA, Packet *aB) const {
         return aA->mFrameSeqNum == aB->mFrameSeqNum;
       }
       bool LessThan(Packet *aA, Packet *aB) const {
         return aA->mFrameSeqNum < aB->mFrameSeqNum;
       }
  };

  class PacketQueue
  {
  public:
    uint32_t mStreamId;
    uint32_t mNextFrameSeqNum;
    nsTArray<nsAutoPtr<Packet>> mQueue;
  };

  class PacketQueueComparatorStreamId
  {
    public:
      bool Equals(PacketQueue *aA, const uint32_t &aB) const {
        return aA->mStreamId == aB;
      }
  };

  class PacketQueueComparator
  {
    public:
      bool Equals(PacketQueue *aA, PacketQueue *aB) const {
        return aA->mStreamId == aB->mStreamId;
      }
      bool LessThan(PacketQueue *aA, PacketQueue *aB) const {
        return aA->mStreamId < aB->mStreamId;
      }
  };

  // For ordering incoming frames
  nsTArray<nsAutoPtr<PacketQueue>> mStreamQueues;
  nsAutoPtr<PacketQueue> mHeaderFrameQueue;

  // Keeps already ordered packets.
  nsTArray<nsAutoPtr<Packet>> mPacketQueue;
  PRFileDesc *mFd;
};


} // namespace mozilla::net
} // namespace mozilla

PRFileDesc *sdt_addSDTLowerLayer(PRFileDesc *aFd, mozilla::net::SDTLower *aHandle);
void sdtLower_ensureInit();

#endif //SDTLOWERLAYER
