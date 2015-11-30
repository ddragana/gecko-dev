/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include "mozilla/Endian.h"
#include "mozilla/Logging.h"
#include "prerror.h"
#include "prio.h"
#include "sdt.h"
#include "sdt_common.h"
#include "SDTLower.h"

#define HTTP2SDT_HEADERSEQ 13
#define HTTP2SDT_FRAMESEQ 9
#define HTTP2SDT_FRAMETYPE 3
#define HTTP2SDT_STREAMID 5
#define SDT_CLEARTEXTPAYLOADSIZE 1336

#define FRAME_TYPE_HEADERS 0x1
#define FRAME_TYPE_CONTINUATION 0x9
#define FRAME_TYPE_PUSH_PROMISE 0x5

//TODO delete streams from mStreamQueues when they are finished.
namespace mozilla {
namespace net {


extern PRLogModuleInfo *gSDTLog;

#define LOG(args) MOZ_LOG(mozilla::net::gSDTLog, mozilla::LogLevel::Error, args)

SDTLower::SDTLower()
{
  mHeaderFrameQueue = new PacketQueue;
  mHeaderFrameQueue->mNextFrameSeqNum = 1;
}

bool
SDTLower::SocketWritable()
{
  return sdt_SocketWritable(mFd->lower);
}

void
SDTLower::ReadHeader(SDTLower::Packet *aPacket)
{
  aPacket->mHeaderSeqNum = NetworkEndian::readUint32(aPacket->mBuffer.get() +
                                                     HTTP2SDT_HEADERSEQ);
  aPacket->mFrameSeqNum = NetworkEndian::readUint32(aPacket->mBuffer.get() +
                                                    HTTP2SDT_FRAMESEQ);
  aPacket->mType = *reinterpret_cast<uint8_t *>(aPacket->mBuffer.get() +
                                                HTTP2SDT_FRAMETYPE);
  aPacket->mStreamId = NetworkEndian::readUint32(aPacket->mBuffer.get() +
                                                 HTTP2SDT_STREAMID);

  LOG(("SDTLower::ReadHeader headerSeq=%d seq=%d type=%d stream=%d.",
      aPacket->mHeaderSeqNum, aPacket->mFrameSeqNum, aPacket->mType,
      aPacket->mStreamId));
}

void
SDTLower::GetFrame()
{
  LOG(("SDTLower::GetFrame."));
  nsAutoPtr<Packet> pkt;
  pkt = new Packet(SDT_CLEARTEXTPAYLOADSIZE);
  int32_t rv = mFd->lower->methods->recv(mFd->lower,
                                         pkt->mBuffer.get(),
                                         SDT_CLEARTEXTPAYLOADSIZE,
                                         0,
                                         PR_INTERVAL_NO_WAIT);
  if (rv > 0) {
    pkt->mBufferLength = rv;
    ReadHeader(pkt);
    OrderFrames(pkt.forget());
  }
}

int32_t
SDTLower::ReadData(void *aBuf, int32_t aAmount, int aFlags)
{
  LOG(("SDTLower::ReadData."));
  if (!mPacketQueue.Length()) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

//  MOZ_ASSERT(aAmount <=
//             (mPacketQueue[0]->mBufferLength - mPacketQueue[0]->mBufferUsed));
  int32_t sz =
    (aAmount < (mPacketQueue[0]->mBufferLength - mPacketQueue[0]->mBufferUsed))
    ? aAmount
    : (mPacketQueue[0]->mBufferLength - mPacketQueue[0]->mBufferUsed);
  memcpy(aBuf, mPacketQueue[0]->mBuffer.get() + mPacketQueue[0]->mBufferUsed,
         sz);
  if (!(aFlags & PR_MSG_PEEK)) {
    mPacketQueue[0]->mBufferUsed += sz;
  }
  if (mPacketQueue[0]->mBufferUsed == mPacketQueue[0]->mBufferLength) {
    mPacketQueue.RemoveElementAt(0);
  }
  return sz;
}

int32_t
SDTLower::WriteData(const void *aBuf, int32_t aAmount)
{
  LOG(("SDTLower::WriteData."));
  return PR_Write(mFd, aBuf, aAmount);
}

void
SDTLower::OrderFrames(SDTLower::Packet *aPacket)
{
  LOG(("SDTLower::OrderFrames %p.", this));

  if (aPacket->mType == FRAME_TYPE_HEADERS ||
      aPacket->mType == FRAME_TYPE_CONTINUATION ||
      aPacket->mType == FRAME_TYPE_PUSH_PROMISE) {

    if (mHeaderFrameQueue->mNextFrameSeqNum > aPacket->mHeaderSeqNum) {
      // Discharge packet, it is a dup.
      delete aPacket;
      return;
    }

    if (mHeaderFrameQueue->mNextFrameSeqNum == aPacket->mHeaderSeqNum) {
      mHeaderFrameQueue->mNextFrameSeqNum++;
      LOG(("SDTLower::OrderFrames - inorder header frame."));
      OrderFramesWithOrderedHeaders(aPacket);

      while (mHeaderFrameQueue->mQueue.Length() &&
             (mHeaderFrameQueue->mNextFrameSeqNum >=
              mHeaderFrameQueue->mQueue[0]->mFrameSeqNum)) {
        LOG(("SDTLower::OrderFrames  inorder %d.",
             mHeaderFrameQueue->mNextFrameSeqNum));
        if (mHeaderFrameQueue->mNextFrameSeqNum ==
              mHeaderFrameQueue->mQueue[0]->mFrameSeqNum) {
          OrderFramesWithOrderedHeaders(mHeaderFrameQueue->mQueue[0].forget());
          mHeaderFrameQueue->mQueue.RemoveElementAt(0);
          mHeaderFrameQueue->mNextFrameSeqNum++;
        } else {
          mHeaderFrameQueue->mQueue.RemoveElementAt(0);
        }
      }
    } else {
      LOG(("SDTLower::OrderFrames queue header frame."));
      mHeaderFrameQueue->mQueue.InsertElementSorted(aPacket, PacketComparator());
    }
  } else {
    OrderFramesWithOrderedHeaders(aPacket);
  }
}

void
SDTLower::OrderFramesWithOrderedHeaders(Packet *aPacket)
{
  LOG(("SDTLower::OrderFramesWithOrderedHeaders %p.", this));

  if (!mStreamQueues.Contains(aPacket->mStreamId,
                              PacketQueueComparatorStreamId())) {
    nsAutoPtr<PacketQueue> newQueue;
    newQueue = new PacketQueue();
    newQueue->mStreamId = aPacket->mStreamId;
    newQueue->mNextFrameSeqNum = 1;
    mStreamQueues.InsertElementSorted(newQueue.forget(), PacketQueueComparator());
  }

  int inx = mStreamQueues.IndexOf(aPacket->mStreamId, 0,
                                  PacketQueueComparatorStreamId());
  PacketQueue *queue = mStreamQueues[inx];
  if (queue->mNextFrameSeqNum > aPacket->mFrameSeqNum) {
    // Discharge packet, it is a dup.
    delete aPacket;
    return;
  }
  if (queue->mNextFrameSeqNum == aPacket->mFrameSeqNum) {
    queue->mNextFrameSeqNum++;
    LOG(("SDTLower::OrderFramesWithOrderedHeaders - inorder frame."));
    mPacketQueue.AppendElement(aPacket);

    while (queue->mQueue.Length() &&
           (queue->mQueue[0]->mFrameSeqNum <= queue->mNextFrameSeqNum)) {
      LOG(("SDTLower::OrderFramesWithOrderedHeaders - inorder %d.",
           queue->mNextFrameSeqNum));
      // TODO need to change a structure maybe to be able to check for duplicates before inserting.
      if (queue->mQueue[0]->mFrameSeqNum == queue->mNextFrameSeqNum) {
        mPacketQueue.AppendElement(mStreamQueues[inx]->mQueue[0].forget());
        queue->mQueue.RemoveElementAt(0);
        queue->mNextFrameSeqNum++;
      } else {
        queue->mQueue.RemoveElementAt(0);
      }
    }
  } else {
    LOG(("SDTLower::OrderFramesWithOrderedHeaders - queue frame."));
    queue->mQueue.InsertElementSorted(aPacket, PacketComparator());
  }
}

} // namespace mozilla::net
} // namespace mozilla

static int32_t
sdtLowerLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
                  int aFlags, PRIntervalTime to)
{
  mozilla::net::SDTLower *handle = (mozilla::net::SDTLower *)(aFD->secret);
  if (!handle) {
    MOZ_ASSERT(false);
    return -1;
  }

  handle->GetFrame();

  PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
  return -1;
}

static int32_t
sdtLowerLayerWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount)
{
  return aFD->lower->methods->write(aFD->lower, aBuf, aAmount);
}

static PRInt16 PR_CALLBACK
sdtLowerLayerPoll(PRFileDesc *aFd, PRInt16 how_flags,
                  PRInt16 *p_out_flags)
{
  LOG(("SDTLower::poll %d %d %p.", how_flags, *p_out_flags, aFd));
  MOZ_ASSERT(aFd->lower->methods->poll);
  return aFd->lower->methods->poll(aFd->lower, how_flags, p_out_flags);
}

static PRStatus
sdtLowerLayerConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  return fd->lower->methods->connect(fd->lower, addr, to);
}

static void
sdtLowerDtor(PRFileDesc *aFd)
{
  if (aFd->secret) {
    mozilla::net::SDTLower *handle = (mozilla::net::SDTLower *)(aFd->secret);
    NS_RELEASE(handle);
    aFd->secret = nullptr;
  }
  PR_DELETE(aFd);
}

static PRDescIdentity sdtLowerIdentity;
static PRIOMethods sdtLowerMethods;

static int sdtLower_once = 0;

void
sdtLower_ensureInit()
{
  if (sdtLower_once) {
    return;
  }
  sdtLower_once = 1;

  sdtLowerIdentity = PR_GetUniqueIdentity("sdtLowerLayer");
  sdtLowerMethods = *PR_GetDefaultIOMethods();

  sdtLowerMethods.read = useRecv;
  sdtLowerMethods.recv = sdtLowerLayerRecv;
  sdtLowerMethods.recvfrom = notImplemented;
  sdtLowerMethods.write = sdtLowerLayerWrite;
  sdtLowerMethods.send = notImplemented2;
  sdtLowerMethods.sendto = notImplemented3;
  sdtLowerMethods.connect = sdtLowerLayerConnect;
  sdtLowerMethods.poll = sdtLowerLayerPoll;
  sdtLowerMethods.close = genericClose;
}

PRFileDesc *
sdt_addSDTLowerLayer(PRFileDesc *aFd, mozilla::net::SDTLower *aHandle)
{
  NS_ADDREF(aHandle);
  sdtLower_ensureInit();

  PRFileDesc *sdtLowerLayer = nullptr;

  sdtLowerLayer = PR_CreateIOLayerStub(sdtLowerIdentity, &sdtLowerMethods);

  if (!(aFd && sdtLowerLayer && aHandle)) {
    goto fail; // ha!
  }
  sdtLowerLayer->dtor = sdtLowerDtor;

  sdtLowerLayer->secret = (struct PRFilePrivate *)aHandle;

  if (PR_PushIOLayer(aFd, PR_GetLayersIdentity(aFd), sdtLowerLayer) == PR_SUCCESS) {
    sdtLowerLayer = nullptr;
  } else {
    goto fail;
  }

  aHandle->SetFD(aFd);

  return aFd;

fail:
  PR_Close(aFd);
  if (sdtLowerLayer) {
    sdtLowerLayer->dtor(sdtLowerLayer);
  }
  NS_RELEASE(aHandle);
  return nullptr;
}
