/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include "prerror.h"
#include "prio.h"
#include "Http2ToSdt.h"
#include <assert.h>
#include "prinrval.h"
#include "prtypes.h"
#include "sdt_common.h"

#define HTTP2SDT_HEADERSEQ 13
#define HTTP2SDT_FRAMESEQ 9
#define HTTP2SDT_SEQLEN 4
#define HTTP2SDT_FRAMETYPE 3
#define HTTP2SDT_STREAMID 5
#define HTTP2SDT_IDLEN 4
#define HTTP2_HEADERLEN 9
#define HTTP2SDT_HEADERLEN 17

#define FRAME_TYPE_HEADERS 0x1
#define FRAME_TYPE_CONTINUATION 0x9
#define FRAME_TYPE_PUSH_PROMISE 0x5

#define SDT_CLEARTEXTPAYLOADSIZE_NOHEADER (1336 - HTTP2SDT_HEADERLEN)

const uint8_t Http2ToSdt::kMagicHello[] = {
  0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
  0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
  0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
};

Http2ToSdt::Http2ToSdt()
  : mError(0) // Check this
  , mOutHeaderFrameNextId(1)
  , mOutBufferUsed(0)
  , mNewFrameLen(0)
  , mNewFrameFilled(0)
  , mNewFrameUsed(0)
  , mMagicHelloSent(false)
{
  mInHeaderFrameQueue = std::unique_ptr<PacketQueue>(new PacketQueue());
  mInHeaderFrameQueue->mNextFrameSeqNum = 1;
}

void
Http2ToSdt::HeaderReadTransform(Http2ToSdt::Packet *aPacket)
{
  memcpy(&aPacket->mHeaderSeqNum, aPacket->mBuffer + HTTP2SDT_HEADERSEQ,
         HTTP2SDT_SEQLEN);
  aPacket->mHeaderSeqNum = ntohl(aPacket->mHeaderSeqNum);

  memcpy(&aPacket->mFrameSeqNum, aPacket->mBuffer + HTTP2SDT_FRAMESEQ,
         HTTP2SDT_SEQLEN);
  aPacket->mFrameSeqNum = ntohl(aPacket->mFrameSeqNum);

  memcpy(&aPacket->mStreamId, aPacket->mBuffer + HTTP2SDT_STREAMID,
         HTTP2SDT_IDLEN);
  aPacket->mStreamId = ntohl(aPacket->mStreamId);

  aPacket->mType = *reinterpret_cast<uint8_t *>(aPacket->mBuffer +
                                                HTTP2SDT_FRAMETYPE);

  memmove(aPacket->mBuffer + HTTP2SDT_HEADERLEN - HTTP2_HEADERLEN,
          aPacket->mBuffer,
          HTTP2_HEADERLEN);

  aPacket->mBufferUsed = HTTP2SDT_HEADERLEN - HTTP2_HEADERLEN;
}

void
Http2ToSdt::GetFrame()
{
  std::unique_ptr<Packet> pkt(new Packet());
  int32_t rv = mFd->lower->methods->recv(mFd->lower,
                                         pkt->mBuffer,
                                         SDT_CLEARTEXTPAYLOADSIZE,
                                         0,
                                         PR_INTERVAL_NO_WAIT);
  if (rv < 0) {
    PRErrorCode errCode = PR_GetError();
    if (errCode != PR_WOULD_BLOCK_ERROR) {
      // Let the really socket return this error.
      mError = errCode;
    }
  } else {
    pkt->mBufferLength = rv;
    HeaderReadTransform(pkt.get());
    OrderPackets(std::move(pkt));
  }
}

int32_t
Http2ToSdt::ReadData(void *aBuf, int32_t aAmount, int aFlags)
{
  if (mError) {
    PR_SetError(mError, 0);
    return -1;
  }

  assert(!mPacketQueue.empty());

  if (!mMagicHelloSent) {
    mMagicHelloSent = true;
    // Make magic frame.
    std::unique_ptr<Packet> pkt(new Packet());
    memcpy(pkt->mBuffer, kMagicHello, 24);
    pkt->mBufferLength = 24;
    mPacketQueue.push_front(std::move(pkt));
  }

  uint32_t sz = (aAmount > (mPacketQueue.front()->mBufferLength - mPacketQueue.front()->mBufferUsed)) ?
                (mPacketQueue.front()->mBufferLength - mPacketQueue.front()->mBufferUsed) :
                aAmount;
  memcpy(aBuf,
         mPacketQueue.front()->mBuffer + mPacketQueue.front()->mBufferUsed,
         sz);
  if (!(aFlags & PR_MSG_PEEK)) {
    mPacketQueue.front()->mBufferUsed += sz;
  }
  if (mPacketQueue.front()->mBufferUsed ==
      mPacketQueue.front()->mBufferLength) {
    mPacketQueue.pop_front();
  }
  return sz;
}

int32_t
Http2ToSdt::WriteData(const void *aBuf, int32_t aAmount)
{
  if (mError) {
    PR_SetError(mError, 0);
    return -1;
  }

  uint32_t read = 0;
  bool changed = true;
  while ((mOutBufferUsed < (SDT_CLEARTEXTPAYLOADSIZE - HTTP2SDT_HEADERLEN)) &&
         aAmount && changed) {
    changed = false;
    if (!mNewFrameFilled) {
      if (aAmount >= HTTP2_HEADERLEN) {
        memcpy(&mNewFrameLen, (uint8_t*)aBuf + 1, 2);
        mNewFrameLen = ntohs(mNewFrameLen);
        mNewFrameLen += HTTP2_HEADERLEN;
        if (mNewFrame.capacity() < mNewFrameLen) {
          mNewFrame.resize(mNewFrameLen);
        }

        memcpy(mNewFrame.data(), aBuf, HTTP2_HEADERLEN);
        aAmount -= HTTP2_HEADERLEN;
        read += HTTP2_HEADERLEN;
        mNewFrameFilled += HTTP2_HEADERLEN;
        changed = true;
      }
    }
    if (mNewFrameLen && (mNewFrameLen != mNewFrameFilled) && aAmount) {
      uint32_t sz = (aAmount > (mNewFrameLen - mNewFrameFilled)) ?
                     (mNewFrameLen - mNewFrameFilled) :
                     aAmount;
      memcpy(mNewFrame.data() + mNewFrameFilled, (uint8_t*)aBuf + read, sz);
      mNewFrameFilled += sz;
      read += sz;
      aAmount -= sz;
      changed = true;
    }

    if ((mNewFrameLen && (mNewFrameLen == mNewFrameFilled)) ||
        (!mNewFrameUsed && (mNewFrameFilled >= SDT_CLEARTEXTPAYLOADSIZE)) ||
        (mNewFrameUsed && (mNewFrameFilled - mNewFrameUsed) >= SDT_CLEARTEXTPAYLOADSIZE_NOHEADER)) {
      memcpy(mOutBuffer + mOutBufferUsed,
             mNewFrame.data(),
             HTTP2_HEADERLEN);

      mNewFrameUsed += (!mNewFrameUsed) ? HTTP2_HEADERLEN : 0; // count header only once.
      uint16_t sz = ((mNewFrameFilled - mNewFrameUsed) >= SDT_CLEARTEXTPAYLOADSIZE_NOHEADER) ?
                     SDT_CLEARTEXTPAYLOADSIZE_NOHEADER :
                     (mNewFrameFilled - mNewFrameUsed);

      uint16_t len = htons(sz);
      memcpy(mOutBuffer + mOutBufferUsed + 1, &len, 2);

      // Add frame IDs.
      uint32_t streamId;
      memcpy(&streamId,
             mOutBuffer + mOutBufferUsed + HTTP2SDT_STREAMID,
             HTTP2SDT_IDLEN);
      streamId = ntohl(streamId);
      uint32_t id;
      if (mOutStreamNextId.find(streamId) == mOutStreamNextId.end()) {
        mOutStreamNextId.insert(std::make_pair(streamId, 1));
        id = 1;
      } else {
        id = mOutStreamNextId[streamId];
      }
      mOutStreamNextId[streamId] = id + 1;
      id = htonl(id);
      memcpy(mOutBuffer + mOutBufferUsed + HTTP2SDT_FRAMESEQ,
             &id,
             HTTP2SDT_SEQLEN);

      if ((mOutBuffer[mOutBufferUsed + HTTP2SDT_FRAMETYPE] == FRAME_TYPE_HEADERS) ||
          (mOutBuffer[mOutBufferUsed + HTTP2SDT_FRAMETYPE] == FRAME_TYPE_CONTINUATION) ||
          (mOutBuffer[mOutBufferUsed + HTTP2SDT_FRAMETYPE] == FRAME_TYPE_PUSH_PROMISE)) {
        id = htonl(mOutHeaderFrameNextId);
        mOutHeaderFrameNextId++;
        memcpy(mOutBuffer + mOutBufferUsed + HTTP2SDT_HEADERSEQ,
               &id,
               HTTP2SDT_SEQLEN);
      }

      mOutBufferUsed += HTTP2SDT_HEADERLEN;

      memcpy(mOutBuffer + mOutBufferUsed,
             mNewFrame.data() + mNewFrameUsed,
             sz);
      mOutBufferUsed += sz;
      mNewFrameUsed += sz;

      if (mNewFrameUsed == mNewFrameLen) {
        mNewFrameLen = mNewFrameUsed = mNewFrameFilled = 0;
      }
    }
  }

  if (mOutBufferUsed) {
    int32_t rv = mFd->lower->methods->write(mFd->lower, mOutBuffer,
                                            mOutBufferUsed);
    if (rv < 0) {
      PRErrorCode errCode = PR_GetError();
      if (errCode != PR_WOULD_BLOCK_ERROR) {
        // Return this error.
        return -1;
      }
    } else {
      assert(rv = mOutBufferUsed);
      mOutBufferUsed = 0;
    }
  }
  if (read) {
    return read;
  } else {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
}

void
Http2ToSdt::OrderPackets(std::unique_ptr<Packet> aPacket)
{
  if (aPacket->mType == FRAME_TYPE_HEADERS ||
      aPacket->mType == FRAME_TYPE_CONTINUATION ||
      aPacket->mType == FRAME_TYPE_PUSH_PROMISE) {

    if (mInHeaderFrameQueue->mNextFrameSeqNum > aPacket->mHeaderSeqNum) {
      // Dup - discharge it.
      return;
    }
    if (mInHeaderFrameQueue->mNextFrameSeqNum == aPacket->mHeaderSeqNum) {
      mInHeaderFrameQueue->mNextFrameSeqNum++;
      OrderPacketsWithOrderedHeaders(std::move(aPacket));

      std::map<uint32_t, std::unique_ptr<Packet>>::iterator it;
      it =
        mInHeaderFrameQueue->mQueue.find(mInHeaderFrameQueue->mNextFrameSeqNum);
      while (it != mInHeaderFrameQueue->mQueue.end()) {
        OrderPacketsWithOrderedHeaders(std::move(it->second));
        mInHeaderFrameQueue->mQueue.erase(it);
        mInHeaderFrameQueue->mNextFrameSeqNum++;
        it = mInHeaderFrameQueue->mQueue.find(mInHeaderFrameQueue->mNextFrameSeqNum);
      }
    } else {
      // Check for dups.
      if (mInHeaderFrameQueue->mQueue.find(aPacket->mHeaderSeqNum) ==
          mInHeaderFrameQueue->mQueue.end()) {
        mInHeaderFrameQueue->mQueue.insert(std::make_pair(aPacket->mHeaderSeqNum,
                                           std::move(aPacket)));
      }
    }
  } else {
    OrderPacketsWithOrderedHeaders(std::move(aPacket));
  }
}

void
Http2ToSdt::OrderPacketsWithOrderedHeaders(std::unique_ptr<Packet> aPacket)
{
  PacketQueue *queue;
  if (mInStreamQueues.find(aPacket->mStreamId) == mInStreamQueues.end()) {
    mInStreamQueues.insert(std::make_pair(aPacket->mStreamId,
                                        std::unique_ptr<PacketQueue>(
                                          new PacketQueue())));
    queue = mInStreamQueues.find(aPacket->mStreamId)->second.get();
    queue->mStreamId = aPacket->mStreamId;
    queue->mNextFrameSeqNum = 1;
  } else {
    queue = mInStreamQueues.find(aPacket->mStreamId)->second.get();
  }

  if (queue->mNextFrameSeqNum > aPacket->mFrameSeqNum) {
    // Dup - discharge it.
    return;
  }

  if (queue->mNextFrameSeqNum == aPacket->mFrameSeqNum) {
    queue->mNextFrameSeqNum++;
    mPacketQueue.push_back(std::move(aPacket));

    std::map<uint32_t, std::unique_ptr<Packet>>::iterator it;
    while ((it = queue->mQueue.find(queue->mNextFrameSeqNum)) !=
           queue->mQueue.end()) {
      mPacketQueue.push_back(std::move(it->second));
      queue->mQueue.erase(it);
      queue->mNextFrameSeqNum++;
    }
  } else {
    if (queue->mQueue.find(aPacket->mFrameSeqNum) == queue->mQueue.end()) {
      queue->mQueue.insert(std::make_pair(aPacket->mFrameSeqNum,
                                          std::move(aPacket)));
    }
  }
}

static int32_t
Http2ToSdtLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
                  int aFlags, PRIntervalTime to)
{
  Http2ToSdt *handle = (Http2ToSdt *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  handle->GetFrame();
  if (handle->HasData()) {
    return handle->ReadData(aBuf, aAmount, aFlags);
  } else {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
}

static int32_t
Http2ToSdtLayerWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount)
{
  Http2ToSdt *handle = (Http2ToSdt *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }
  return handle->WriteData(aBuf, aAmount);
}

static PRInt16 PR_CALLBACK
Http2ToSdtLayerPoll(PRFileDesc *aFd, PRInt16 how_flags,
                        PRInt16 *p_out_flags)
{
  assert(aFd->lower->methods->poll);
  return aFd->lower->methods->poll(aFd->lower, how_flags, p_out_flags);
}

static PRStatus
Http2ToSdtLayerConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  return fd->lower->methods->connect(fd->lower, addr, to);
}

static void
Http2ToSdtDtor(PRFileDesc *aFd)
{
  if (aFd->secret) {
    Http2ToSdt *handle = (Http2ToSdt *)(aFd->secret);
    delete handle;
    aFd->secret = nullptr;
  }
  PR_DELETE(aFd);
}

static PRDescIdentity Http2ToSdtIdentity;
static PRIOMethods Http2ToSdtMethods;

static int Http2ToSdt_once = 0;

void
Http2ToSdt_ensureInit()
{
  if (Http2ToSdt_once) {
    return;
  }
  Http2ToSdt_once = 1;

  Http2ToSdtIdentity = PR_GetUniqueIdentity("Http2ToSdtLayer");
  Http2ToSdtMethods = *PR_GetDefaultIOMethods();

  Http2ToSdtMethods.read = useRecv;
  Http2ToSdtMethods.recv = Http2ToSdtLayerRecv;
  Http2ToSdtMethods.recvfrom = notImplemented;
  Http2ToSdtMethods.write = Http2ToSdtLayerWrite;
  Http2ToSdtMethods.send = notImplemented2;
  Http2ToSdtMethods.sendto = notImplemented3;
  Http2ToSdtMethods.connect = Http2ToSdtLayerConnect;
  Http2ToSdtMethods.close = genericClose;
}

PRFileDesc *
sdt_addHttp2ToSdtLayer(PRFileDesc *aFd)
{
  Http2ToSdt_ensureInit();

  PRFileDesc *Http2ToSdtLayer = nullptr;
  Http2ToSdt *handle = new Http2ToSdt();

  Http2ToSdtLayer =
    PR_CreateIOLayerStub(Http2ToSdtIdentity, &Http2ToSdtMethods);

  if (!(aFd && Http2ToSdtLayer && handle)) {
    goto fail; // ha!
  }
  Http2ToSdtLayer->dtor = Http2ToSdtDtor;

  Http2ToSdtLayer->secret = (struct PRFilePrivate *)handle;

  if (PR_PushIOLayer(aFd, PR_GetLayersIdentity(aFd), Http2ToSdtLayer) ==
      PR_SUCCESS) {
    Http2ToSdtLayer = nullptr;
  } else {
    goto fail;
  }

  handle->SetFD(aFd);

  return aFd;

fail:
  PR_Close(aFd);
  if (Http2ToSdtLayer) {
    Http2ToSdtLayer->dtor(Http2ToSdtLayer);
  }
  return nullptr;
}
