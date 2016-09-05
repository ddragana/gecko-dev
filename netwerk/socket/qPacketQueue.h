/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <stdlib.h>

#define NUM_RETRANSMIT_IDS 3

struct id_t
{
  uint16_t mEpoch;
  uint64_t mSeq;
  PRIntervalTime mSentTime;
};

struct aPacket_t
{
  uint32_t mSize;
  // All ids that this packet is sent with.
  uint64_t mOriginalId; // I used this only for debugging.
  struct id_t mIds[NUM_RETRANSMIT_IDS];
  uint32_t mIdsNum;
  uint8_t mForRetransmission;
  uint8_t mIsPingPkt;
  struct aPacket_t *mNext;
  // the buffer lives at the end of the struct
};

struct aPacketQueue_t
{
  struct aPacket_t *mFirst, *mLast;
  uint32_t mLen;
};

void PacketQueueAddNew(struct aPacketQueue_t *queue, struct aPacket_t *pkt)
{
  pkt->mNext = NULL;
  if (queue->mLen) {
    assert(queue->mFirst);
    assert(queue->mLast);
    assert(!queue->mLast->mNext);
    queue->mLast->mNext = pkt;
    queue->mLast = pkt;
  } else {
    assert(!queue->mFirst);
    assert(!queue->mLast);
    queue->mLast = pkt;
    queue->mFirst = pkt;
  }
  ++queue->mLen;
}

struct aPacket_t *
PacketQueueRemoveFirstPkt(struct aPacketQueue_t *queue)
{
  if (!queue->mFirst) {
    return NULL;
  }

  struct aPacket_t *done = queue->mFirst;
  if (queue->mLast == done) {
    queue->mLast = NULL;
  }
  queue->mFirst = done->mNext;
  --queue->mLen;
  done->mNext = NULL;
  return done;
}

struct aPacket_t *
PacketQueueRemovePktWithId(struct aPacketQueue_t *queue, uint64_t id)
{
  if (!queue->mFirst) {
    return NULL;
  }

  struct aPacket_t *curr = queue->mFirst;
  struct aPacket_t *prev = NULL;

  while (curr) {
    for (uint32_t i = 0; i < curr->mIdsNum; i++) {
      if (curr->mIds[i].mSeq == id) {
        if (prev) {
          prev->mNext = curr->mNext;
        } else {
          queue->mFirst = curr->mNext;
        }
        if (!curr->mNext) {
          queue->mLast = prev;
        }
        curr->mNext = NULL;
        queue->mLen--;
        return curr;
      }
    }
    prev = curr;
    curr = curr->mNext;
  }
  return NULL;
}


void
PacketQueueRemoveAll(struct aPacketQueue_t *queue)
{
  if (!queue->mFirst) {
    return;
  }

  struct aPacket_t *curr = queue->mFirst;
  struct aPacket_t *done;
  while (curr) {
    done = curr;
    curr = curr->mNext;
    free(done);
  }
  queue->mFirst = queue->mLast = NULL;
  queue->mLen = 0;
}
