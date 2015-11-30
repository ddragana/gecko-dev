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
  int32_t sz;
  // All ids that this packet is sent with.
  struct id_t mIds[NUM_RETRANSMIT_IDS];
  uint32_t mIdsNum;
  uint8_t mForRetransmission;
  struct aPacket_t *mNext;
  // the buffer lives at the end of the struct
};

struct aPacketQueue_t
{
  struct aPacket_t *mFirst, *mLast;
  uint32_t mLen;
};

int PacketQueueAddNew(struct aPacketQueue_t *aQueue, struct aPacket_t *aPkt)
{
  aPkt->mNext = NULL;
  if (aQueue->mLen) {
    assert(aQueue->mFirst);
    assert(aQueue->mLast);
    assert(!aQueue->mLast->mNext);
    aQueue->mLast->mNext = aPkt;
    aQueue->mLast = aPkt;
  } else {
    assert(!aQueue->mFirst);
    assert(!aQueue->mLast);
    aQueue->mLast = aPkt;
    aQueue->mFirst = aPkt;
  }
  ++aQueue->mLen;
}

struct aPacket_t *
PacketQueueRemoveFirstPkt(struct aPacketQueue_t *aQueue)
{
  if (!aQueue->mFirst) {
    return NULL;
  }

  struct aPacket_t *done = aQueue->mFirst;
  if (aQueue->mLast == done) {
    aQueue->mLast = NULL;
  }
  aQueue->mFirst = done->mNext;
  --aQueue->mLen;
  done->mNext = NULL;
  return done;
}

struct aPacket_t *
PacketQueueRemovePktWithId(struct aPacketQueue_t *aQueue, uint64_t aId)
{
  if (!aQueue->mFirst) {
    return NULL;
  }

  struct aPacket_t *curr = aQueue->mFirst;
  struct aPacket_t *prev = NULL;
  uint8_t found = 0;
  while (curr) {
    for (int i = 0; i < curr->mIdsNum; i++) {
      if (curr->mIds[i].mSeq == aId) {
        if (prev) {
          prev->mNext = curr->mNext;
        } else {
          aQueue->mFirst = curr->mNext;
        }
        if (!curr->mNext) {
          aQueue->mLast = prev;
        }
        curr->mNext = NULL;
        aQueue->mLen--;
        return curr;
      }
    }
    prev = curr;
    curr = curr->mNext;
  }
  return NULL;
}


void
PacketQueueRemoveAll(struct aPacketQueue_t *aQueue)
{
  if (!aQueue->mFirst) {
    return NULL;
  }

  struct aPacket_t *curr = aQueue->mFirst;
  struct aPacket_t *done;
  while (curr) {
    done = curr;
    curr = curr->mNext;
    free(done);
  }
  aQueue->mFirst = aQueue->mLast = NULL;
  aQueue->mLen = 0;
}
