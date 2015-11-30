/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "nspr.h"
#include "prerror.h"
#include "prio.h"
#include "sdt.h"
#include "ssl.h"
#include "unistd.h"

#include "qPacketQueue.h"
#include "sdt_common.h"


// TODO connection reusing

/*
an SDT Socket

A deal with ack info, retransmisions
Q queuelayer (pacing, congestion control, etc..)
C cryptolayer (dtls)
S layer - This implementation uses sequence number from DTLS. S layer is under
          DTLS layer and is responsible remembering sequence number of outgoing
          and incoming packets.

on write -
A nop
Q queues (and manages timers) or sends to network - TODO still missing, I have not deleted functions from Patrick's implementation, but they are never called.
C applies ciphers (dtls from nss)
S read sequence number from DTLS header and store it in packet info of the
  outgoing packet

on read -
S (epoch, seq, etc..) read DTLS sequence number and update structure that
  keeps info about received packets. This structure is use for forming ACKs.
C decrypt (dlts from nss)
Q nop
A The packet can be data or ACK. If it is ACK remove from retransmission queue
  the packets that the ACK is acking, check for retransmissions, FACK(TODO).
  If it is a data packet, make and send an ACK and send data to upper layer.

TODO add session identifier for mobility.

// TODO sdtlib-internal.h

/* There is an unfortunate amount of standalone (non reuse) C going on in here
   in the hope of maximum reusability. this might actually be a good candidate
   for a different runtime (rust?) and a c ABI layer. (can go do that?) But that's
   premature compared to working on the basics of the protocol atm. */

#define DTLS_TYPE_CHANGE_CIPHER 20
#define DTLS_TYPE_ALERT         21
#define DTLS_TYPE_HANDSHAKE     22
#define DTLS_TYPE_DATA          23

#define HTTP2SDT_HEADER 17

// DEV_ABORT's might actually happen in the wild, but in the lab are more
// likely to be a bug.. so we will abort on them for now, but they need a
// runtime error path too.
#if 1
#define DEV_ABORT(x) do { abort(); } while (0)
#else
#define DEV_ABORT(x) do { } while (0)
#endif
#define nullptr 0

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

#if 0
// DRAGANA: DTLS layer is set in the similar way as a TLS layer so question
// down should have the same answer as any TLS session in FF, except caching which connection over sdt were successful. Proxy needs to be fix.
  // how does auth work here?
  // sni? session caching? alpn? allowable suites?
  // can tls for https be removed if e2e?
#endif

static uint32_t aBufferLenMax = 128; // number of queued packets

// our standard time unit is a microsecond
static uint64_t qMaxCreditsDefault = 80000; // ums worth of full bucket
static uint64_t qPacingRateDefault =  5000; // send every 2ms (2000ums)

#define DUPACK_THRESH 3
#define EARLY_RETRANSMIT_FACTOR 0.25

#define MAX_RTO 60000 // 60s
#define MIN_RTO 1000 // 1s

static PRIntervalTime sMinRTO; // MinRTO in interval that we do not need to convert it each time.
static PRIntervalTime sMaxRTO; // MaxRTO in interval that we do not need to convert it each time.

#define RTO_FACTOR 4
#define RTT_FACTOR_ALPHA 0.125
#define RTT_FACTOR_BETA 0.25

static uint32_t amplificationPacket = 2;

void
LogBuffer(const char *label, const char *data, uint32_t datalen)
{
  // Max line is (16 * 3) + 10(prefix) + newline + null
  char linebuf[128];
  uint32_t index;
  char *line = linebuf;

  linebuf[127] = 0;
  fprintf(stderr,"%s \n", label);
  for (index = 0; index < datalen; ++index) {
    if (!(index % 16)) {
      if (index) {
        *line = 0;
        fprintf(stderr,"%s\n", linebuf);
      }
      line = linebuf;
      snprintf(line, 128, "%08X: ", index);
      line += 10;
    }
    snprintf(line, 128 - (line - linebuf), "%02X ",
             ((const uint8_t *)(data))[index]);
    line += 3;
  }
  if (index) {
    *line = 0;
    fprintf(stderr,"%s\n", linebuf);
  }
}

struct range_t
{
  uint64_t mStart;
  uint64_t mEnd;
  struct range_t *mNext;
};

enum SDTConnectionState {
  SDT_CONNECTING, // Until DTLS handshake finishes
  SDT_TRANSFERRING,
  SDT_CLOSING
};

struct sdt_t
{
  uint64_t connectionId; // session identifier for mobility. TODO not use now.

  PRNetAddr peer;
  uint8_t isConnected;
  uint8_t isServer;

  enum SDTConnectionState state;

  // Not yet transmitted.
  struct aPacketQueue_t aTransmissionQueue;
  // Transmitted not acked.
  struct aPacketQueue_t aRetransmissionQueue;

  // Pkt currently being transferred. This is used for the communication between
  // a and s layer: 1) if it is NULL it is an ack or DTLS handshake packet.
  //                2) not NULL it is new packet or a retransmission.
  struct aPacket_t *aPktTransmit;

  // Max number of outstanding packets (sender buffer size)
  uint32_t mMaxBufferedPkt;

  uint64_t aLargestAcked;

  struct range_t *aRecvAckRange; // We are keeping track of the ack ranges that
                                 // a sender has already received from the
                                 // receiver. So we can search
                                 // aRetransmissionQueue only for a diff.
                                 // These are actually ACKed(SACK) ranges not
                                 // NACKed!!! (easier to compare, even though
                                 // we get NACK ranges in an ACK)

  // TODO add this.
  // Let's keep track of acks so that we do not need to go though
  // aRetransmissionQueue for nacked acks. They are not in queue so that will cause the search ti go through the whole queue.
//  uint64_t ackStart; // this is the lowest.
//  unsigned char acks[SDT_REPLAY_WINDOW / 8];

  // Keep track of the largest sent id. This is needed for Early
  // Retransmissions.
  uint8_t aLargestSentEpoch;
  uint64_t aLargestSentId;

  // When a packet is received on slayer we record epoch, seq. number and
  // time.
  uint8_t  sRecvRecordType;
  uint16_t sRecvEpoch;
  uint16_t sRecvDtlsLen;
  uint64_t sRecvSeq;
  uint64_t sBytesRead;
  uint8_t sRecvNewPkt;

  // We always get the whole packet from the network.
  uint8_t aLayerBuffer[SDT_CLEARTEXTPAYLOADSIZE];
  uint32_t aLayerBufferLen;
  uint32_t aLayerBufferUsed;

  // This is for received packet
  uint8_t aLargestRecvEpoch;
  uint64_t aLargestRecvId;
  PRIntervalTime aLargestRecvTime;
  uint8_t aNumTimeStamps;
  uint64_t aTSSeqNums[10];
  // TODO we can also get rtt for acks, currently partially implemented. Acks
  // have different pkt size, maybe use that. (if we do not need it easy to fix this)
  // We keep last 10 timestamps and this is array is used as a ring.
  PRIntervalTime aTimestamps[10];
  struct range_t *aNackRange; // NACK ranges to send in a ACK

  PRIntervalTime aNextToRetransmit;

  PRIntervalTime srtt;
  PRIntervalTime rttvar;
  PRIntervalTime minrtt;
  PRIntervalTime rto;
  uint8_t waitForFirstAck;

  PRIntervalTime RTOTimer; // TODO
  uint8_t RTOTimerSet;

  PRIntervalTime ERTimer; // TODO
  uint8_t ERTimerSet;

  PRTime qLastCredit;
  // credits are key in ums
  uint64_t qCredits;
  uint64_t qMaxCredits;
  uint64_t qPacingRate;

  PRFileDesc *fd; // weak ptr, dont close
};

struct sdt_t *sdt_newHandle()
{
  struct sdt_t *handle = (struct sdt_t *) malloc (sizeof(struct sdt_t));
  memset(handle, 0, sizeof(struct sdt_t));

  handle->state = SDT_CONNECTING;

  handle->aTransmissionQueue.mLen = 0;
  handle->aTransmissionQueue.mFirst = nullptr;
  handle->aTransmissionQueue.mLast = nullptr;
  handle->aRetransmissionQueue.mLen = 0;
  handle->aRetransmissionQueue.mFirst = nullptr;
  handle->aRetransmissionQueue.mLast = nullptr;
  handle->mMaxBufferedPkt = aBufferLenMax;

  handle->aLargestAcked = 0;

  handle->aLargestSentEpoch = 0;
  handle->aLargestSentId = 0;

  handle->connectionId = 0;

  handle->aLayerBufferLen = 0;
  handle->aLayerBufferUsed = 0;

  handle->aLargestRecvEpoch = 0;
  handle->aLargestRecvId = 0;
  handle->aLargestRecvTime = 0;
  handle->aNumTimeStamps = 0;
  handle->aNackRange = nullptr;
  handle->aNextToRetransmit = 0xffffffffUL;

  handle->srtt = 0;
  handle->rttvar = 0;
  handle->minrtt = 0;
  handle->rto = sMinRTO;
fprintf(stderr, "sMinRTO %d %d", sMinRTO, PR_IntervalToSeconds(sMinRTO));
  handle->waitForFirstAck = 1;

  handle->RTOTimer = 0;
  handle->RTOTimerSet = 0;

  handle->ERTimer = 0;
  handle->ERTimerSet = 0;

  handle->qMaxCredits = qMaxCreditsDefault;
  handle->qMaxCredits = qPacingRateDefault * 3; // TODO: not use currently
  handle->qPacingRate = qPacingRateDefault;

  return handle;
}

static void
sdt_freeHandle(struct sdt_t *handle)
{
  
  PacketQueueRemoveAll(&handle->aTransmissionQueue);
  PacketQueueRemoveAll(&handle->aRetransmissionQueue);
  struct range_t *curr = handle->aRecvAckRange;
  struct range_t *done;
  while (curr) {
    done = curr;
    curr = curr->mNext;
    free(done);
  }
  curr = handle->aNackRange;
  while (curr) {
    done = curr;
    curr = curr->mNext;
    free(done);
  }
  // TODO delete queued packets...
  free(handle);
}

static unsigned int
sdt_preprocess(struct sdt_t *handle,
               unsigned char *pkt, uint32_t len)
{
  if (len < (11)) {
    DEV_ABORT();
    return 0;
  }

  // sanity check dtls 1.0, 1.1, or 1.2
  if (!((pkt[1] == 0xFE) && (pkt[2] >= 0xFD))) {
    DEV_ABORT();
    return 0;
  }

  // the leading bytes of a dlts record format are 1 byte of type, 2 of tls
  // version, and 64 bits of sequence number

  handle->sRecvRecordType = pkt[0];
  memcpy (&handle->sRecvEpoch, pkt + 3, 2);
  handle->sRecvEpoch = ntohs(handle->sRecvEpoch);

  memcpy (&handle->sRecvSeq, pkt + 7, 4);
  handle->sRecvSeq = ntohl(handle->sRecvSeq);
  handle->sRecvSeq += ((uint64_t)pkt[5]) << 40;
  handle->sRecvSeq += ((uint64_t)pkt[6]) << 32;

  memcpy (&handle->sRecvDtlsLen, pkt + 11, 2);
  handle->sRecvDtlsLen = ntohs(handle->sRecvDtlsLen);

  // we don't allow renogitation which is implied by epoch > 1
  if (handle->sRecvEpoch > 1) {
    DEV_ABORT();
    return 0;
  }
  if (!handle->sRecvEpoch && (handle->sRecvRecordType == DTLS_TYPE_DATA)) {
    // we should only be handshaking in epoch 0
    DEV_ABORT();
    return 0;
  }

  return 1;
}

static PRDescIdentity qIdentity;
static PRDescIdentity sIdentity;
static PRDescIdentity aIdentity;

static PRIOMethods qMethods;
static PRIOMethods sMethods;
static PRIOMethods aMethods;

uint8_t
sLayerPacketReceived(struct sdt_t *handle, uint16_t aEpoch, uint64_t aSeq)
{
  uint8_t newPkt = 0;

  if (handle->aLargestRecvEpoch < aEpoch) {
    handle->aLargestRecvEpoch = aEpoch;
  }

  fprintf(stderr, "sLayerPacketReceived largest receive till now=%d; this "
                  "packet seq=%d handle=%p\n", handle->aLargestRecvId, aSeq,
                  handle);

  PRIntervalTime now = PR_IntervalNow();

  if (handle->aLargestRecvId < aSeq) {
    if ((handle->aLargestRecvId + 1) < aSeq) {

      // there is some packets missing between last largest and the new largest
      // packet id.
      struct range_t *range = (struct range_t *)malloc(sizeof(struct range_t));
      range->mStart = handle->aLargestRecvId + 1;
      range->mEnd = aSeq - 1;
      range->mNext = handle->aNackRange;
      handle->aNackRange = range;
    }
    handle->aLargestRecvId = aSeq;
    handle->aLargestRecvTime = now;
    newPkt = 1;

  } else {
    struct range_t* curr = handle->aNackRange;
    struct range_t* prev = nullptr;
    // Ranges are ordered largerId towards smaller
    while (curr && (curr->mStart > aSeq)) {
      prev = curr;
      curr = curr->mNext;
    }

    if (!curr || (curr->mEnd < aSeq)) {
      // Duplicate just ignore it.
      newPkt = 0;

    } else {
      // This packet was NACK previously
      if ((curr->mStart == aSeq) || (curr->mEnd == aSeq)) {
        if (curr->mStart != curr->mEnd) {
          if (curr->mStart == aSeq) {
            curr->mStart = aSeq + 1;
          } else {
            curr->mEnd = aSeq - 1;
          }
        } else {
          // This is the only missing packet in a range, delete the range.
          if (prev) {
            prev->mNext = curr->mNext;
          } else {
            handle->aNackRange = curr->mNext;
          }
          free(curr);
        }
      } else {
        // Split the range.
        struct range_t *newRange =
          (struct range_t *) malloc (sizeof(struct range_t));
        newRange->mStart = aSeq + 1;
        newRange->mEnd = curr->mEnd;
        curr->mEnd = aSeq -1;
        newRange->mNext = curr;
        if (prev) {
          prev->mNext = newRange;
        } else {
          handle->aNackRange = newRange;
        }
      }

      newPkt = 1;
    }
  }
  if (newPkt) {
    handle->aTSSeqNums[handle->aNumTimeStamps % 10] = aSeq;
    handle->aTimestamps[handle->aNumTimeStamps % 10] = now;
    handle->aNumTimeStamps++;
    handle->aNumTimeStamps = (handle->aNumTimeStamps == 20) ?
     10 : handle->aNumTimeStamps;
    handle->sRecvNewPkt = 1;
  }
  return newPkt;
}

static int32_t
sLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
           int flags, PRIntervalTime to)
{
  int32_t rv = aFD->lower->methods->recv(aFD->lower, aBuf, aAmount, flags, to);

  if (rv < 0) {
    return rv;
  }

  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  handle->sBytesRead += rv;
  if (!sdt_preprocess(handle, aBuf, rv)) {
    assert(0);
    return -1;
  }

  fprintf(stderr,"sLayer Recv got %d of ciphertext this=%p "
          "type=%d epoch=%X seq=0x%lX dtlsLen=%d sBytesRead=%ld\n", rv, handle,
          handle->sRecvRecordType, handle->sRecvEpoch, handle->sRecvSeq,
          handle->sRecvDtlsLen, handle->sBytesRead);

  if (handle->sRecvEpoch != 0) {
    uint8_t newPkt = sLayerPacketReceived(handle, handle->sRecvEpoch,
                                          handle->sRecvSeq);
    if (!newPkt) {
      PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
      rv = -1;
    }
  }

  return rv;
}

static int32_t
sLayerSendTo(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
             int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }
  addr = &(handle->peer);

  if (aAmount > SDT_PAYLOADSIZE) {
    DEV_ABORT();
    // todo set error
    return -1;
  }


//TODO: TEST
  uint32_t epoch;
  memcpy (&epoch, aBuf + 3, 2);
  epoch = ntohs(epoch);
  uint64_t id;
  memcpy (&id, aBuf + 7, 4);
  id = ntohl(id);
  id += ((uint64_t)((uint8_t*)aBuf)[5]) << 40;
  id += ((uint64_t)((uint8_t*)aBuf)[6]) << 32;
 
int rv;
//if ((u64 == 2) && (u32 == 1)) {
//rv = aAmount;
//} else {
  rv = aFD->lower->methods->sendto(aFD->lower, aBuf, aAmount, flags, addr, to);
//}

  fprintf(stderr,"sLayer send %p %d rv=%d\n", handle,
          aAmount, rv);

  if (rv < 0) {
    return -1;
  }

  if (rv < (aAmount)) {
    DEV_ABORT();
    // todo set err
    return -1;
  }

  if (((((uint8_t*)aBuf)[0]) != DTLS_TYPE_DATA) ||
      (!handle->aPktTransmit)) {
    //It is ACK or DTLS handshake packet.
    return aAmount;
  }

  // Remember last 3 Ids. TODO: 2 is enough
  if (handle->aPktTransmit->mIdsNum == NUM_RETRANSMIT_IDS) {
    for (int i = 0; i < NUM_RETRANSMIT_IDS -1; i++) {
      handle->aPktTransmit->mIds[i] = handle->aPktTransmit->mIds[i + 1];
    }
    handle->aPktTransmit->mIdsNum--;
  }

  assert(handle->aPktTransmit->mIdsNum < NUM_RETRANSMIT_IDS);
  int inx = handle->aPktTransmit->mIdsNum++;

//fprintf(stderr, "sLayer send IDNUM %p %d\n", handle->aPktTransmit, handle->aPktTransmit->mIdsNum);

  handle->aPktTransmit->mIds[inx].mEpoch = epoch;
  handle->aPktTransmit->mIds[inx].mSeq = id;
  handle->aPktTransmit->mIds[inx].mSentTime = PR_IntervalNow();

  handle->aLargestSentEpoch = epoch;
  handle->aLargestSentId = id;

//fprintf(stderr, "Send id: %lu time: %u pkt: %p inx: %d\n", handle->aPktTransmit->mIds[inx].mSeq, handle->aPktTransmit->mIds[inx].mSentTime, handle->aPktTransmit, inx);

  return aAmount;
}

uint8_t
DoWeNeedToSendAck(struct sdt_t *handle)
{
  // TODO: Decide when we are going to send ack, for each new packet probably,
  // but maybe implement delayACK as well.
  return handle->sRecvNewPkt;
}

struct aPacket_t *
MakeAckPkt(struct sdt_t *handle)
{
  // TODO: For now we are always sanding as much as it can fit in a pkt.
  // To fix:
  // 1) Make possible to send multiple packets if the ack info does not fit
  //    into one.
  // 2) implement STOP_WAITING
  // 3) if number of consecutive lost packet exceed 256, current implementation
  //    will fail. make continues ranges.

  struct aPacket_t *pkt = (struct aPacket_t *)malloc(sizeof(struct aPacket_t) +
                                                     SDT_CLEARTEXTPAYLOADSIZE);
  pkt->mIdsNum = 0;
  pkt->mNext = nullptr;
  pkt->mForRetransmission = 0;
  unsigned char *buf = (unsigned char *)(pkt + 1);

  buf[0] = 0x40;
  buf[1] = 0;
  uint64_t num64 = htonll(handle->aLargestRecvId);

  memcpy(buf + 2, &num64, 8);
  // TODO: fix this. (hint: largestReceicved time delta)
  uint32_t num32 = htonl(PR_IntervalToMicroseconds(PR_IntervalNow() - handle->aLargestRecvTime));
  memcpy(buf + 10, &num32, 4);
  uint8_t numTS = 0;
  uint32_t offset = 15;
  int i = handle->aNumTimeStamps - 1;
  int prevInx;
  for (; i >= 0 && i >= handle->aNumTimeStamps - 10; i--) {
    int inx = i % 10;
    if ((handle->aLargestRecvId - handle->aTSSeqNums[inx]) < 255) {
      buf[offset] = (uint8_t)(handle->aLargestRecvId - handle->aTSSeqNums[inx]);
      offset++;
      if (!numTS) {
        num32 = htonl(PR_IntervalToMicroseconds(PR_IntervalNow() -
                                                handle->aTimestamps[inx]));
      } else {
        num32 = htonl(PR_IntervalToMicroseconds(handle->aTimestamps[prevInx] -
                                                handle->aTimestamps[inx]));
      }
//fprintf(stderr, "MakeAck last %d %d %d %d %d %d\n", handle->aLargestRecvId, handle->aTSSeqNums[inx], ntohl(num32), i, handle->aNumTimeStamps, numTS);
      memcpy(buf + offset, &num32, 4);
      offset += 4;
      prevInx = inx;
      numTS++;
    }
  }
  buf[14] = numTS;
  uint8_t numR = 0;
  if (handle->aNackRange) {
    uint32_t offsetRangeNum = offset;
    offset++;
    buf[0] = 0x60;
    struct range_t *curr = handle->aNackRange;
    struct range_t *prev = nullptr;
    uint32_t continuesLeft = 0;
    while (curr && (offset < (SDT_CLEARTEXTPAYLOADSIZE - 9))) {
      if (!numR) {
        num64 = htonll(handle->aLargestRecvId - curr->mEnd);
      } else if (!continuesLeft) {
        num64 = htonll(prev->mStart - curr->mEnd - 1);
      } else {
        num64 = 0;
      }
//fprintf(stderr, "MakeAck range %lu %lu\n", curr->mStart, curr->mEnd);
      memcpy(buf + offset, &num64, 8);
      offset += 8;
      uint64_t rangeLength = (!continuesLeft) ? curr->mEnd - curr->mStart :
                                                continuesLeft;
      if (rangeLength > 256) {
        buf[offset] = 255;
        continuesLeft = rangeLength - 256;
      } else {
        buf[offset] = (uint8_t)(rangeLength);
        prev = curr;
        curr = curr->mNext;
      }
      numR++;
      offset++;
    }
    buf[offsetRangeNum] = numR;
  }
  handle->sRecvNewPkt = 0;
  pkt->sz = offset;
  return pkt;
}

// r is timeRecv - timeSent and delay is delay at receiver
// srtt uses r and minrtt uses clean rtt r - delay. minrtt still not used,
// maybe not needed, it is from quic.
void
CalculateRTT(struct sdt_t *handle, PRIntervalTime r, PRIntervalTime delay)
{
  // RFC 6298
  PRIntervalTime rwod = r - delay;
  if (handle->waitForFirstAck) {
    handle->waitForFirstAck = 0;
    handle->rttvar = r / 2;
    handle->srtt = r;
    handle->minrtt = rwod;

  } else {

    // Use this measurement only if delay is not greater than rtt.
    if (delay > handle->srtt) {
      return;
    }

    handle->rttvar = (1.0 - RTT_FACTOR_BETA) * handle->rttvar +
                     RTT_FACTOR_BETA * abs(handle->srtt - r);
    handle->srtt = (1.0 - RTT_FACTOR_ALPHA) * handle->srtt +
                   RTT_FACTOR_ALPHA * r;
    handle->minrtt = (1.0 - RTT_FACTOR_ALPHA) * handle->minrtt +
                     RTT_FACTOR_ALPHA * rwod;
  }
  handle->rto = handle->srtt + ((RTO_FACTOR * handle->rttvar) > 1) ?
                               (RTO_FACTOR * handle->rttvar) :
                               1;
  if (handle->rto < sMinRTO) {
    handle->rto = sMinRTO;
  }
  if (handle->rto > sMaxRTO) {
    handle->rto = sMaxRTO;
  }
}

void
MaybeStartRTOTimer(struct sdt_t *handle)
{
  if (!handle->RTOTimerSet) {
    handle->RTOTimerSet = 1;
    handle->RTOTimer = PR_IntervalNow() + handle->rto;
  }
}

void
StopRTOTimer(struct sdt_t *handle)
{
  handle->RTOTimerSet = 0;
}

void
RestartRTOTimer(struct sdt_t *handle)
{
  assert(handle->RTOTimerSet);
  handle->RTOTimer = PR_IntervalNow() + handle->rto;
}

uint8_t
RTOTimerExpired(struct sdt_t *handle, PRIntervalTime now)
{
  return (handle->RTOTimerSet && (handle->RTOTimer < now));
}

void
StartERTimer(struct sdt_t *handle)
{
  handle->ERTimerSet = 1;
  handle->ERTimer = PR_IntervalNow() + handle->srtt * EARLY_RETRANSMIT_FACTOR;
}

uint8_t
ERTimerExpired(struct sdt_t *handle, PRIntervalTime now)
{
  return (handle->ERTimerSet && (handle->ERTimer < now));
}

void
StopERTimer(struct sdt_t *handle)
{
  handle->ERTimerSet = 0;
}

void
NeedRetransmissionDupAck(struct sdt_t *handle)
{
  if (!handle->aTransmissionQueue.mFirst) {
    return 0;
  }

  fprintf(stderr, "NeedRetransmissionDupAck\n");

  struct aPacket_t *curr = handle->aRetransmissionQueue.mFirst;
  struct aPacket_t *prev = nullptr;

  while (curr && !curr->mForRetransmission &&
         (handle->aLargestAcked >= (curr->mIds[curr->mIdsNum - 1].mSeq +
                                    DUPACK_THRESH))) {

//fprintf(stderr, "Send id: %lu pkt: %p inx: %d \n", curr->mIds[curr->mIdsNum - 1].mSeq, curr, curr->mIdsNum);

    curr->mForRetransmission = 1;
    prev = curr;
    curr = curr->mNext;
  }
}

int8_t
NeedToSendRetransmit(struct sdt_t *handle)
{
  return handle->aRetransmissionQueue.mFirst &&
         handle->aRetransmissionQueue.mFirst->mForRetransmission;
}

int
RemoveRange(struct sdt_t *handle, uint64_t aStart, uint64_t aEnd, int aNumTS,
            uint32_t *aTsDelay, uint64_t *aTsSeqno)
{
  // This function removes range of newly acked packets and updates rtt, rto.

  assert(aEnd >= aStart);
  // TODO keep track of ACK packets. Because acks are not in retransmission
  // queue search will need to through the whole queue.
  int rv = 0;
  struct aPacket_t *pkt;
  for (int i = aStart; i <= aEnd; i++) {
    pkt = PacketQueueRemovePktWithId(&handle->aRetransmissionQueue, i);

    // We are also acking acks so maybe there is no pkt
    if (pkt) {
      rv = 1;
      // I expect that numTS should be really small 1-2 (currently it is 10 :)),
      // so this is not that slow and pkt->mIdsNum is in 99.99% of the cases
      // only 1.
      // TODO: this can be optimize  by preprocessing tsDelay and tsSeqno.
      int ts = 0;
      uint8_t found = 0;
      while (!found && ts < aNumTS) {
        // Use this measurement only if delay is not greater than rtt.
        if (aTsDelay[ts] < handle->srtt) {
          for (int id = 0; id < pkt->mIdsNum; id++) {
            if (pkt->mIds[id].mSeq == aTsSeqno[ts]) {

              CalculateRTT(handle,
                           ntohl(PR_IntervalNow() - pkt->mIds[id].mSentTime),
                           aTsDelay[ts]);
              found = 1;
              break;
            }
          }
        }
        ts++;
      }
      free(pkt);
    }
  }
  return rv;
}

static void
RecvAck(struct sdt_t *handle)
{
  fprintf(stderr, "RecvAck [this=%p]\n", handle);

  assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= 15);

  uint8_t newlyAcked = 0;

  uint8_t hasRanges = (handle->aLayerBuffer[handle->aLayerBufferUsed] == 0x60);
  uint64_t largestRecv;

  // Frame type and reveived entropy (reveived entropy not implemented)
  handle->aLayerBufferUsed += 2;

  // The largest received
  memcpy(&largestRecv, handle->aLayerBuffer + handle->aLayerBufferUsed, 8);
  largestRecv = ntohll(largestRecv);
  handle->aLayerBufferUsed += 8;

  if (handle->aLargestAcked > largestRecv) {
    // Out of order ack!!! Ignore it.
    handle->aLayerBufferUsed += 4;
    uint8_t numTS = handle->aLayerBuffer[handle->aLayerBufferUsed];
    handle->aLayerBufferUsed += numTS * 5 + 1;
    if (hasRanges) {
      uint8_t numR = handle->aLayerBuffer[handle->aLayerBufferUsed]; // number of ranges.
      handle->aLayerBufferUsed += numR * 9 + 1;
    }
    return;
  }

  // Not sure about this.
  handle->aLayerBufferUsed += 4; // Delay at the receiver of the largest observed.

  // Timestamps
  uint8_t numTS =   handle->aLayerBuffer[handle->aLayerBufferUsed];
  assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >=
         (1 + numTS * 5));

  handle->aLayerBufferUsed += 1; // Number of timestamps.
  uint64_t tsSeqno[numTS];
  int32_t tsDelay[numTS];
  for (int i = 0; i < numTS; i++) {
    uint8_t delta = handle->aLayerBuffer[handle->aLayerBufferUsed];
    handle->aLayerBufferUsed += 1;
    assert(delta <= largestRecv); // TODO change this.

    tsSeqno[i] = largestRecv - delta;
    memcpy(&tsDelay[i], handle->aLayerBuffer + handle->aLayerBufferUsed, 4);
    tsDelay[i] = ntohl(tsDelay[i]);

    if (i) {
      tsDelay[i] += tsDelay[i - 1];
      assert(tsDelay[i] >= 0); //TODO for debug it is ok, but change this later.
    }
    tsDelay[i] = PR_MicrosecondsToInterval(tsDelay[i]);

    handle->aLayerBufferUsed += 4; // Delay at the receiver.
  }

  if (!hasRanges) {
    // No ranges

    if (handle->aLargestAcked == largestRecv) {
      // dup!!!
      return;
    }

    newlyAcked = RemoveRange(handle, handle->aLargestAcked + 1, largestRecv,
                             numTS, tsDelay,
                tsSeqno); 
    handle->aLargestAcked = largestRecv;
  } else {

    assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= 1);
    uint8_t numR = handle->aLayerBuffer[handle->aLayerBufferUsed]; // number of ranges.
    handle->aLayerBufferUsed += 1;

    assert((handle->aLayerBufferLen - handle->aLayerBufferUsed) >= (numR * 9));

    uint64_t num64;
    uint64_t recvRangeStart = largestRecv;
    uint64_t recvRangeEnd = 0;
    uint8_t continueRange = 0; // TODO Not tested.
    struct range_t newRanges[numR + 1];

    int ranges = 0;
    for (int i = 0; i < numR; i++) {

      memcpy(&num64, handle->aLayerBuffer + handle->aLayerBufferUsed, 8);
      handle->aLayerBufferUsed += 8;

      assert(recvRangeStart >= ntohll(num64));

      if (num64 != 0) {
        recvRangeEnd = recvRangeStart - ntohll(num64) + 1;

        newRanges[ranges].mStart = recvRangeStart;
        newRanges[ranges].mEnd = recvRangeEnd;
        ranges++;
        recvRangeStart = recvRangeEnd -
                         handle->aLayerBuffer[handle->aLayerBufferUsed] - 2;
      } else {
        recvRangeStart -= (handle->aLayerBuffer[handle->aLayerBufferUsed] + 1);
      }
      handle->aLayerBufferUsed++;
fprintf(stderr, "RECVACK %lu %lu \n", recvRangeStart, recvRangeEnd);
    }
    newRanges[ranges].mStart = recvRangeStart;
    newRanges[ranges].mEnd = 0;
    ranges++;

    // Compare new and old ranges.
    struct range_t *curr = handle->aRecvAckRange;
    if (!curr) {
      // There was no NACK till now.
      curr = (struct range_t *) malloc (sizeof(struct range_t));
      curr->mNext = nullptr;
      curr->mStart = handle->aLargestAcked;
      curr->mEnd = 0;
      handle->aRecvAckRange = curr;
    }
    struct range_t *prev = nullptr;

    for (int i = 0; i < ranges; i++) {
fprintf(stderr, "RECVACK1 %lu %lu %lu %lu\n", newRanges[i].mStart, newRanges[i].mEnd, curr->mStart, curr->mEnd);
      if ((newRanges[i].mStart == curr->mStart) &&
          (newRanges[i].mEnd == curr->mEnd)) {
        // The old one.
        prev = curr;
        curr = curr->mNext;
      } else if (newRanges[i].mEnd > curr->mStart) {
        // completly new one.
        int rv = RemoveRange(handle, newRanges[i].mStart, newRanges[i].mEnd,
                             numTS, tsDelay, tsSeqno);
        newlyAcked |= rv;
        struct range_t *newRange = (struct range_t *) malloc (sizeof(struct range_t));
        newRange->mStart = newRanges[i].mStart;
        newRange->mEnd = newRanges[i].mEnd;
        newRange->mNext = curr;
        if (prev) {
          prev->mNext = newRange;
        } else {
          handle->aRecvAckRange = newRange;
        }
      } else {
        // NO nacks of ack packet accepted!!!
        assert(newRanges[i].mStart >= curr->mStart); 
        assert(newRanges[i].mEnd <= curr->mEnd);

        if (newRanges[i].mStart > curr->mStart) {
          int rv = RemoveRange(handle, newRanges[i].mStart, curr->mStart,
                               numTS, tsDelay, tsSeqno);
          curr->mStart = newRanges[i].mStart;
        }

        if (newRanges[i].mEnd < curr->mEnd) {
          struct range_t *nextR = curr->mNext;
          assert(nextR); // The last one ends at 0 so this
          while (newRanges[i].mEnd < nextR->mEnd) {

            if (nextR->mStart > newRanges[i].mEnd) {
              // merge 2 ranges
              int rv = RemoveRange(handle, curr->mEnd, nextR->mStart,
                                   numTS, tsDelay, tsSeqno);
              newlyAcked |= rv;
              curr->mEnd =  nextR->mEnd;
              curr->mNext = nextR->mNext;
              free(nextR);
            }
          }
        }
        if (newRanges[i].mEnd < curr->mEnd) {
          int rv = RemoveRange(handle, curr->mEnd, newRanges[i].mEnd, numTS,
                               tsDelay, tsSeqno);
          newlyAcked |= rv;
          curr->mEnd = newRanges[i].mEnd;
        }
        prev = curr;
        curr = curr->mNext;
      }
    }
    handle->aLargestAcked = largestRecv;
  }

  if (handle->aLayerBufferLen == handle->aLayerBufferUsed) {
    handle->aLayerBufferLen = handle->aLayerBufferUsed = 0;
  }

  if (newlyAcked) {
    NeedRetransmissionDupAck(handle);
  }

  if (newlyAcked && (handle->aRetransmissionQueue.mLen == 0)) {
    // All packets are acked stop RTO timer.
    StopRTOTimer(handle);
    StopERTimer(handle);
  } else if (newlyAcked) {
    // Some new packet(s) are acked - restart rto timer.
    RestartRTOTimer(handle);
  }

  if ((handle->aRetransmissionQueue.mLen) &&
      (handle->aLargestSentId == handle->aLargestAcked)) {
    StartERTimer(handle);
  }
}

void
CheckRetransmissionTimers(struct sdt_t *handle)
{
  if (ERTimerExpired(handle, PR_IntervalNow())) {
    fprintf(stderr, "ERTimerExpired\n");
    assert(handle->aRetransmissionQueue.mFirst);
    handle->aRetransmissionQueue.mFirst->mForRetransmission = 1;
    StopERTimer(handle);

  } else if (RTOTimerExpired(handle, PR_IntervalNow())) {
    fprintf(stderr, "RTOTimerExpired\n");
    assert(handle->aRetransmissionQueue.mFirst);
    struct aPacket_t *curr = handle->aRetransmissionQueue.mFirst;
    // Mare all for retransmission.
    while (curr) {
      curr->mForRetransmission = 1;
      curr = curr->mNext;
    }
    handle->rto *= 2;
    // This is a bit incorrect, but it is ok. We  should restart it when we do
    // resend this pkt.
    RestartRTOTimer(handle);
  }
}

static int32_t
aLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
           int flags, PRIntervalTime to)
{
  // There must be place for the whole frame (max UDP payload).
//  assert(aAmount == SDT_CLEARTEXTPAYLOADSIZE);

  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  if (!handle->aLayerBufferLen) {
    int32_t rv = aFD->lower->methods->recv(aFD->lower,
                                           handle->aLayerBuffer,
                                           SDT_CLEARTEXTPAYLOADSIZE,
                                           flags,
                                           to);
    if (rv < 0) {
      return rv;
    }

    handle->aLayerBufferLen = rv;

    assert(handle->sRecvNewPkt);

    // An ack is a separate packet and we do not ack the ack!
    if (handle->aLayerBuffer[handle->aLayerBufferUsed]  & 0x40) {
      handle->sRecvNewPkt = 0;
    } else {
      // Try to send ack.
      // If it does not succeed leave handle->sRecvNewPkt and the ack will be
      // sent later.
      struct aPacket_t *pkt = MakeAckPkt(handle);
      unsigned char *buf = (unsigned char *)(pkt + 1);
      int rv = aFD->lower->methods->write(aFD->lower,
                                          buf,
                                          pkt->sz);
      free(pkt);
      if (rv > 0) {
        handle->sRecvNewPkt = 0;
      }
    }
  }

  // Check if the first frame is ask frame or PADDING.
  // (Depends on a spec we can replace "while" with "if").
  while (handle->aLayerBufferLen &&
         ((handle->aLayerBuffer[handle->aLayerBufferUsed]  & 0x40) ||  // ACK
          (handle->aLayerBuffer[handle->aLayerBufferUsed + 3] == 0xc))) { // PADDING

    if (handle->aLayerBuffer[handle->aLayerBufferUsed] & 0x40) {
      RecvAck(handle);
    } else {
      // Ignore the rest of the packet.
      uint16_t length;
      memcpy(&length, handle->aLayerBuffer + handle->aLayerBufferUsed + 1, 2);
      length = ntohs(length);
      assert((length + HTTP2SDT_HEADER) ==
             (handle->aLayerBufferLen - handle->aLayerBufferUsed));
      handle->aLayerBufferUsed = handle->aLayerBufferLen = 0;
    }
  }

  if (!handle->aLayerBufferLen) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  // Analyze next frame.
  int16_t length;
  memcpy(&length, handle->aLayerBuffer + handle->aLayerBufferUsed + 1, 2);
  length = ntohs(length);
  length += HTTP2SDT_HEADER;
  assert(length <= SDT_CLEARTEXTPAYLOADSIZE);
  assert(length <= handle->aLayerBufferLen - handle->aLayerBufferUsed);
  if (length > aAmount) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  memcpy(aBuf, handle->aLayerBuffer + handle->aLayerBufferUsed, length);
  handle->aLayerBufferUsed += length;
  if (handle->aLayerBufferLen == handle->aLayerBufferUsed) {
    handle->aLayerBufferLen = handle->aLayerBufferUsed = 0;
  }
//LogBuffer("aLayerRecv buffer ", aBuf, rv);
  return length;
}

static int32_t
aLayerWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

  fprintf(stderr, "aLayerWrite state=%d amount=%d\n", handle->state, aAmount);

  switch (handle->state) {
  case SDT_CONNECTING:
    {
      // DTLS have not finish yet, we need to push it forward.
      int rv = aFD->lower->methods->write(aFD->lower,
                                          nullptr,
                                          0);

      if (rv == 0) {
        handle->state = SDT_TRANSFERRING;
        if (aAmount > 0) {
          PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
          rv = -1;
        }
      } else {
        PRErrorCode errCode = PR_GetError();
        if (errCode != PR_WOULD_BLOCK_ERROR) {
          handle->state = SDT_CLOSING;
        }
      }
      return rv;
    }
  case SDT_TRANSFERRING:
    {

      fprintf(stderr, "aLayerWrite state=SDT_TRANSFERRING queued=%d max=%d\n",
              handle->aTransmissionQueue.mLen +
              handle->aRetransmissionQueue.mLen,
              handle->mMaxBufferedPkt );
      uint8_t newPktAccepted = 0;
      uint8_t retransmission = 0;

      // 1) Accept new data if there is space
      if (aAmount && ((handle->aTransmissionQueue.mLen +
           handle->aRetransmissionQueue.mLen) < handle->mMaxBufferedPkt)) {

        PR_STATIC_ASSERT((SDT_CLEARTEXTPAYLOADSIZE) <= SDT_MTU);

        struct aPacket_t *pkt =
          (struct aPacket_t *)malloc(sizeof(struct aPacket_t) + aAmount);
        pkt->sz = aAmount;
        pkt->mIdsNum = 0;
        pkt->mForRetransmission = 0;

        unsigned char *buf = (unsigned char *)(pkt + 1);
        memcpy(buf, aBuf, aAmount);

        PacketQueueAddNew(&handle->aTransmissionQueue, pkt);

        newPktAccepted = 1;
      }

      // 2) Check if a timer expired
      CheckRetransmissionTimers(handle);

      // 3) Send a packet.
      if (!NeedToSendRetransmit(handle)) {
        handle->aPktTransmit = handle->aTransmissionQueue.mFirst;
      } else {
        retransmission = 1;
        handle->aPktTransmit = handle->aRetransmissionQueue.mFirst;
      }

      if (handle->aPktTransmit) {
        unsigned char *buf = (unsigned char *)(handle->aPktTransmit + 1);
//LogBuffer("aLayerSendTo pkt ", buf, aAmount + sizeof(struct aPacket_t));
        int rv = aFD->lower->methods->write(aFD->lower,
                                            buf,
                                            handle->aPktTransmit->sz);
        if (rv <= 0) {
          handle->aPktTransmit = nullptr;
          PRErrorCode errCode = PR_GetError();
          if (errCode != PR_WOULD_BLOCK_ERROR) {
            return rv;
          } else {
            return (newPktAccepted) ? aAmount : -1;
          }
        }

        // Start rto timer if needed. RTO timere is started only for data
        // packets.
        MaybeStartRTOTimer(handle);

        fprintf(stderr, "LayerSendTo amount=%d newPkt=%d pkt_sz=%d rv=%d pkt=%p"
                " number_of_ids=%d\n",
                aAmount, newPktAccepted, handle->aPktTransmit->sz, rv,
                handle->aPktTransmit, handle->aPktTransmit->mIdsNum);

//        buf = (unsigned char *)(handle->aPktTransmit);
//        LogBuffer("aLayerSendTo pkt 2", buf,
//                  handle->aPktTransmit->sz + sizeof(struct aPacket_t));

        if (!retransmission) {
          PacketQueueRemoveFirstPkt(&handle->aTransmissionQueue);
        } else {
          PacketQueueRemoveFirstPkt(&handle->aRetransmissionQueue);
          handle->aPktTransmit->mForRetransmission = 0;
        }
        PacketQueueAddNew(&handle->aRetransmissionQueue, handle->aPktTransmit);
        handle->aPktTransmit = nullptr;
      }

      // 4) Send an ack if necessary.
      if (DoWeNeedToSendAck(handle)) {
        struct aPacket_t *pkt = MakeAckPkt(handle);
        unsigned char *buf = (unsigned char *)(pkt + 1);
        int rv = aFD->lower->methods->write(aFD->lower,
                                            buf,
                                            pkt->sz);
        free(pkt);

        if (rv < 0) {
          PRErrorCode errCode = PR_GetError();
          if (errCode != PR_WOULD_BLOCK_ERROR) {
            return rv;
          }
        }
      }
      return (newPktAccepted) ? aAmount : -1;
    }
  case SDT_CLOSING:
    // TODO CLOSING part!!!
    assert (0);
  }

  return -1;
}

int
qAllowSend(struct sdt_t *handle)
{
  // first update credits
  if (handle->qCredits < handle->qMaxCredits) {
    PRTime now = PR_Now();
    PRTime delta = now - handle->qLastCredit;
    handle->qCredits += delta;
    handle->qLastCredit = now;
    if (handle->qCredits > handle->qMaxCredits) {
      handle->qCredits = handle->qMaxCredits;
    }
  }
  return (handle->qCredits >= handle->qPacingRate);
}

void
qChargeSend(struct sdt_t *handle)
{
  if (handle->qCredits < handle->qPacingRate) {
    DEV_ABORT(0);
    handle->qCredits = 0;
    return;
  }

  handle->qCredits -= handle->qPacingRate;
}

static int32_t
qLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
           int flags, PRIntervalTime to)
{
  // There must be place for the whole frame (max UDP payload).
  assert(aAmount == SDT_CLEARTEXTPAYLOADSIZE);

  return aFD->lower->methods->recv(aFD->lower, aBuf, aAmount, flags, to);
}

static int32_t
qLayerWrite(PRFileDesc *aFD, const void *aBuf, int32_t aAmount)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

/*  if (!qAllowSend(handle)) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
*/
  // send now
//  qChargeSend(handle);
  return aFD->lower->methods->write(aFD->lower, aBuf, aAmount);
}

static PRStatus
sLayerConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return PR_FAILURE;
  }
  char host[164] = {0};
  PR_NetAddrToString(addr, host, sizeof(host));
  fprintf(stderr, "sLayerConnect host: %s\n", host);
  int port = 0;
  if (addr->raw.family == AF_INET) {
    port = addr->inet.port;
  } else if (addr->raw.family == AF_INET6) {
    port = addr->ipv6.port;
  }
  fprintf(stderr, "sLayerConnect port: %d\n", port);

  memcpy(&(handle->peer), addr, sizeof(PRNetAddr));
  handle->isConnected = 1;
  return PR_SUCCESS;
}

static PRStatus
sLayerBind(PRFileDesc *fd, const PRNetAddr *addr)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return PR_FAILURE;
  }

  return fd->lower->methods->bind(fd->lower, addr);
}

static PRStatus
sLayerGetSockName(PRFileDesc *fd, PRNetAddr *addr)
{
  return fd->lower->methods->getsockname(fd->lower, addr);
}

static PRStatus
sLayerGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle || !handle->isConnected) {
    return PR_FAILURE;
  }

  memcpy(addr, &handle->peer, sizeof (PRNetAddr));
  return PR_SUCCESS;
}

static PRStatus
sLayerGetSocketOption(PRFileDesc *fd, PRSocketOptionData *aOpt)
{
  return fd->lower->methods->getsocketoption(fd->lower, aOpt);
}

static PRStatus
sLayerSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *aOpt)
{
  return fd->lower->methods->setsocketoption(fd->lower, aOpt);
}

static PRInt16 PR_CALLBACK
sLayerPoll(PRFileDesc *fd, PRInt16 how_flags, PRInt16 *p_out_flags)
{
  assert(fd->lower->methods->poll);
  return fd->lower->methods->poll(fd->lower, how_flags, p_out_flags);
}

static PRInt16 PR_CALLBACK
qLayerPoll(PRFileDesc *aFd, PRInt16 how_flags, PRInt16 *p_out_flags)
{
/*  *p_out_flags = 0;
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert(0);
    return PR_POLL_ERR;
  }
  if ((how_flags & PR_POLL_WRITE) && !qAllowSend(handle)) {
    how_flags ^= PR_POLL_WRITE; 
  }*/

  assert(aFd->lower->methods->poll);
  return aFd->lower->methods->poll(aFd->lower, how_flags, p_out_flags);
}

static PRInt16 PR_CALLBACK
aLayerPoll(PRFileDesc *aFd, PRInt16 how_flags, PRInt16 *p_out_flags)
{
  *p_out_flags = 0;
  PRInt16 outFlags = 0;

  struct sdt_t *handle = (struct sdt_t *)(aFd->secret);
  if (!handle) {
    assert(0);
    *p_out_flags = PR_POLL_ERR;
    return how_flags;
  }

  PRIntervalTime now = PR_IntervalNow();
  if ((how_flags & PR_POLL_WRITE) &&
      !(RTOTimerExpired(handle, now) ||
        ERTimerExpired(handle, now) ||
        handle->aTransmissionQueue.mLen)) {
    how_flags ^= PR_POLL_WRITE;
  }

  if (how_flags & PR_POLL_READ) {
    if (handle->aLayerBufferLen) {
      *p_out_flags |= PR_POLL_READ;
      return how_flags;
    } else if (handle->state != SDT_TRANSFERRING){
      // Look for date from the network.
      how_flags ^= PR_POLL_READ;
    }
  }

  assert(aFd->lower->methods->poll);
  PRInt16 rv = aFd->lower->methods->poll(aFd->lower,
                                   how_flags,
                                   p_out_flags);
  return rv;
}

static void
strongDtor(PRFileDesc *fd)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (handle) {
    fd->secret = nullptr;
    sdt_freeHandle(handle);
  }
  PR_DELETE(fd);
}

uint8_t
sdt_SocketWritable(PRFileDesc * aFd)
{
  assert(PR_GetLayersIdentity(aFd) == aIdentity);
  struct sdt_t *handle = (struct sdt_t *)(aFd->secret);
  if (!handle) {
    assert(0);
    return 0;
  }

  return ((handle->aTransmissionQueue.mLen + handle->aRetransmissionQueue.mLen)
          < handle->mMaxBufferedPkt);
}

static int sdt_once = 0;
void
sdt_ensureInit()
{
  if (sdt_once) {
    return;
  }
  sdt_once = 1;

  sMinRTO = PR_MillisecondsToInterval(MIN_RTO); // 1s
  sMaxRTO = PR_MillisecondsToInterval(MAX_RTO); // 60s

  qIdentity = PR_GetUniqueIdentity("sdt-qLayer");
  sIdentity = PR_GetUniqueIdentity("sdt-sLayer");
  aIdentity = PR_GetUniqueIdentity("sdt-aLayer");

  qMethods = *PR_GetDefaultIOMethods();
  sMethods = *PR_GetDefaultIOMethods();
  aMethods = *PR_GetDefaultIOMethods();

  // setup read side methods
  // qLayer is nop
  sMethods.read = useRecv;
  sMethods.recv = sLayerRecv;
  sMethods.recvfrom = notImplemented;
  // cLayer is nss
  sMethods.write = useSendTo1;
  sMethods.send = useSendTo2;
  sMethods.sendto = sLayerSendTo;

  qMethods.read = useRecv;
  qMethods.recv = qLayerRecv;
  qMethods.recvfrom = notImplemented;
  qMethods.write = qLayerWrite;
  qMethods.send = notImplemented2;
  qMethods.sendto = notImplemented3;

  aMethods.read = useRecv;
  aMethods.recv = aLayerRecv;
  aMethods.recvfrom = notImplemented;
  aMethods.write = aLayerWrite;
  aMethods.send = notImplemented2;
  aMethods.sendto = notImplemented3;

  // some other general methods
  sMethods.connect = sLayerConnect;
//  qMethods.connect = sLayerConnect;
  sMethods.bind = sLayerBind;
  sMethods.getsockname = sLayerGetSockName;
  sMethods.getpeername = sLayerGetPeerName;
  sMethods.getsocketoption = sLayerGetSocketOption;
  sMethods.setsocketoption = sLayerSetSocketOption;
  sMethods.poll = sLayerPoll;
  qMethods.poll = qLayerPoll;
  aMethods.poll = aLayerPoll;
  qMethods.close = genericClose;
  sMethods.close = genericClose;
  aMethods.close = genericClose;
}
    
PRFileDesc *
sdt_openSocket(PRIntn af)
{
  sdt_ensureInit();

  PRFileDesc *fd = PR_OpenUDPSocket(af);

  PRSocketOptionData opt;
  opt.option = PR_SockOpt_Nonblocking;
  opt.value.non_blocking =  1;
  PR_SetSocketOption(fd, &opt);

  return sdt_addSDTLayers(fd);
}

PRFileDesc *
sdt_addSDTLayers(PRFileDesc *aFd)
{
  PRFileDesc *sLayer = nullptr;

  sLayer = PR_CreateIOLayerStub(sIdentity, &sMethods);
  
  if (!(aFd && sLayer)) {
    goto fail; // ha!
  }

  sLayer->dtor = strongDtor;

  struct sdt_t *handle = sdt_newHandle();
  if (!handle) {
    goto fail;
  }
  sLayer->secret = (struct PRFilePrivate *)handle;

  if (PR_PushIOLayer(aFd, PR_GetLayersIdentity(aFd), sLayer) == PR_SUCCESS) {
    sLayer = nullptr;
  } else {
    goto fail;
  }

  handle->fd = aFd;
  return aFd;

fail:
  PR_Close(aFd);
  if (sLayer) {
    sLayer->dtor(sLayer);
  }
  return nullptr;
}

PRFileDesc *
sdt_addALayer(PRFileDesc *aFd)
{
  PRFileDesc * sFd = PR_GetIdentitiesLayer(aFd, sIdentity);
  struct sdt_t *handle = (struct sdt_t *)(sFd->secret);

  if (!handle) {
    goto fail;
  }

  PRFileDesc *qLayer = nullptr;
  PRFileDesc *aLayer = nullptr;

  qLayer = PR_CreateIOLayerStub(qIdentity, &qMethods);
  aLayer = PR_CreateIOLayerStub(aIdentity, &aMethods);

  if (!(aFd && qLayer && aLayer)) {
    goto fail; // ha!
  }

  qLayer->dtor = weakDtor;
  aLayer->dtor = weakDtor;

  qLayer->secret = (struct PRFilePrivate *)handle;
  aLayer->secret = (struct PRFilePrivate *)handle;

  if (PR_PushIOLayer(aFd, PR_GetLayersIdentity(aFd), qLayer) == PR_SUCCESS) {
    qLayer = nullptr;
  } else {
    goto fail;
  }

  if (PR_PushIOLayer(aFd, PR_GetLayersIdentity(aFd), aLayer) == PR_SUCCESS) {
    aLayer = nullptr;
  } else {
    goto fail;
  }

  handle->fd = aFd;
  return aFd;

fail:
  PR_Close(aFd);
  if (qLayer) {
    qLayer->dtor(qLayer);
  }
  if (aLayer) {
    aLayer->dtor(aLayer);
  }
  return nullptr;
}
