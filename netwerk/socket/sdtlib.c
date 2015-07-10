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
#include "sdtlib.h"
#include "ssl.h"
#include "unistd.h"

/*
an SDT Scoket has the following layers, the U layer is passed into the library

P packetizelayer (quantize and lock)
C cryptolayer (dtls)
S sdtlayer (sdt framing)
Q queuelayer (pacing, cong contrl, etc..)
U udptransport layer (I/O happens here)

on write -
P packetizes the data into an MTU acceptable quanta (~1300)
C applies ciphers (dtls from nss)
S places UUID on front
Q queues (and manages timers) or sends to U
U network write

on read -
U network read
Q nop
S find sdt_preprocess (epoch, seq, etc..) remove sdt envelope
C decrypt (dlts from nss)
P replay detect, generate ack (or corrupt, or ooo), pass to plaintext
*/

// todo sdtlib-internal.h

/* There is an unfortunate amount of standalone (non reuse) C going on in here
   in the hope of maximum reusability.. this might actually be a good candidate
   for a different runtime (rust?) and a c ABI layer. (can go do that?) But that's
   premature compared to working on the basics of the protocol atm. */

#define DTLS_TYPE_CHANGE_CIPHER 20
#define DTLS_TYPE_ALERT         21
#define DTLS_TYPE_HANDSHAKE     22
#define DTLS_TYPE_DATA          23

// DEV_ABORT's might actually happen in the wild, but in the lab are more
// likely to be a bug.. so we will abort on them for now, but they need a
// runtime error path too.
#if 1
#define DEV_ABORT(x) do { abort(); } while (0)
#else
#define DEV_ABORT(x) do { } while (0)
#endif
#define nullptr 0

#if 0
  // how does auth work here?
  // sni? session caching? alpn? allowable suites?
  // can tls for https be removed if e2e?
#endif

static uint32_t qBufferLenMax = 128; // number of queued packets

// our standard time unit is a microsecond
static uint64_t qMaxCreditsDefault = 80000; // ums worth of full bucket
static uint64_t qPacingRateDefault =  2000; // send every 2ms (2000ums)

static uint32_t amplificationPacket = 2;

struct qPacket_t
{
  int32_t sz;
  struct qPacket_t *next;
  // the buffer lives at the end of the struct
};
            
struct sdt_t
{
  unsigned char uuid[SDT_UUIDSIZE];
  PRNetAddr peer;
  uint8_t isConnected;
  uint8_t isServer;

  uint8_t  recordType;
  uint16_t epoch;
  uint64_t seq;
  uint64_t sBytesRead;

  uint64_t upperWindow; // SDT_REPLAY_WINDOW - 1
  unsigned char window[SDT_REPLAY_WINDOW / 8];

  uint32_t qBufferLen;
  PRTime qBufferNextSend;
  struct qPacket_t *qFirst, *qLast;
  PRTime qLastCredit;
  // credits are key in ums
  uint64_t qCredits;
  uint64_t qMaxCredits;
  uint64_t qPacingRate;

  struct sdt_t *next, *prev; // for the transmit thread
  PRFileDesc *fd; // weak ptr, dont close
};

static struct sdt_t *transmitHead;
static PRLock *mutex; // stack mutex.. can improve to stack + per flow
static PRCondVar *condVar;

static void assert_lock(struct sdt_t *handle)
{
  PR_AssertCurrentThreadOwnsLock(mutex);
}

static void hlock(struct sdt_t *handle)
{
  PR_Lock(mutex); // just one for now
}

static void hunlock(struct sdt_t *handle)
{
  PR_Unlock(mutex);
}

static void
addToTransmitList_locked(struct sdt_t *handle)
{
  // need to insert this sorted by qBufferNextSend
  // todo need transmitTail to search from rear in common case
  assert_lock(handle);
  assert(handle->next == NULL);
  assert(handle->prev == NULL);

  if (!transmitHead) {
    transmitHead = handle;
    return;
  }

  struct sdt_t *trailingNode = NULL;
  for (struct sdt_t *i = transmitHead;
       i && (i->qBufferNextSend < handle->qBufferNextSend); i = i->next) {
    handle->next = i;
    if (i) {
      handle->prev = i->prev;
    } else {
      assert(trailingNode);
      handle->prev = trailingNode;
    }
    if (handle->prev) {
      handle->prev->next = handle;
    } else {
      transmitHead = handle;
    }
    if (handle->next) {
      handle->next->prev = handle;
    }
    trailingNode = i;
  }
}

static void
removeFromTransmitList_locked(struct sdt_t *handle)
{
  assert_lock(handle);
  if ((!handle->prev) && (transmitHead != handle)) {
    return; // not on the list!
  }

  if (transmitHead == handle) { // head of list
    assert(!handle->prev);
    transmitHead = handle->next;
    if (handle->next) {
      handle->next->prev = NULL;
    }
  } else {
    assert(handle->prev);
    handle->prev->next = handle->next;
    if (handle->next) {
      handle->next->prev = handle->prev;
    }
  }
  handle->next = NULL;
  handle->prev = NULL;
}

struct sdt_t *sdt_newHandle(unsigned char *id_buf_16)
{
  struct sdt_t *handle = (struct sdt_t *) malloc (sizeof(struct sdt_t));
  memset(handle, 0, sizeof(struct sdt_t));
  handle->upperWindow = SDT_REPLAY_WINDOW - 1;

  PR_STATIC_ASSERT(SDT_UUIDSIZE == 20);
  handle->uuid[0] = 0x88;  // magic
  handle->uuid[1] = 0x77;  //magic
  handle->uuid[2] = 0x66; // magic
  handle->uuid[3] = 0x00; // version
  memcpy (handle->uuid + 4, id_buf_16, 16);
  handle->qMaxCredits = qMaxCreditsDefault;
  handle->qMaxCredits = qPacingRateDefault * 3; // todo
  handle->qPacingRate = qPacingRateDefault;
  return handle;
}

static void
sdt_freeHandle(struct sdt_t *handle)
{
  assert_lock(handle);
  removeFromTransmitList_locked(handle);
  free(handle);
}

static unsigned int
sdt_preprocess(struct sdt_t *handle,
               unsigned char *pkt, uint32_t len)
{
  assert_lock(handle);
  if (len < SDT_UUIDSIZE + 11) {
    DEV_ABORT();
    return 0;
  }

  // todo deal with bad version
  // todo encapsulate magic
  if (!((pkt[0] == 0x88) && (pkt[1] == 0x77) && (pkt[2] == 0x66) && (pkt[3] == 0x00))) {
    DEV_ABORT();
    return 0;
  }

  // sanity check dtls 1.0, 1.1, or 1.2
  if (!((pkt[SDT_UUIDSIZE + 1] == 0xFE) && (pkt[SDT_UUIDSIZE + 2] >= 0xFD))) {
    DEV_ABORT();
    return 0;
  }

  if (memcmp(pkt, handle->uuid, SDT_UUIDSIZE)) {
    DEV_ABORT();
    return 0;
  }

  // the leading bytes of a dlts record format are 1 byte of type, 2 of tls version,
  // and 64 bits of sequence number

  handle->recordType = pkt[SDT_UUIDSIZE];
  memcpy (&handle->epoch, pkt + SDT_UUIDSIZE + 3, 2);
  handle->epoch = ntohs(handle->epoch);

  memcpy (&handle->seq, pkt + SDT_UUIDSIZE + 7, 4);
  handle->seq = ntohl(handle->seq);
  handle->seq += ((uint64_t)pkt[SDT_UUIDSIZE + 5]) << 40;
  handle->seq += ((uint64_t)pkt[SDT_UUIDSIZE + 6]) << 32;

  // we don't allow renogitation which is implied by epoch > 1
  if (handle->epoch > 1) {
    DEV_ABORT();
    return 0;
  }
  if (!handle->epoch && (handle->recordType == DTLS_TYPE_DATA)) {
    // we should only be handshaking in epoch 0
    DEV_ABORT();
    return 0;
  }

  return 1;
}

// windowing
// we support a SDT_REPLAY_WINDOW packet window, ending at the highest seq number seen

// todo - reliable should not advance window if overwriting a 0 bit, but nonreliable
// should

// 0 for valid, 1 for too old, 2 for replayed
static unsigned int
sdt_replayCheck(struct sdt_t *handle, uint64_t seqno)
{
  assert_lock(handle);
  fprintf(stderr,"replay check %p 0x%lX\n",handle, seqno);

  uint64_t lowerWindow = handle->upperWindow - (SDT_REPLAY_WINDOW - 1);
  uint64_t byteIdx = (seqno >> 3) & ((SDT_REPLAY_WINDOW / 8) - 1);
  uint8_t bitno = seqno & 7;

  if (seqno < lowerWindow) {
    return 1;
  }

  if (seqno <= handle->upperWindow) {
    // this packet is in window, so we can check it without further adjustments
    unsigned int rv = (handle->window[byteIdx] & (1 << (bitno))) ? 2 : 0;
    // mark it used
    handle->window[byteIdx] |= (1 << (bitno));
    return rv;
  }

  // extend the window
  // todo - obviously there are better ways to do this than bit by
  // bit, but for the common (+1) case the inner loop doesn't exec at all
  for (uint64_t i = handle->upperWindow + 1; i < (seqno - 1); ++i) {
    uint64_t tmpByteIdx = (i >> 3) & ((SDT_REPLAY_WINDOW / 8) - 1);
    uint8_t tmpBitno = i & 7;
    handle->window[tmpByteIdx] &= ~(1 << tmpBitno);
  }

  // mark it in the window
  handle->window[byteIdx] |= 1 << (bitno);
  handle->upperWindow = seqno;
  return 0;
}

static PRDescIdentity uIdentity;
static PRDescIdentity qIdentity;
static PRDescIdentity sIdentity;
static PRDescIdentity pIdentity;

static PRIOMethods uMethods;
static PRIOMethods qMethods;
static PRIOMethods sMethods;
// cMethods are controlled by nss
static PRIOMethods pMethods;

// a generic read to recv mapping
static int32_t
useRecv(PRFileDesc *fd, void *aBuf, int32_t aAmount)
{
  return fd->methods->recv(fd, aBuf, aAmount, 0, PR_INTERVAL_NO_WAIT);
}

// a generic write to send mapping
static int32_t
useSendTo1(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  return fd->methods->sendto(fd, aBuf, aAmount, 0, nullptr, PR_INTERVAL_NO_WAIT);
}

// a generic send to sendto mapping
static int32_t
useSendTo2(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
           int flags, PRIntervalTime to)
{
  return aFD->methods->sendto(aFD, aBuf, aAmount, flags, nullptr, to);
}
    
static int32_t
notImplemented(PRFileDesc *fd, void *aBuf, int32_t aAmount,
               int flags, PRNetAddr *addr, PRIntervalTime to)
{
  DEV_ABORT();
  return -1;
}

static PRStatus
genericClose(PRFileDesc *fd)
{
  PRFileDesc *thisLayer = PR_PopIOLayer(fd, PR_GetLayersIdentity(fd));
  thisLayer->dtor(thisLayer);
  return PR_Close(fd);
}

static void
weakDtor(PRFileDesc *fd)
{
  // do not free the handle associated with secret, this
  // layer is just a weak pointer
  fd->secret = nullptr;
  PR_DELETE(fd);
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

static int32_t
sLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
           int flags, PRIntervalTime to)
{
  int32_t rv = aFD->lower->methods->recv(aFD->lower, aBuf, aAmount, flags, to);
  if (rv < 0) {
    return rv;
  }
  if (rv < SDT_UUIDSIZE) {
    assert (0);
    return -1;
  }
  // aBuf now contains prefixed and ciphered sdt frame from network

  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }
  assert_lock(handle);

  handle->sBytesRead += rv;
  if (!sdt_preprocess(handle, aBuf, rv)) {
    assert (0);
    return -1;
  }

  rv -= SDT_UUIDSIZE;
  memmove(aBuf, aBuf + SDT_UUIDSIZE, rv);

  fprintf(stderr,"sLayer Recv got %d (%d) of ciphertext this=%p "
          "type=%d %X %lX sBytesRead=%ld\n", rv, rv + SDT_UUIDSIZE, handle,
          handle->recordType, handle->epoch, handle->seq, handle->sBytesRead);

  if (handle->isServer &&
      (handle->sBytesRead < (amplificationPacket * SDT_MTU))) {
    fprintf(stderr,"sLayer Recv %p dropping packet because recv threshold %d"
            "not met yet (%ld)\n", handle, amplificationPacket * SDT_MTU,
            handle->sBytesRead);
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }


  return rv;
}

static int32_t
pLayerRecv_locked(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
                  int flags, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }
  assert_lock(handle);

  int32_t rv = aFD->lower->methods->recv(aFD->lower, aBuf, aAmount, flags, to);
  if (rv < 0) {
    return -1;
  }

  // we now need to do replay detection, cc feedback, rst-like handling,

  if (sdt_replayCheck(handle, handle->seq) != 0) {
    // drop it
    // todo this is a dup and should be cc feedback
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }

  fprintf(stderr,"pLayer Recv got %d of plaintext this=%p\n", rv, handle);

  // todo cc feedback inclduing ack
  // todo lifecycle handling
  // todo deal with dtls corruption as feedback

  return rv;
}

static int32_t
pLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
           int flags, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }
  hlock(handle);
  int32_t rv = pLayerRecv_locked(aFD, aBuf, aAmount, flags, to);
  hunlock(handle);
  return rv;
}

static int32_t
pLayerAvailable(PRFileDesc *fd)
{
  // the cLayer (nss dtls) asserts on available(). todo
  // for now just return 0.
  // later, I guess buffers will need to live on this side of
  // the cLayer

  return 0;
}

static PRStatus
pLayerClose(PRFileDesc *fd)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return PR_FAILURE;
  }

  hlock(handle);
  PRStatus rv = genericClose(fd);
  hunlock(handle);
  return rv;
}

static int32_t
pLayerSendTo_locked(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                    int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }
  assert_lock(handle);

  if (aAmount > SDT_CLEARTEXTPAYLOADSIZE) {
    aAmount = SDT_CLEARTEXTPAYLOADSIZE;
  }

  // the cLayer (nss) doesn't support sendto, that's ok we'll just use send
  // and the sLayer underneat it will pick up the same peer address and use
  // sendto from there on out.
  int32_t rv = aFD->lower->methods->send(aFD->lower, aBuf, aAmount, flags, to);

  if (rv != -1) {
    fprintf(stderr,"pLayer send %p %d (from %d) rv=%d\n",
            handle,
            aAmount <= SDT_CLEARTEXTPAYLOADSIZE ? aAmount : SDT_CLEARTEXTPAYLOADSIZE,
            aAmount, rv);
  }

  return rv;
}

static int32_t
pLayerSendTo(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
             int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }
  hlock(handle);
  int32_t rv = pLayerSendTo_locked(aFD, aBuf, aAmount, flags, addr, to);
  hunlock(handle);
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
  assert_lock(handle);
  addr = &(handle->peer);

  if (aAmount > SDT_PAYLOADSIZE) {
    DEV_ABORT();
    // todo set error
    return -1;
  }

  PR_STATIC_ASSERT((SDT_PAYLOADSIZE + SDT_UUIDSIZE) <= SDT_MTU);
  unsigned char buf[SDT_MTU]; // todo mbuf chain is inevitable
  memcpy(buf, handle->uuid, SDT_UUIDSIZE);
  memcpy(buf + SDT_UUIDSIZE, aBuf, aAmount);

  sdt_preprocess(handle, buf, aAmount + SDT_UUIDSIZE);
  int32_t sendLen = aAmount + SDT_UUIDSIZE;
  int32_t rv;
  if (!handle->isServer && (handle->recordType == DTLS_TYPE_HANDSHAKE)) {
    memset(buf + aAmount + SDT_UUIDSIZE, 0x7d, SDT_MTU - SDT_UUIDSIZE - aAmount);
    sendLen = SDT_MTU;
    // this is an extra send(s) to avoid amplification
    rv = aFD->lower->methods->sendto(aFD->lower, buf, sendLen, flags, addr, to);
    for (unsigned int i=0; i < amplificationPacket - 1; i++) {
      aFD->lower->methods->sendto(aFD->lower, buf, sendLen, flags, addr, to);
    }
  } else {
    rv = aFD->lower->methods->sendto(aFD->lower, buf, sendLen, flags, addr, to);
  }

  fprintf(stderr,"sLayer send %p %d (from %d) rv=%d\n", handle,
          aAmount + SDT_UUIDSIZE, aAmount, rv);

  if (rv < 0) {
    return -1;
  }
  if (rv < (aAmount + SDT_UUIDSIZE)) {
    DEV_ABORT();
    // todo set err
    return -1;
  }
  return aAmount;
}

static
void updateNextSend_locked(struct sdt_t *handle) 
{
  assert_lock(handle);
  if (handle->qCredits >= handle->qPacingRate) {
    handle->qBufferNextSend = 0;
  } else {
    handle->qBufferNextSend = handle->qPacingRate - handle->qCredits;
    handle->qBufferNextSend += PR_Now();
  }
}

// todo new file
static int // 0 on ok
qAdd(struct sdt_t *handle, const void *aBuf, int32_t sz) 
{
  assert_lock(handle);
  struct qPacket_t *pkt = (struct qPacket_t *) malloc(sizeof(struct qPacket_t) + sz);
  if (!pkt) {
    return 1;
  }
  pkt->next = nullptr;
  pkt->sz = sz;
  memcpy(pkt + 1, aBuf, sz);

  if (handle->qBufferLen) {
    assert(handle->qFirst);
    assert(handle->qLast);
    assert(!handle->qLast->next);
    handle->qLast->next = pkt;
    handle->qLast = pkt;
  } else {
    assert(!handle->qFirst);
    assert(!handle->qLast);
    handle->qLast = pkt;
    handle->qFirst = pkt;
  }
  ++handle->qBufferLen;
  if (handle->qBufferLen == 1) {
    updateNextSend_locked(handle);
    addToTransmitList_locked(handle);
    PR_NotifyCondVar(condVar);
  }
  fprintf(stderr,"qadd %p %d\n", handle, handle->qBufferLen);
  return 0;
}

int
qAllowSend(struct sdt_t *handle)
{
  assert_lock(handle);
  // first update credits
  if (handle->qCredits < handle->qMaxCredits) {
    PRTime now = PR_Now();
    PRTime delta = now - handle->qLastCredit;
    handle->qCredits += delta;
    fprintf(stderr,"adding %ld credits %ld\n", delta, handle->qCredits);
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
  assert_lock(handle);
  if (handle->qCredits < handle->qPacingRate) {
    DEV_ABORT(0);
    handle->qCredits = 0;
    return;
  }

  handle->qCredits -= handle->qPacingRate;
  fprintf(stderr,"%p credits are now %ld\n", handle, handle->qCredits);
}

static int32_t
qLayerSendTo(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
             int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }
  assert_lock(handle);
  addr = &(handle->peer);

  // todo - cc check and queue it if necessary
  // todo cc pluggable
  // If there are buffers, queue it or reject it
  if (handle->qBufferLen >= qBufferLenMax) {
    PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
    return -1;
  }
  if (handle->qBufferLen || !qAllowSend(handle)) {
    if (qAdd(handle, aBuf, aAmount) != 0) {
      PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
      return -1;
    }
    return aAmount;
  }

  // send now
  qChargeSend(handle);
  return aFD->lower->methods->sendto(aFD->lower, aBuf, aAmount, flags, addr, to);
}

static PRStatus
pLayerConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return PR_FAILURE;
  }
  hlock(handle);
  PRStatus rv = fd->lower->methods->connect(fd->lower, addr, to);
  hunlock(handle);
  return rv;
}

static PRStatus
sLayerConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(fd->secret);
  if (!handle) {
    assert (0);
    return PR_FAILURE;
  }
  memcpy(&(handle->peer), addr, sizeof(PRNetAddr));
  handle->isConnected = 1;
  return PR_SUCCESS;
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

static int32_t
uLayerRead(PRFileDesc *fd, void *aBuf, int32_t aAmount)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_Read(udp_socket, aBuf, aAmount);
}

static int32_t
uLayerRecv(PRFileDesc *fd, void *aBuf, int32_t aAmount, int flags, PRIntervalTime to)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_Recv(udp_socket, aBuf, aAmount, flags, to);
}

static int32_t
uLayerRecvFrom(PRFileDesc *fd, void *aBuf, int32_t aAmount, int flags, PRNetAddr *addr, PRIntervalTime to)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_RecvFrom(udp_socket, aBuf, aAmount, flags, addr, to);
}

static int32_t
uLayerAvailable(PRFileDesc *fd)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_Available(udp_socket);
}

static int32_t
uLayerWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_Write(udp_socket, aBuf, aAmount);
}

static int32_t
uLayerSend(PRFileDesc *fd, const void *aBuf, int32_t aAmount, int flags, PRIntervalTime to)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_Send(udp_socket, aBuf, aAmount, flags, to);
}

static int32_t
uLayerSendTo(PRFileDesc *fd, const void *aBuf, int32_t aAmount, int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_SendTo(udp_socket, aBuf, aAmount, flags, addr, to);
}

static PRStatus
uLayerGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_GetPeerName(udp_socket, addr);
}

static PRStatus
uLayerGetSocketOption(PRFileDesc *fd, PRSocketOptionData *aOpt)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_GetSocketOption(udp_socket, aOpt);
}

static PRStatus
uLayerSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *aOpt)
{
  PRFileDesc *udp_socket = (PRFileDesc *)(fd->secret);
  return PR_SetSocketOption(udp_socket, aOpt);
}

static void
qTransmitThread(void *arg)
{
  // the idea is to sleep until the next packet needs to be sent
  // and transmithead is sorted by wakeup needs

  hlock(NULL);
  do {
    for (struct sdt_t *handle = transmitHead; handle; ) {
      int sentPacket = 0;
      while (handle->qFirst && qAllowSend(handle)) {
        fprintf(stderr,"xmit thread %p %d allow=%d\n",
                handle, handle->qBufferLen, qAllowSend(handle));
        PRFileDesc *qLayer = sdt_layerQ(handle->fd);
        unsigned char *buf = (unsigned char *)(handle->qFirst + 1);
        int32_t rv =
          qLayer->lower->methods->sendto(qLayer->lower, buf, handle->qFirst->sz, 0, &handle->peer, PR_INTERVAL_NO_WAIT);
        fprintf(stderr,"xmit thread %p sendto %d\n", handle, rv);
        sentPacket = 1;
        if (rv > 1) {
          qChargeSend(handle);
          struct qPacket_t *done = handle->qFirst;
          if (handle->qLast == done) {
            handle->qLast = NULL;
          }
          handle->qFirst = done->next;
          free (done);
          --handle->qBufferLen;
        }
      }
      if (!sentPacket) {
        // ordered by next send time, so we're done
        break;
      }
      if (!handle->qBufferLen) {
        removeFromTransmitList_locked(handle);
      } else {
        updateNextSend_locked(handle);
        // resort, probly to end of list
        removeFromTransmitList_locked(handle);
        addToTransmitList_locked(handle);
      }
      handle = transmitHead;
    }
    PRIntervalTime to = PR_INTERVAL_NO_TIMEOUT;
    if (transmitHead) {
      PRTime sleep_duration;
      sleep_duration = transmitHead->qBufferNextSend - PR_Now();
      if (sleep_duration < 1) {
        sleep_duration = 1;
      }
      sleep_duration += 200;
      fprintf(stderr,"xmit thread sleep %ld usec\n",sleep_duration);
      to = PR_MicrosecondsToInterval(sleep_duration);
    } else {
      fprintf(stderr,"xmit thread sleep INFINITY usec\n");
    }

    // spend most of our time waiting on the condvar (which releases the lock during wait)
    PR_WaitCondVar(condVar, to);
  } while (1);
  hunlock(NULL);
  
  // when to terminate todo
}

static int sdt_once = 0;
void
sdt_ensureInit()
{
  // this function is not locked
  if (sdt_once) {
    return;
  }
  sdt_once = 1;

  mutex = PR_NewLock();
  condVar = PR_NewCondVar(mutex);

  PR_CreateThread(PR_USER_THREAD, qTransmitThread, NULL, PR_PRIORITY_NORMAL,
                  PR_GLOBAL_THREAD, PR_UNJOINABLE_THREAD, 0);

  uIdentity = PR_GetUniqueIdentity("sdt-uShimLayer");
  qIdentity = PR_GetUniqueIdentity("sdt-qLayer");
  sIdentity = PR_GetUniqueIdentity("sdt-sLayer");
  pIdentity = PR_GetUniqueIdentity("sdt-pLayer");

  uMethods = *PR_GetDefaultIOMethods();
  qMethods = *PR_GetDefaultIOMethods();
  sMethods = *PR_GetDefaultIOMethods();
  pMethods = *PR_GetDefaultIOMethods();

  // setup read side methods
  // uLayer is imported network io
  // qLayer is nop
  sMethods.read = useRecv;
  sMethods.recv = sLayerRecv;
  sMethods.recvfrom = notImplemented;
  // cLayer is nss
  pMethods.read = useRecv;
  pMethods.recv = pLayerRecv;
  pMethods.recvfrom = notImplemented;
  pMethods.available = pLayerAvailable;

  pMethods.write = useSendTo1;
  pMethods.send = useSendTo2;
  pMethods.sendto = pLayerSendTo;
  // cLayer is nss
  sMethods.write = useSendTo1;
  sMethods.send = useSendTo2;
  sMethods.sendto = sLayerSendTo;
  qMethods.write = useSendTo1;
  qMethods.send = useSendTo2;
  qMethods.sendto = qLayerSendTo;

  // some other general methods
  sMethods.connect = pLayerConnect;
  sMethods.connect = sLayerConnect;
  sMethods.getsockname = sLayerGetSockName;
  sMethods.getpeername = sLayerGetPeerName;
  sMethods.getsocketoption = sLayerGetSocketOption;
  sMethods.setsocketoption = sLayerSetSocketOption;

  qMethods.close = genericClose;
  sMethods.close = genericClose;
  pMethods.close = pLayerClose;
  
  // definitely todo need a poll()

  uMethods.read = uLayerRead;
  uMethods.recv = uLayerRecv;
  uMethods.recvfrom = uLayerRecvFrom;
  uMethods.available = uLayerAvailable;
  uMethods.write = uLayerWrite;
  uMethods.send = uLayerSend;
  uMethods.sendto = uLayerSendTo;
  uMethods.getpeername = uLayerGetPeerName;
  uMethods.getsocketoption = uLayerGetSocketOption;
  uMethods.setsocketoption = uLayerSetSocketOption;
  uMethods.close = genericClose;

}

static SECStatus
sdtGreenLightAuth(void* arg, PRFileDesc* fd, PRBool arg2, PRBool arg3)
{
  // todo integrate with psm
  return SECSuccess;
}
    
PRFileDesc *
sdt_ImportFD(PRFileDesc *udp_socket, unsigned char *id_buf_16)
{
  sdt_ensureInit();

  PRFileDesc *fd = udp_socket;
  PRFileDesc *qLayer = nullptr;
  PRFileDesc *sLayer = nullptr;
  PRFileDesc *pLayer = nullptr;

  qLayer = PR_CreateIOLayerStub(qIdentity, &qMethods);
  sLayer = PR_CreateIOLayerStub(sIdentity, &sMethods);
  pLayer = PR_CreateIOLayerStub(pIdentity, &pMethods);
  
  if (!(qLayer && qLayer && qLayer && qLayer)) {
    goto fail; // ha!
  }

  qLayer->dtor = strongDtor;
  sLayer->dtor = weakDtor;
  pLayer->dtor = weakDtor;

  struct sdt_t *handle = sdt_newHandle(id_buf_16);
  if (!handle) {
    goto fail;
  }
  qLayer->secret = (struct PRFilePrivate *)handle;
  sLayer->secret = (struct PRFilePrivate *)handle;
  pLayer->secret = (struct PRFilePrivate *)handle;

  if (PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), qLayer) == PR_SUCCESS) {
    qLayer = nullptr;
  } else {
    goto fail;
  }

  if (PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), sLayer) == PR_SUCCESS) {
    sLayer = nullptr;
  } else {
    goto fail;
  }

  // the cLayer
  fd = DTLS_ImportFD(nullptr,fd);
  if (!fd) {
    goto fail;
  }

  if (SSL_AuthCertificateHook(fd, sdtGreenLightAuth, nullptr) != SECSuccess) {
    goto fail;
  }
  
  if (PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), pLayer) == PR_SUCCESS) {
    pLayer = nullptr;
  } else {
    goto fail;
  }

  handle->fd = fd;
  return fd;

fail:
  PR_Close(fd);
  if (qLayer) {
    qLayer->dtor(qLayer);
  }
  if (sLayer) {
    sLayer->dtor(sLayer);
  }
  if (pLayer) {
    pLayer->dtor(pLayer);
  }
  return nullptr;
}

PRFileDesc *
sdt_layerP(PRFileDesc *sdtFD)
{
  if (PR_GetLayersIdentity(sdtFD) != pIdentity) {
    return nullptr;
  }
  return sdtFD;
}

PRFileDesc *
sdt_ImportFDServer(PRFileDesc *udp_socket, unsigned char *id_buf_16)
{
  PRFileDesc *rv = sdt_ImportFD(udp_socket, id_buf_16);
  if (!rv) {
    return nullptr;
  }

  struct sdt_t *handle = (struct sdt_t *)(rv->secret);
  assert (handle);
  handle->isServer = 1;
  return rv;
}

PRFileDesc *
sdt_layerC(PRFileDesc *sdtFD)
{
  if (PR_GetLayersIdentity(sdtFD) != pIdentity) {
    return nullptr;
  }
  return sdtFD->lower; // cLayer is next
}

PRFileDesc *
sdt_layerU(PRFileDesc *sdtFD)
{
  if (PR_GetLayersIdentity(sdtFD) != pIdentity) {
    return nullptr;
  }

  //  p->c->s->q->u
  // todo get by identity I suppose
  assert (sdtFD->lower->lower->lower->lower);
  assert (!sdtFD->lower->lower->lower->lower->lower);
  return sdtFD->lower->lower->lower->lower;
}

PRFileDesc *
sdt_layerQ(PRFileDesc *sdtFD)
{
  if (PR_GetLayersIdentity(sdtFD) != pIdentity) {
    return nullptr;
  }

  //  p->c->s->q->u
  // todo get by identity I suppose
  assert(PR_GetLayersIdentity(sdtFD->lower->lower->lower) == qIdentity);
  return sdtFD->lower->lower->lower;
}

// callers to sdtlib can either pass in a real UDP socket to the Import*() functions
// or they can pass that UDP socket into this function and get a shim layerU that
// can be passed to the importing function. The shim does I/O with the layerU function
// but it does not layer it beacuse of data structure problems in the layering with
// sharing the same layer in multiple stacks simultaneously.
PRFileDesc *
sdt_newShimLayerU(PRFileDesc *udp_socket)
{
  PRFileDesc *uLayer = PR_CreateIOLayerStub(uIdentity, &uMethods);
  uLayer->secret = (struct PRFilePrivate *)udp_socket;
  uLayer->dtor = weakDtor;
  return uLayer;
}
