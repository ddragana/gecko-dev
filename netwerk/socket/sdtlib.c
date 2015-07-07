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

/*
an SDT Scoket has the following layers, the U layer is passed into the library

P packetizelayer (quantize)
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

#define DTLS_TYPE_CHANGE_CIPHER 20
#define DTLS_TYPE_ALERT         21
#define DTLS_TYPE_HANDSHAKE     22
#define DTLS_TYPE_DATA          23
// DEV_ASSERT's might actually happen in the wild, but should not in development,
// so we assert them at that time
#define DEV_ASSERT assert
#define nullptr 0

#if 0
  // how does auth work here?
  // sni? session caching? alpn? allowable suites?
  // can tls for https be removed if e2e?
#endif

struct sdt_t
{
  unsigned char uuid[SDT_UUIDSIZE];
  PRNetAddr peer; // todo
  uint8_t connected;

  uint8_t  recordType;
  uint16_t epoch;
  uint64_t seq;

  uint64_t upperWindow; // SDT_REPLAY_WINDOW - 1
  unsigned char window[SDT_REPLAY_WINDOW / 8];
};

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
  return handle;
}

static void
sdt_freeHandle(struct sdt_t *handle)
{
  free(handle);
}

static unsigned int
sdt_preprocess(struct sdt_t *handle,
               unsigned char *pkt, uint32_t len)
{
  if (len < SDT_UUIDSIZE + 11) {
    DEV_ASSERT(0);
    return 0;
  }

  if (!((pkt[0] == 0x88) && (pkt[1] == 0x77) && (pkt[2] == 0x66) && (pkt[3] == 0x00))) {
    DEV_ASSERT(0);
    return 0;
  }

  // sanity check dtls 1.0, 1.1, or 1.2
  if (!((pkt[SDT_UUIDSIZE + 1] == 0xFE) && (pkt[SDT_UUIDSIZE + 2] >= 0xFD))) {
    DEV_ASSERT(0);
    return 0;
  }

  if (memcmp(pkt, handle->uuid, SDT_UUIDSIZE)) {
    DEV_ASSERT(0);
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
    DEV_ASSERT(0);
    return 0;
  }
  if (!handle->epoch && (handle->recordType == DTLS_TYPE_DATA)) {
    // we should only be handshaking in epoch 0
    DEV_ASSERT(0);
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

static PRDescIdentity qIdentity;
static PRDescIdentity sIdentity;
static PRDescIdentity pIdentity;

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
  DEV_ASSERT(0);
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
  // aBuf now contains prefixe and ciphered sdt frame from network

  struct sdt_t *handle = (struct sdt_t *)(aFD->secret); // todo
  if (!handle) {
    assert (0);
    return -1;
  }

  if (!sdt_preprocess(handle, aBuf, rv)) {
    assert (0);
    return -1;
  }
  rv -= SDT_UUIDSIZE;
  memmove(aBuf, aBuf + SDT_UUIDSIZE, rv);

  fprintf(stderr,"sLayer Recv got %d (%d) of ciphertext this=%p "
          "type=%d %X %lX\n", rv, rv + SDT_UUIDSIZE, handle,
          handle->recordType, handle->epoch, handle->seq);

  return rv;
}

static int32_t
pLayerRecv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
           int flags, PRIntervalTime to)
{
  int32_t rv = aFD->lower->methods->recv(aFD->lower, aBuf, aAmount, flags, to);
  if (rv < 0) {
    return -1;
  }

  struct sdt_t *handle = (struct sdt_t *)(aFD->secret); // todo
  if (!handle) {
    assert (0);
    return -1;
  }

  // we now need to do replay detection, cc feedback, rst-like handling,

  if (sdt_replayCheck(handle, handle->seq) != 0) {
    // drop it
    // todo error = wouldblock
    // this is a dup and should be cc feedback
    return -1;
  }

  fprintf(stderr,"pLayer Recv got %d of plaintext this=%p\n", rv, handle);

  // todo cc feedback inclduing ack
  // todo lifecycle handling

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
    
static int32_t
pLayerSendTo(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
             int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  struct sdt_t *handle = (struct sdt_t *)(aFD->secret);
  if (!handle) {
    assert (0);
    return -1;
  }

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
    DEV_ASSERT(0);
    // todo set error
    return -1;
  }

  PR_STATIC_ASSERT((SDT_PAYLOADSIZE + SDT_UUIDSIZE) <= SDT_MTU);
  unsigned char buf[SDT_MTU]; // todo mbuf chain is inevitable
  memcpy(buf, handle->uuid, SDT_UUIDSIZE);
  memcpy(buf + SDT_UUIDSIZE, aBuf, aAmount);

  int32_t rv = aFD->lower->methods->sendto(aFD->lower, buf, aAmount + SDT_UUIDSIZE, flags, addr, to);

  fprintf(stderr,"sLayer send %p %d (from %d) rv=%d\n", handle,
          aAmount + SDT_UUIDSIZE, aAmount, rv);

  if (rv == -1) {
    return -1;
  }
  if (rv < SDT_UUIDSIZE) {
    DEV_ASSERT(0);
    // todo set err
    return -1;
  }
  return rv - SDT_UUIDSIZE;
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
  addr = &(handle->peer);

  // todo - cc check and queue it if necessary

  return aFD->lower->methods->sendto(aFD->lower, aBuf, aAmount, flags, addr, to);
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
  handle->connected = 1;
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
  if (!handle || !handle->connected) {
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

static int sdt_once = 0;
void
sdt_ensureInit()
{
  // this function is not locked
  if (sdt_once) {
    return;
  }
  sdt_once = 1;

  qIdentity = PR_GetUniqueIdentity("sdt-qLayer");
  sIdentity = PR_GetUniqueIdentity("sdt-sLayer");
  pIdentity = PR_GetUniqueIdentity("sdt-pLayer");

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
  sMethods.connect = sLayerConnect;
  sMethods.getsockname = sLayerGetSockName;
  sMethods.getpeername = sLayerGetPeerName;
  sMethods.getsocketoption = sLayerGetSocketOption;
  sMethods.setsocketoption = sLayerSetSocketOption;

  qMethods.close = genericClose;
  sMethods.close = genericClose;
  pMethods.close = genericClose;
  
  // definitely todo need a poll()
}

static SECStatus
sdtGreenLightAuth(void* arg, PRFileDesc* fd, PRBool arg2, PRBool arg3)
{
  // todo integrate with psm
  return SECSuccess;
}
    
// todo how is this different for server
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
