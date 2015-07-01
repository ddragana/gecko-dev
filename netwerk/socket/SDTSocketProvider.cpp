/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nspr.h"
#include "nsCOMPtr.h"
#include "nsRefPtr.h"
#include "nsError.h"
#include "nsIServiceManager.h"
#include "nsIUUIDGenerator.h"
#include "mozilla/Logging.h"
#include "SDTSocketProvider.h"
#include "ssl.h"

#if 0
 README
  * netwerk/test/unit/test_get.js is a long https:// GET - but it is not localhost, so is not CI worthy
  * you need to build proxy.cpp and setenv all_proxy http://localhost:7000 to use it (assuming 7000)

 TODO (at best a partial list)
 * source port should be same for all flows, demux by uuid
 * uuid and h2 should be able to go longer the normal connect/close cycle..
 * timeouts
 * reliabiity
 * pacing
 * mtu detection
 * congestion control
 * poll()
 * fec
 * psm integration (especially, but not only, auth)
 * amplification issues
 * shared header (and code?) between gecko and proxy
 * investigate dtlscon pmtu change
 * have psm and http use common pref for finding transport layer

#endif

using mozilla::LogLevel;

namespace mozilla { namespace net {

static PRLogModuleInfo *gSDTLog = nullptr;
#define LOG(args) MOZ_LOG(gSDTLog, mozilla::LogLevel::Debug, args)

// todo put these in class
#define MTU 1400
#define UUIDSIZE 20
#define PAYLOADSIZE (MTU - UUIDSIZE)
#define CLEARTEXTPAYLOADSIZE (PAYLOADSIZE - 64)

class SDTSocket
{
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(SDTSocket)
  SDTSocket(PRFileDesc *fd)
    : mConnected(false)
    , mLeftOverLen(0)
    , mLeftOverOffset(0)
  {
    nsresult rv;
    nsID idee;
    LOG(("SDTSocket ctor %p\n", this));

    nsCOMPtr<nsIUUIDGenerator> uuidgen = do_GetService("@mozilla.org/uuid-generator;1", &rv);
    if (NS_SUCCEEDED(rv)) {
      rv = uuidgen->GenerateUUIDInPlace(&idee);
    }
    if (NS_SUCCEEDED(rv)) {
      // todo magic smarter
      PR_STATIC_ASSERT(sizeof (idee) == 16);
      PR_STATIC_ASSERT(UUIDSIZE == 20);
      mSend[0] = 0x88;  // magic
      mSend[0] = 0x77;  //magic
      mSend[0] = 0x66; // magic
      mSend[0] = 0x00; // version
      memcpy(mSend + 4, &(idee.m0), 16);
      memcpy(mUUID, mSend, UUIDSIZE);
    }
  }

  static PRStatus sConnect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->Connect(fd, addr, to);
  }
  PRStatus Connect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to);

  static PRStatus sClose(PRFileDesc *fd)
  {
    LOG(("SDTSocket::sClose %p\n", fd->secret));
    nsRefPtr<SDTSocket> self = reinterpret_cast<SDTSocket *>(fd->secret);
    if (!self) {
      return PR_SUCCESS;
    }

    fd->identity = PR_INVALID_IO_LAYER;
    return fd->lower->methods->close(fd->lower);
  }

  static int16_t sPoll(PRFileDesc *fd, int16_t in_flags, int16_t *out_flags)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->Poll(fd, in_flags, out_flags);
  }
  int16_t Poll(PRFileDesc *fd, int16_t in_flags, int16_t *out_flags);

  static PRStatus sGetSockName(PRFileDesc *fd, PRNetAddr *addr)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->GetSockName(fd, addr);
  }
  PRStatus GetSockName(PRFileDesc *fd, PRNetAddr *addr);

  static PRStatus sGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->GetPeerName(fd, addr);
  }
  PRStatus GetPeerName(PRFileDesc *fd, PRNetAddr *addr);

  static PRStatus sGetSocketOption(PRFileDesc *fd, PRSocketOptionData *aOpt)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->GetSocketOption(fd, aOpt);
  }
  PRStatus GetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt);

  static PRStatus sSetSocketOption(PRFileDesc *fd, const PRSocketOptionData *aOpt)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->SetSocketOption(fd, aOpt);
  }
  PRStatus SetSocketOption(PRFileDesc *aFD, const PRSocketOptionData *aOpt);

  static int32_t sRead(PRFileDesc *fd, void *aBuf, int32_t aAmount)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->Read(fd, aBuf, aAmount);
  }
  int32_t Read(PRFileDesc *aFD, void *aBuf, int32_t aAmount);

  static int32_t sRecv(PRFileDesc *fd, void *aBuf, int32_t aAmount,
                       int flags, PRIntervalTime to)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->Recv(fd, aBuf, aAmount, flags, to);
  }
  int32_t Recv(PRFileDesc *fd, void *aBuf, int32_t aAmount,
               int flags, PRIntervalTime to);

  static int32_t sRecvFrom(PRFileDesc *fd, void *aBuf, int32_t aAmount,
                           int flags, PRNetAddr *addr, PRIntervalTime to)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->RecvFrom(fd, aBuf, aAmount, flags, addr, to);
  }
  int32_t RecvFrom(PRFileDesc *fd, void *aBuf, int32_t aAmount,
                   int flags, PRNetAddr *addr, PRIntervalTime to);

  static int32_t sWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(fd->secret);
    return self->Write(fd, aBuf, aAmount);
  }
  int32_t Write(PRFileDesc *fd, const void *aBuf, int32_t aAmount);

  static int32_t sSend(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                       int flags, PRIntervalTime to)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(aFD->secret);
    return self->Send(aFD, aBuf, aAmount, flags, to);
  }
  int32_t Send(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
               int flags, PRIntervalTime to);

  static int32_t sSendTo(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                         int flags, const PRNetAddr *addr, PRIntervalTime to)
  {
    SDTSocket *self = reinterpret_cast<SDTSocket *>(aFD->secret);
    return self->SendTo(aFD, aBuf, aAmount, flags, addr, to);
  }
  int32_t SendTo(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                 int flags, const PRNetAddr *addr, PRIntervalTime to);


  static int32_t sPacketizeWrite(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
  {
    if (aAmount > CLEARTEXTPAYLOADSIZE) {
      aAmount = CLEARTEXTPAYLOADSIZE;
    }
    return fd->lower->methods->write(fd->lower, aBuf, aAmount);
  }

  static int32_t sPacketizeSend(PRFileDesc *fd, const void *aBuf, int32_t aAmount,
                                int flags, PRIntervalTime to)
  {
    if (aAmount > CLEARTEXTPAYLOADSIZE) {
      aAmount = CLEARTEXTPAYLOADSIZE;
    }
    return fd->lower->methods->send(fd->lower, aBuf, aAmount, flags, to);
  }

  static int32_t sPacketizeSendTo(PRFileDesc *fd, const void *aBuf, int32_t aAmount,
                                  int flags, const PRNetAddr *addr, PRIntervalTime to)
  {
    if (aAmount > CLEARTEXTPAYLOADSIZE) {
      aAmount = CLEARTEXTPAYLOADSIZE;
    }
    return fd->lower->methods->sendto(fd->lower, aBuf, aAmount, flags, addr, to);
  }

  static int32_t sPacketizeAvailable(PRFileDesc *fd)
  {
    return 0;
  }

  static SECStatus GreenLightAuth(void* arg, PRFileDesc* fd, PRBool, PRBool)
  {
    LOG(("SDTSocketProvider::GreenlightAuth ok\n"));
    // todo integrate with psm
    return SECSuccess;
  }

private:
  ~SDTSocket() {
    LOG(("~SDTSocket %p\n", this));
  }
  PRNetAddr mPeerName;
  unsigned char mSend[MTU];
  unsigned char mRecv[MTU + 1];
  unsigned char mUUID[UUIDSIZE];
  bool mConnected;
  int32_t mLeftOverLen; // in recv buffer
  int32_t mLeftOverOffset;
};

NS_IMETHODIMP
SDTSocketProvider::NewSocket(int32_t family,
                             const char *host,
                             int32_t port,
                             const char *proxyHost,
                             int32_t proxyPort,
                             uint32_t flags,
                             PRFileDesc **result,
                             nsISupports **securityInfo)
{
  PRFileDesc *fd = nullptr;
  PRFileDesc *sdtLayer = nullptr;
  PRFileDesc *packetizeLayer = nullptr;
  PRDescIdentity sdtIdentity;
  PRDescIdentity packetizeIdentity;
  static PRIOMethods sdtMethods;
  static PRIOMethods packetizeMethods;
  nsRefPtr<SDTSocket> sdtSock;
  SECStatus rv2;

  if (!gSDTLog) {
    gSDTLog = PR_NewLogModule("sdt");
    sdtMethods = *PR_GetDefaultIOMethods();
    packetizeMethods = *PR_GetDefaultIOMethods();

    sdtMethods.connect = SDTSocket::sConnect;
    sdtMethods.close = SDTSocket::sClose;
    sdtMethods.getsockname = SDTSocket::sGetSockName;
    sdtMethods.getpeername = SDTSocket::sGetPeerName;
    sdtMethods.getsocketoption = SDTSocket::sGetSocketOption;
    sdtMethods.setsocketoption = SDTSocket::sSetSocketOption;
    sdtMethods.read = SDTSocket::sRead;
    sdtMethods.recv = SDTSocket::sRecv;
    sdtMethods.write = SDTSocket::sWrite;
    sdtMethods.send = SDTSocket::sSend;
    sdtMethods.sendto = SDTSocket::sSendTo;
    // todo need a poll implementation

    packetizeMethods.write = SDTSocket::sPacketizeWrite;
    packetizeMethods.send = SDTSocket::sPacketizeSend;
    packetizeMethods.sendto = SDTSocket::sPacketizeSendTo;
    packetizeMethods.available = SDTSocket::sPacketizeAvailable;
  }

  LOG(("SDTSocketProvider::NewSocket %p\n", this));

  fd = PR_OpenUDPSocket(family);
  if (!fd) {
    goto onfail;
  }

  sdtSock = new SDTSocket(fd);
  sdtIdentity = PR_GetUniqueIdentity("SDT");
  sdtLayer = PR_CreateIOLayerStub(sdtIdentity, &sdtMethods);
  if (!sdtLayer) {
    goto onfail;
  }
  packetizeIdentity = PR_GetUniqueIdentity("SDT-packetize");
  packetizeLayer = PR_CreateIOLayerStub(packetizeIdentity, &packetizeMethods);
  if (!packetizeLayer) {
    goto onfail;
  }
  sdtSock.forget(reinterpret_cast<SDTSocket **>(&sdtLayer->secret));

  if (PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), sdtLayer) == PR_FAILURE) {
    goto onfail;
  }
  sdtLayer = nullptr;

  // how does auth work here?
  // sni? session caching? alpn? allowable suites?
  // can tls for https be removed?
  // need to integrate with psm
  fd = DTLS_ImportFD(nullptr,fd);

  rv2 = SSL_AuthCertificateHook(fd, SDTSocket::GreenLightAuth, nullptr);
  if (rv2 != SECSuccess) {
    goto onfail;
  }

  if (PR_PushIOLayer(fd, PR_GetLayersIdentity(fd), packetizeLayer) == PR_FAILURE) {
    goto onfail;
  }
  packetizeLayer = nullptr;

  *result = fd;
  LOG(("SDTSocketProvider::NewSocket ok %p\n", this));
  return NS_OK;

onfail:
  LOG(("SDTSocketProvider::NewSocket fail %p\n", this));
  MOZ_ASSERT(false, "to be removed");

  if (sdtLayer) {
    sdtSock = reinterpret_cast<SDTSocket *>(sdtLayer->secret);
    PR_DELETE(sdtLayer);
  }
  if (packetizeLayer) {
    PR_DELETE(packetizeLayer);
  }
  if (fd) {
    PR_Close(fd);
  }
  return NS_ERROR_SOCKET_CREATE_FAILED;
}

NS_IMETHODIMP
SDTSocketProvider::AddToSocket(int32_t family,
                                   const char *host,
                                   int32_t port,
                                   const char *proxyHost,
                                   int32_t proxyPort,
                                   uint32_t flags,
                                   PRFileDesc *sock,
                                   nsISupports **socksInfo)
{
  return NS_ERROR_SOCKET_CREATE_FAILED;
}

int16_t
SDTSocket::Poll(PRFileDesc *fd, int16_t in_flags, int16_t *out_flags)
{
  LOG(("SDTSocket::Poll %p\n", this));
  // todo - but for now, just let udp do its thing
  return fd->lower->methods->poll(fd->lower, in_flags, out_flags);
}

PRStatus
SDTSocket::Connect(PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime to)
{
  // we use unconnected sockets, so connect() just stores an ip address for now
  LOG(("SDTSocket::Connect %p\n", this));

  memcpy (&mPeerName, addr, sizeof (PRNetAddr));
  mConnected = true;
  return PR_SUCCESS;
}

PRStatus
SDTSocket::GetSockName(PRFileDesc *fd, PRNetAddr *addr)
{
  LOG(("SDTSocket::GetSockName %p\n", this));
  return fd->lower->methods->getsockname(fd->lower, addr);
}

PRStatus
SDTSocket::GetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
  LOG(("SDTSocket::GetPeerName %p\n", this));
  if (!mConnected) {
    return PR_FAILURE;
  }
  memcpy(addr, &mPeerName, sizeof (PRNetAddr));
  return PR_SUCCESS;
}

PRStatus
SDTSocket::GetSocketOption(PRFileDesc *fd, PRSocketOptionData *aOpt)
{
  LOG(("SDTSocket::GetSocketOption %p\n", this));
  return fd->lower->methods->getsocketoption(fd->lower, aOpt);
}

PRStatus
SDTSocket::SetSocketOption(PRFileDesc *fd, const PRSocketOptionData *aOpt)
{
  LOG(("SDTSocket::SetSocketOption %p\n", this));
  return fd->lower->methods->setsocketoption(fd->lower, aOpt);
}

int32_t
SDTSocket::Read(PRFileDesc *aFD, void *aBuf, int32_t aAmount)
{
  LOG(("SDTSocket::Read %p\n", this));
  return Recv(aFD, aBuf, aAmount, 0, PR_INTERVAL_NO_WAIT);
}

int32_t
SDTSocket::Recv(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
                int flags, PRIntervalTime to)
{
  LOG(("SDTSocket::Recv %p\n", this));
  PRNetAddr addr;
  return RecvFrom(aFD, aBuf, aAmount, flags, &addr, to);
}

int32_t
SDTSocket::RecvFrom(PRFileDesc *aFD, void *aBuf, int32_t aAmount,
                    int flags, PRNetAddr *addr, PRIntervalTime to)
{
  LOG(("SDTSocket::RecvFrom (aAmount=%d) %p", aAmount, this));

  if (mLeftOverOffset) {
    if (aAmount > mLeftOverLen) {
      aAmount = mLeftOverLen;
    }
    memcpy(aBuf, mRecv + mLeftOverOffset, aAmount);
    LOG(("SDTSocket::RecvFrom %p using leftover %d from %d\n", this, aAmount, mLeftOverOffset));
    mLeftOverLen -= aAmount;
    mLeftOverOffset += aAmount;
    if (!mLeftOverLen) {
      mLeftOverOffset = 0;
    }
    return aAmount;
  }

  int32_t rv =
    aFD->lower->methods->recvfrom(aFD->lower, mRecv, MTU + 1, flags, addr, to);
  // allow a read of +1 to assert if overfilling
  MOZ_ASSERT(rv <= MTU, "to be removed");

  LOG(("SDTSocket::RecvFrom %p network read %d", this, rv));
  // note that we don't check addr. UUID defines the flow
  if (rv > 0) {
    if (rv < UUIDSIZE) {
      MOZ_ASSERT(false, "to be removed");
      memcpy(mRecv, mUUID, UUIDSIZE);
      rv = -1;
    } else {
      rv -= UUIDSIZE;
      if (rv > aAmount) {
        // read more in packet that stream read called for. need a buffer.
        mLeftOverLen = rv - aAmount;
        mLeftOverOffset = UUIDSIZE + aAmount;
        LOG(("SDTSocket::RecvFrom %p storing leftover %d\n", this, mLeftOverLen));
        rv = aAmount; // stream amount
      }
      memcpy(aBuf, mRecv + UUIDSIZE, rv);

      if (memcmp(mRecv, mUUID, UUIDSIZE)) {
        // wrong uuid for this socket
        MOZ_ASSERT(false, "to be removed");
        memcpy(mRecv, mUUID, UUIDSIZE);
        rv = -1;
      }
    }
  }
  return rv;
}

int32_t
SDTSocket::Write(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
{
  return Send(fd, aBuf, aAmount, 0, PR_INTERVAL_NO_WAIT);
}

int32_t
SDTSocket::Send(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                int flags, PRIntervalTime to)
{
  // todo better buffering and pacing for mtu
  MOZ_ASSERT(aAmount <= PAYLOADSIZE);
  if (aAmount > PAYLOADSIZE) {
    aAmount = PAYLOADSIZE;
  }

  memcpy (mSend + UUIDSIZE, aBuf, aAmount);

  int32_t rv = SendTo(aFD, mSend, aAmount + UUIDSIZE, flags, &mPeerName, to);
  LOG(("SDTSocket::Send %p %d (+hdr) %d\n", this, aAmount, rv));
  MOZ_ASSERT(rv <= MTU);
  return (rv > UUIDSIZE) ? (rv - UUIDSIZE) : 0;
}

int32_t
SDTSocket::SendTo(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                  int flags, const PRNetAddr *addr, PRIntervalTime to)
{
  int32_t rv = aFD->lower->methods->sendto(aFD->lower, aBuf, aAmount, flags, addr, to);
  LOG(("SDTSocket::SendTo %p %d (includes hdr) %d\n", this, aAmount, rv));
  return rv;
}


NS_IMPL_ISUPPORTS(SDTSocketProvider, nsISocketProvider)

} } // namespace mozilla::net

