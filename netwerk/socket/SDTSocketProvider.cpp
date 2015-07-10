/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Logging.h"
#include "nsCOMPtr.h"
#include "nsIServiceManager.h"
#include "nsIUUIDGenerator.h"
#include "nspr.h"
#include "sdtlib.h"
#include "SDTSocketProvider.h"

#if 0
 README
  * netwerk/test/unit/test_get.js is a long https:// GET - but it is not localhost, so is not CI worthy
  * you need to build proxy.cpp and setenv all_proxy http://localhost:7000 to use it (assuming 7000)

 TODO (at best a partial list)
 * source port should be same for all flows in client too, demux by uuid - socketprovider keep udpsocket and shim like proxy
 * reliabiity (optional).. via ack.. notion of deadline notion of ack with uni-tt
 * happy eyeballs
 * uuid and h2 should be able to go longer the normal connect/close cycle..
 * timeouts
 * mtu detection
 * congestion control (latency sensitive)
 * poll()
 * fec
 * psm integration (especially, but not only, auth)
 * investigate dtlscon pmtu change
 * have psm and http use common pref for finding transport layer
 * better h2 integration where fec is per headers and reliability per stream
#endif

// dtls 1.2 rfc 6437, tls 1.2 rfc 5246

using mozilla::LogLevel;

namespace mozilla { namespace net {

static PRLogModuleInfo *gSDTLog = nullptr;
#define LOG(args) MOZ_LOG(gSDTLog, mozilla::LogLevel::Debug, args)

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
  nsresult rv;

  if (!gSDTLog) {
    gSDTLog = PR_NewLogModule("sdt");
  }

  LOG(("SDTSocketProvider::NewSocket %p\n", this));
  nsCOMPtr<nsIUUIDGenerator> uuidgen;

  fd = PR_OpenUDPSocket(family);
  if (!fd) {
    goto onfail;
  }

  nsIID idee;
  uuidgen = do_GetService("@mozilla.org/uuid-generator;1", &rv);
  if (NS_SUCCEEDED(rv)) {
    rv = uuidgen->GenerateUUIDInPlace(&idee);
  }
  if (NS_FAILED(rv)) {
    goto onfail;
  }
  PR_STATIC_ASSERT(sizeof (idee) == 16);
  fd = sdt_ImportFD(fd, reinterpret_cast<unsigned char *>(&(idee.m0)));

  *result = fd;
  LOG(("SDTSocketProvider::NewSocket ok %p\n", this));
  return NS_OK;

onfail:
  LOG(("SDTSocketProvider::NewSocket fail %p\n", this));
  MOZ_ASSERT(false, "to be removed");

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


NS_IMPL_ISUPPORTS(SDTSocketProvider, nsISocketProvider)

} } // namespace mozilla::net

