/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef SDT_COMMON
#define SDT_COMMON

#include "nspr.h"

#if 1
#define DEV_ABORT(x) do { abort(); } while (0)
#else
#define DEV_ABORT(x) do { } while (0)
#endif
#define nullptr 0

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
  return fd->methods->sendto(fd, aBuf, aAmount, 0, nullptr,
                             PR_INTERVAL_NO_WAIT);
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

static int32_t
notImplemented2(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                int flags, PRIntervalTime to)
{
  DEV_ABORT();
  return -1;
}

static int32_t
notImplemented3(PRFileDesc *aFD, const void *aBuf, int32_t aAmount,
                int flags, const PRNetAddr* aAddr, PRIntervalTime to)
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

#endif // SDT_COMMON
