/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#ifndef SDT_SOCKET
#define SDT_SOCKET

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SDT_MTU 1400
#define SDT_PAYLOADSIZE 1400
#define SDT_CLEARTEXTPAYLOADSIZE (SDT_PAYLOADSIZE - 64)
#define SDT_REPLAY_WINDOW 8192

PRFileDesc *sdt_openSocket(PRIntn af);
PRFileDesc *sdt_addSDTLayers(PRFileDesc *aFd);
PRFileDesc *sdt_addALayer(PRFileDesc *aFd);
void sdt_ensureInit();
uint8_t sdt_SocketWritable(PRFileDesc *aFd);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif //SDT_SOCKET

