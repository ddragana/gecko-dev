/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SDT_MTU 1400
#define SDT_UUIDSIZE 20
#define SDT_PAYLOADSIZE (SDT_MTU - SDT_UUIDSIZE)
#define SDT_CLEARTEXTPAYLOADSIZE (SDT_PAYLOADSIZE - 64)
#define SDT_REPLAY_WINDOW 8192

PRFileDesc *
sdt_ImportFD(PRFileDesc *udp_socket, unsigned char *id_buf_16);

PRFileDesc *
sdt_ImportFDServer(PRFileDesc *udp_socket, unsigned char *id_buf_16);

PRFileDesc *
sdt_newShimLayerU(PRFileDesc *udp_socket);

void sdt_ensureInit();

unsigned char *sdt_Peek(PRFileDesc fd, PRNetAddr *sin, int *rlen);

  
PRFileDesc *sdt_layerP(PRFileDesc *sdtFD);
PRFileDesc *sdt_layerC(PRFileDesc *sdtFD);
PRFileDesc *sdt_layerQ(PRFileDesc *sdtFD);
PRFileDesc *sdt_layerU(PRFileDesc *sdtFD);

#ifdef __cplusplus
}
#endif /* __cplusplus */

