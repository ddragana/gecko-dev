/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include "key.h"
#include "ssl.h"
#include "nss.h"
#include "pk11pub.h"
#include "pkcs12.h"
#include "sechash.h"
#include "secpkcs7.h"
#include "secport.h"
#include "prerror.h"
#include "sdtlib.h"
#include "secmod.h"
#include "sslproto.h"
#include <assert.h>

#define UDP_LISTEN_PORT 7000

// these are the front side dtls server certs
// currently not checked
#define CERTDIR "/home/mcmanus/proxycerts"
#define CERTNICK "pgo server certificate"

// this is the backend H1 proxy
#define GWPORT 3128
#define GWHOST 0x7f000001

#if 0
 README

clang++ -g -I ../../../obj-debug-scratch/dist/include/ -I ../../../obj-debug-scratch/dist/include/nss -L ../../../obj-debug-scratch/dist/lib/ -I ../../../obj-debug-scratch/dist/include/nspr/ ../../../obj-debug-scratch/netwerk/socket/sdtlib.o  proxy.cpp ../../../obj-debug-scratch/dist/lib/libssl3.so ../../../obj-debug-scratch/dist/lib/libnss3.so -lnspr4

   * see the flowID for information on the stack of fd handlers
   * the proxy is a gateway between udp/sdt on the front side and proxiable tcp/h1 on the backside. So it is meant
     to point at a h1 proxy such as squid on localhost:3128

 TODO (at best a partial list)
 * shared header (and code?) between gecko and proxy
 * what does a reused flow with a closed backend mean?
 * a whole lot more thinking about dtls params
 * backside tcp connect is blocking
 * backside tcp writes are lossy on short return and blocking
 * poll

#endif

PRIOMethods cryptoMethods;

static PRFileDesc *udp_socket = NULL;

static CERTCertificate *cert;
static SECKEYPrivateKey *privKey;

class flowID;
class flowID *hash[256];

class flowID
{
public:
  flowID(unsigned char *aUUID, PRNetAddr *sin)
  : tcp(-1)
  {
    unsigned char id = HashID(aUUID);
    memcpy (mUUID, aUUID, SDT_UUIDSIZE);
    next = hash[id];
    hash[id] = this;

    PRFileDesc *layerU = sdt_layerU(udp_socket);
    if (!layerU) {
      // probably just means that udp_socket hasn't been used with a sdt
      // stack yet
      layerU = udp_socket;
    }

    mFD = sdt_ImportFD(layerU, aUUID + 4);
    assert(mFD); // todo
    PR_Connect(mFD, sin, PR_INTERVAL_NO_WAIT);
    PRFileDesc *crypto = sdt_layerC(mFD);
    assert(crypto); // todo

    SSLKEAType certKEA = NSS_FindCertKEAType(cert);
    if (SSL_ConfigSecureServer(crypto, cert, privKey, certKEA)
        != SECSuccess) {
      assert(false);
    }

    SECStatus status;
    status = SSL_OptionSet(crypto, SSL_SECURITY, true);
    assert(status == SECSuccess);
    status = SSL_OptionSet(crypto, SSL_HANDSHAKE_AS_CLIENT, false);
    assert(status == SECSuccess);
    status = SSL_OptionSet(crypto, SSL_HANDSHAKE_AS_SERVER, true);
    assert(status == SECSuccess);
    status = SSL_ResetHandshake(crypto, true);
    assert(status == SECSuccess);
  }

  ~flowID() {
    if (tcp != -1) {
      close (tcp);
    }
    if (mFD) {
      PR_Close(mFD);
    }
  }

  static unsigned char HashID(unsigned char *aUUID)
  {
    // todo runtime err
    // todo magic should be in sdtlib
    assert((aUUID[0] == 0x88) && (aUUID[1] == 0x77) && (aUUID[2] == 0x66) && (aUUID[3] == 0x00));
    unsigned char id = aUUID[0];
    for (unsigned int i = 1; i < SDT_UUIDSIZE; ++i) {
      id ^= aUUID[i];
    }
    return id;
  }

  void ensureConnect()
  {
    if (tcp != -1) {
      return;
    }
    tcp = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(GWPORT);
    sin.sin_addr.s_addr = htonl(GWHOST);

    // todo nonblock
    if (connect(tcp, (const struct sockaddr *) &sin, sizeof (sin)) < 0) {
      close(tcp);
      tcp = -1;
      fprintf(stderr, "tcp connect failed\n");
    } else {
      fprintf(stderr, "tcp connect ok\n");
    }
  }

  void processForward()
  {
    // take ciphertext from front, decrypt, and send as plaintext to tcp on back
    unsigned char clearTextBuf[SDT_MTU*2];
    int rlen;
    int subtotal = 0;

    do {
      rlen = PR_Read(mFD, clearTextBuf, SDT_MTU * 2);
      fprintf(stderr,"after decypt we have rlen=%d\n", rlen);
      if (rlen > 0) {
        fprintf(stderr, "forward %d of decrypted cipher to backend\n", rlen);
        forward(clearTextBuf, rlen);
      } else if ((rlen == -1) && (PR_GetError() == PR_WOULD_BLOCK_ERROR)) {
        rlen = 1; // fake it to reloop
      }
    } while (rlen > 0);
  }

  void forward(unsigned char *buf, unsigned int l)
  {
    // todo partial writes, etc..
    if (tcp == -1) {
      return;
    }
    write (tcp, buf, l);
  }

  void processReverse()
  {
    if (tcp == -1) {
      return;
    }

    unsigned char cleartext[SDT_CLEARTEXTPAYLOADSIZE]; // todo member with fixed uuid
    int rr = recv(tcp, cleartext, SDT_CLEARTEXTPAYLOADSIZE, MSG_DONTWAIT);
    if (rr > 0) {
      fprintf(stderr,"tcp socket read %d\n", rr);

      // we have cleartext.. we need to turn it into ciphertext and
      // stick a uuid on the front of it

      int offset = 0;
      do {
        int iw = PR_Write(mFD, cleartext + offset, rr);
        if (iw > 0) {
          rr -= iw;
          offset += iw;
        } else {
          break;
        }
      }
      while (rr > 0);
    } else if (rr == 0) {
      close(tcp);
      tcp = -1;
    }
  }

  PRFileDesc *mFD;
  unsigned char mUUID[SDT_UUIDSIZE];
  class flowID *next; // hash flow table chain
  int tcp; // tcp file descriptor
};

class flowID *
findFlow(unsigned char *uuid, PRNetAddr *sin, bool makeIt)
{
  unsigned char id = flowID::HashID(uuid);
  class flowID *rv;

  for (rv = hash[id]; rv; rv = rv->next) {
    if (!memcmp(rv->mUUID, uuid, SDT_UUIDSIZE)) {
      break;
    }
  }
  if (!rv && makeIt) {
    rv = new flowID(uuid, sin);
  }
  // todo I think this becomes IP addr independent if we
  // just reconnect an old flow id with a changed prnetaddr
  return rv;
}

// bogus password func, just don't use passwords. :-P
static char *
password_func(PK11SlotInfo* slot, PRBool retry, void* arg)
{
  if (retry) {
    return NULL;
  }
  return strdup("");
}

static void setupNSS()
{
  PK11_SetPasswordFunc(password_func);
  NSS_GetVersion();
  if (NSS_Init(CERTDIR) != SECSuccess) {
    assert(false);
  }
  if (NSS_SetDomesticPolicy() != SECSuccess) {
    assert(false);
  }
  if (SSL_ConfigServerSessionIDCache(0, 0, 0, NULL) != SECSuccess) {
    assert(false);
  }

  cert = PK11_FindCertFromNickname(CERTNICK, NULL);
  assert(cert);
  privKey =  PK11_FindKeyByAnyCert(cert, NULL);
  assert(privKey);
}

static void setupListener()
{
  PRNetAddr sin;
  sdt_ensureInit();
  sin.inet.family = PR_AF_INET;
  sin.inet.ip = 0;
  sin.inet.port = htons(UDP_LISTEN_PORT);
  udp_socket = PR_OpenUDPSocket(AF_INET);
  if (PR_Bind(udp_socket, &sin) != PR_SUCCESS) {
    assert(0);
  }
  // todo check return vals
}


int main()
{
  setupNSS();
  setupListener();

  // a primative flow table.. uid to fd and fd is a tcp connect to proxy
  // write each message to the proxy
  // then need to mux reads from that set of fds and the udp_socket
  // udp_socket is just that - it has no sdt or crypto io layers

  unsigned char cipheredBuf[SDT_MTU + 1];

  PRNetAddr sin;
  while (1) {
    bool didWork = false;
    PRFileDesc *layerU = sdt_layerU(udp_socket);
    if (!layerU) {
      // probably just means that udp_socket hasn't been used with a sdt
      // stack yet
      layerU = udp_socket;
    }
    int rlen = PR_RecvFrom(layerU, cipheredBuf, SDT_MTU + 1, PR_MSG_PEEK, &sin, PR_INTERVAL_NO_WAIT);
    assert (rlen <= SDT_MTU); // to be removed (runtime error)
    if (rlen >= SDT_UUIDSIZE) {
      class flowID *flow = findFlow(cipheredBuf, &sin, true);
      fprintf(stderr, "udp read %d %p port %d\n", rlen, flow, ntohs(sin.inet.port));

      flow->ensureConnect();
      flow->processForward();
      didWork = true;
    }

    // this is obviously nothing more than a poc hack that needs todo poll()
    for (unsigned int i = 0; i < 256; ++i) {
      for (flowID *f = hash[i]; f ; f = f->next) {
        f->processReverse();
      }
    }

    if (!didWork) {
      usleep(5000); // 5ms
    }
  }
  return 0;
}
