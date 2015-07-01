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
#include "secmod.h"
#include "sslproto.h"
#include <assert.h>

// these are the front side dtls server certs
// currently not checked
#define CERTDIR "/home/mcmanus/proxycerts"
#define CERTNICK "pgo server certificate"

// this is the backend H1 proxy
#define GWPORT 3128
#define GWHOST 0x7f000001

#if 0
 README
   clang++ -g -I ../../../obj-debug-scratch/dist/include/ -I ../../../obj-debug-scratch/dist/include/nss -L ../../../obj-debug-scratch/dist/lib/ -I ../../../obj-debug-scratch/dist/include/nspr/ proxy.cpp ../../../obj-debug-scratch/dist/lib/libssl3.so ../../../obj-debug-scratch/dist/lib/libnss3.so -lnspr4

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


PRFileDesc *udp_socket = NULL;
PRDescIdentity identity;
PRIOMethods cryptoMethods;

CERTCertificate *cert;
SECKEYPrivateKey *privKey;

// todo put these in shared header
#define MTU 1400
#define UUIDSIZE 20
#define PAYLOADSIZE (MTU - UUIDSIZE)
#define CLEARTEXTPAYLOADSIZE (PAYLOADSIZE - 64)

class flowID;
class flowID *hash[256];

class flowID
{
public:
  flowID(unsigned char *aUUID, PRNetAddr *sin)
  : tcp(-1)
  {
    // two layers of IO Methods - on the top is dtls, and below it are the sdt layers;
    // cleartext gets written into the fd, changed to ciphertext and then given to the sdt
    // layer which is EncryptAndForward. It takes the ciphertext and writes it to the
    // global muxed udp FD (src port 7000), using send_to of the port associated with this uuid.
    // On the read side, data is read off the global muxxed fd (7000) and the uuid is taken from
    // the front and used to find the per flow fd. that fd is then read from and the bottom sdt
    // handler knows where the ciphertext read from the globalfd lives, and passes it up to the
    // dtls handler which decrypts returns cleartext.

    unsigned char id = HashID(aUUID);
    memcpy (uuid, aUUID, UUIDSIZE);
    next = hash[id];
    hash[id] = this;
    memcpy (&udpPeer, sin, sizeof(PRNetAddr));
    crypto = PR_CreateIOLayerStub(identity, &cryptoMethods);
    crypto->secret = (PRFilePrivate *)this;
    crypto = DTLS_ImportFD(NULL, crypto);

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
    if (crypto) {
      PR_Close(crypto);
    }
  }

  static unsigned char HashID(unsigned char *aUUID)
  {
    unsigned char id = aUUID[0];
    for (unsigned int i = 1; i < UUIDSIZE; ++i) {
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
      fprintf(stdout, "tcp connect failed\n");
    } else {
      fprintf(stdout, "tcp connect ok\n");
    }
  }

  static int32_t sDecrypt1(PRFileDesc *fd, void *aBuf, int32_t aAmount)
  {
    return sDecrypt(fd, aBuf, aAmount, 0, PR_INTERVAL_NO_WAIT);
  }

  static int32_t sDecrypt(PRFileDesc *fd, void *aBuf, int32_t aAmount,
                          int , PRIntervalTime)
  {
    if (aAmount == 0) {
      return 0;
    }

    flowID *self = reinterpret_cast<flowID *>(fd->secret);
    if (aAmount > self->toDecryptLen) {
      aAmount = self->toDecryptLen;
    }
    if (aAmount < 1) {
      PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
      return -1;
    }
    memcpy(aBuf, self->toDecrypt, aAmount);
    self->toDecrypt += aAmount;
    self->toDecryptLen -= aAmount;
    return aAmount;
  }

  static PRStatus sGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
  {
    flowID *self = reinterpret_cast<flowID *>(fd->secret);
    memcpy(addr, &self->udpPeer, sizeof(PRNetAddr));
    return PR_SUCCESS;
  }

  static PRStatus sGetSocketOption(PRFileDesc *aFD, PRSocketOptionData *aOpt)
  {
    if (aOpt->option == PR_SockOpt_Nonblocking) {
      aOpt->value.non_blocking = PR_TRUE;
      return PR_SUCCESS;
    }
    return PR_FAILURE;
  }

  void decryptAndForward(unsigned char *buf, unsigned int l)
  {
    // take ciphertext from front, decrypt, and send as plaintext to tcp on back
    unsigned char clearTextBuf[MTU*2];
    int rlen;
    int subtotal = 0;

    // the read from crypto will pull data from toDecrypt in ::sDecrypt()
    toDecrypt = buf;
    toDecryptLen = l;
    do {
      fprintf(stderr,"before decypt we have %d input\n", toDecryptLen);
      rlen = PR_Read(crypto, clearTextBuf, MTU * 2);
      fprintf(stderr,"after decypt we have %d input rlen=%d\n", toDecryptLen, rlen);
      if (rlen > 0) {
        fprintf(stdout, "forward %d of decrypted cipher to backend\n", rlen);
        forward(clearTextBuf, rlen);
      } else if ((rlen == -1) && (PR_GetError() == PR_WOULD_BLOCK_ERROR)) {
        rlen = 1; // fake it to reloop
      }
    } while ((rlen > 0) && (toDecryptLen > 0));
  }

  void forward(unsigned char *buf, unsigned int l)
  {
    // todo partial writes, etc..
    if (tcp == -1) {
      return;
    }
    write (tcp, buf, l);
  }

  static int32_t sEncryptAndForward1(PRFileDesc *fd, const void *aBuf, int32_t aAmount)
  {
    return sEncryptAndForward(fd, aBuf, aAmount, 0, PR_INTERVAL_NO_WAIT);
  }

  static int32_t sEncryptAndForward(PRFileDesc *fd, const void *aBuf, int32_t aAmount,
                                    int, PRIntervalTime)
  {
    flowID *self = reinterpret_cast<flowID *>(fd->secret);
    // aBuf contains ciphertext.. our job is to frame it and send it via udp
    assert(aAmount <= PAYLOADSIZE); // to be removed (runtime error)
    unsigned char frame[MTU];
    memcpy (frame, self->uuid, UUIDSIZE);
    memcpy(frame + UUIDSIZE, (unsigned char *)aBuf, aAmount);
    int sr = PR_SendTo(udp_socket, frame, UUIDSIZE + aAmount, 0,
                       &self->udpPeer, PR_INTERVAL_NO_WAIT);
    fprintf(stdout,"udp socket reply send %d\n", sr);
    return (sr >= UUIDSIZE) ? (sr - UUIDSIZE) : -1;
  }

  void reverse()
  {
    if (tcp == -1) {
      return;
    }

    unsigned char cleartext[CLEARTEXTPAYLOADSIZE]; // todo member with fixed uuid
    int rr = recv(tcp, cleartext, CLEARTEXTPAYLOADSIZE, MSG_DONTWAIT);
    if (rr > 0) {
      fprintf(stdout,"tcp socket read %d\n", rr);

      // we have cleartext.. we need to turn it into ciphertext and
      // stick a uuid on the front of it

      int offset = 0;
      do {
        // each call to PR_Write will take some plaintext encrypt
        // it.. and then call EncryptAndForward on with the ciphertext which will
        // put a frame on it and sent it out
        int iw = PR_Write(crypto, cleartext + offset, rr);
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

  static void setupMethods()
  {
    cryptoMethods = *PR_GetDefaultIOMethods();
    cryptoMethods.read = sDecrypt1;
    cryptoMethods.recv = sDecrypt;
    cryptoMethods.write = sEncryptAndForward1;
    cryptoMethods.send = sEncryptAndForward;
    cryptoMethods.getpeername = sGetPeerName;
    cryptoMethods.getsocketoption = sGetSocketOption;
  }

  PRNetAddr udpPeer;
  unsigned char uuid[UUIDSIZE];
  class flowID *next;
  int tcp;
  unsigned char *toDecrypt;
  unsigned int toDecryptLen;
  PRFileDesc *crypto;
};

class flowID *
findFlow(unsigned char *uuid, PRNetAddr *sin, bool makeIt)
{
  unsigned char id = flowID::HashID(uuid);
  class flowID *rv;

  for (rv = hash[id]; rv; rv = rv->next) {
    if (!memcmp(rv->uuid, uuid, UUIDSIZE)) {
      break;
    }
  }
  if (!rv && makeIt) {
    rv = new flowID(uuid, sin);
  }
  return rv;
}

// bogus password func, just don't use passwords. :-P
char* password_func(PK11SlotInfo* slot, PRBool retry, void* arg)
{
  if (retry) {
    return NULL;
  }
  return strdup("");
}

int main()
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

  flowID::setupMethods();

  PRNetAddr sin;
  sin.inet.family = PR_AF_INET;
  sin.inet.port = htons(7000);
  sin.inet.ip = 0;

  identity = PR_GetUniqueIdentity("sdt-crypto");
  udp_socket = PR_OpenUDPSocket(AF_INET);
  PR_Bind(udp_socket, &sin);

  // a flow table.. uid to fd and fd is a tcp connect to proxy
  // write each message to the proxy
  // then need to mux reads from that set of fds and the udp_socket

  unsigned char cipheredBuf[MTU + 1];
  while (1) {
    bool didWork = false;
    int rlen = PR_RecvFrom(udp_socket, cipheredBuf, MTU + 1, 0, &sin, PR_INTERVAL_NO_WAIT);
    assert (rlen <= MTU); // to be removed (runtime error)
    if (rlen >= UUIDSIZE) {
      class flowID *flow = findFlow(cipheredBuf, &sin, true);
      fprintf(stdout, "udp read %d %p port %d\n", rlen, flow, ntohs(sin.inet.port));

      flow->ensureConnect();
      flow->decryptAndForward(cipheredBuf + UUIDSIZE, rlen - UUIDSIZE);
      didWork = true;
    }

    // this is obviously nothing more than a poc hack that needs todo poll()
    for (unsigned int i = 0; i < 256; ++i) {
      for (flowID *f = hash[i]; f ; f = f->next) {
        f->reverse();
      }
    }

    if (!didWork) {
      usleep(5000); // 5ms
    }
  }
  return 0;
}
