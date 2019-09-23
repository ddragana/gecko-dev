/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef NeqoHttp3Conn_h__
#define NeqoHttp3Conn_h__

#include "mozilla/net/neqo_glue_ffi.h"

namespace mozilla {
namespace net {

class NeqoHttp3Conn final {
 public:
  static nsresult Init(const nsACString *origin,
                       const nsACString *alpn,
                       const nsACString *local_addr,
                       const nsACString *remote_addr,
                       uint32_t max_table_size,
                       uint16_t max_blocked_streams,
                       NeqoHttp3Conn** aConn) {
    return neqo_http3conn_new(origin, alpn, local_addr, remote_addr,
        max_table_size, max_blocked_streams, aConn);
  }

  void Close(uint64_t aError) {
    neqo_http3conn_close(this, aError);
  }

  nsresult GetSecInfo(NeqoSecretInfo *aSecInfo) {
    return neqo_http3conn_tls_info(this, aSecInfo);
  }

  nsresult PeerCertificateInfo(NeqoCertificateInfo *aCertInfo) {
      return neqo_http3conn_peer_certificate_info(this, aCertInfo);
  }

  void PeerAuthenticated(PRErrorCode error) {
    neqo_http3conn_authenticated(this, error);
  }

  void ProcessInput(uint8_t *aPacket, uint32_t aLen) {
    neqo_http3conn_process_input(this, aPacket, aLen);
  }

  void ProcessHttp3() {
    neqo_http3conn_process_http3(this);
  }

  uint64_t ProcessOutput() {
    return neqo_http3conn_process_output(this);
  }

  nsresult GetDataToSend(nsTArray<uint8_t> &data) {
    data.TruncateLength(0);
    return neqo_http3conn_get_data_to_send(this, &data);
  }

  Http3Event GetEvent() {
    return neqo_http3conn_event(this);
  }

  nsresult Fetch(const nsACString *aMethod, const nsACString *aScheme,
      const nsACString *aHost, const nsACString *aPath, const nsACString *aHeaders,
      uint64_t *aStreamId) {
    return neqo_http3conn_fetch(this, aMethod, aScheme, aHost, aPath, aHeaders, aStreamId);
  }

  nsresult SendRequestBody(uint64_t aStreamId, const uint8_t* aBuf, uint32_t aCount,
      uint32_t* aCountRead) {
    return neqo_htttp3conn_send_request_body(this, aStreamId, aBuf, aCount, aCountRead);
  }

  // This closes only the sending side of a stream.
  nsresult CloseStream(uint64_t aStreamId) {
    return neqo_http3conn_close_stream(this, aStreamId);
  }
  nsresult ReadResponseHeaders(uint64_t aStreamId, nsTArray<uint8_t> *aHeaders, bool *fin) {
    return neqo_http3conn_read_response_headers(this, aStreamId, aHeaders, fin);
  }

  nsresult ReadResponseData(uint64_t aStreamId, uint8_t *aBuf, uint32_t aLen, uint32_t *aRead, bool *aFin) {
    return neqo_http3conn_read_response_data(this, aStreamId, aBuf, aLen, aRead, aFin);
  }

  void ResetStream(uint64_t aStreamId, uint64_t aError) {
    neqo_http3conn_reset_stream(this, aStreamId, aError);
  }

  nsrefcnt AddRef() { return neqo_http3conn_addref(this); }
  nsrefcnt Release() { return neqo_http3conn_release(this); }

 private:
  NeqoHttp3Conn();  /* never defined */
  ~NeqoHttp3Conn(); /* never defined */
  NeqoHttp3Conn(const NeqoHttp3Conn&) = delete;
  NeqoHttp3Conn& operator=(const NeqoHttp3Conn&) = delete;

};

}
}

#endif
