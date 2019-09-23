/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Generated with cbindgen:0.9.0 */

/* DO NOT MODIFY THIS MANUALLY! This file was generated using cbindgen.
 */

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>
#include "certt.h"
#include "prerror.h"

namespace mozilla {
namespace net {

template<typename T>
struct Vec;

struct Http3AppError {
  enum class Tag {
    NoError,
    WrongSettingsDirection,
    PushRefused,
    InternalError,
    PushAlreadyInCache,
    RequestCancelled,
    IncompleteRequest,
    ConnectError,
    ExcessiveLoad,
    VersionFallback,
    WrongStream,
    LimitExceeded,
    DuplicatePush,
    UnknownStreamType,
    WrongStreamCount,
    ClosedCriticalStream,
    WrongStreamDirection,
    EarlyResponse,
    MissingSettings,
    UnexpectedFrame,
    RequestRejected,
    GeneralProtocolError,
    MalformedFrame,
    DecompressionFailed,
    EncoderStreamError,
    DecoderStreamError,
  };

  struct MalformedFrame_Body {
    uint64_t _0;
  };

  Tag tag;
  union {
    MalformedFrame_Body malformed_frame;
  };
};

struct QuicTransportError {
  enum class Tag {
    NoError,
    InternalError,
    ServerBusy,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ProtocolViolation,
    InvalidMigration,
    CryptoAlert,
  };

  struct CryptoAlert_Body {
    uint8_t _0;
  };

  Tag tag;
  union {
    CryptoAlert_Body crypto_alert;
  };
};

struct CloseError {
  enum class Tag {
    QuicTransportError,
    Http3AppError,
  };

  struct QuicTransportError_Body {
    QuicTransportError _0;
  };

  struct Http3AppError_Body {
    Http3AppError _0;
  };

  Tag tag;
  union {
    QuicTransportError_Body quic_transport_error;
    Http3AppError_Body http3_app_error;
  };
};

struct Http3Event {
  enum class Tag {
    /// A request stream has space for more data to be send.
    DataWritable,
    /// A server has send STOP_SENDING frame.
    StopSending,
    HeaderReady,
    /// New bytes available for reading.
    DataReadable,
    /// Peer reset the stream.
    Reset,
    /// A new push stream
    NewPushStream,
    RequestsCreatable,
    AuthenticationNeeded,
    ConnectionConnected,
    GoawayReceived,
    ConnectionClosing,
    ConnectionClosed,
    NoEvent,
  };

  struct DataWritable_Body {
    uint64_t stream_id;
  };

  struct StopSending_Body {
    uint64_t stream_id;
  };

  struct HeaderReady_Body {
    uint64_t stream_id;
  };

  struct DataReadable_Body {
    uint64_t stream_id;
  };

  struct Reset_Body {
    uint64_t stream_id;
    Http3AppError error;
  };

  struct NewPushStream_Body {
    uint64_t stream_id;
  };

  struct ConnectionClosing_Body {
    CloseError error;
  };

  struct ConnectionClosed_Body {
    CloseError error;
  };

  Tag tag;
  union {
    DataWritable_Body data_writable;
    StopSending_Body stop_sending;
    HeaderReady_Body header_ready;
    DataReadable_Body data_readable;
    Reset_Body reset;
    NewPushStream_Body new_push_stream;
    ConnectionClosing_Body connection_closing;
    ConnectionClosed_Body connection_closed;
  };
};

class NeqoHttp3Conn;

struct NeqoSecretInfo {
  bool set;
  uint16_t version;
  uint16_t cipher;
  uint16_t group;
  bool resumed;
  bool early_data;
  nsCString alpn;
  uint16_t signature_scheme;
};

struct NeqoCertificateInfo {
  nsTArray<nsTArray<uint8_t>> certs;
  bool stapled_ocsp_responses_present;
  nsTArray<nsTArray<uint8_t>> stapled_ocsp_responses;
  bool signed_cert_timestamp_present;
  nsTArray<uint8_t> signed_cert_timestamp;
};

extern "C" {

nsrefcnt neqo_http3conn_addref(const NeqoHttp3Conn *conn);

void neqo_http3conn_authenticated(NeqoHttp3Conn *conn, PRErrorCode error);

void neqo_http3conn_close(NeqoHttp3Conn *conn, uint64_t error);

nsresult neqo_http3conn_close_stream(NeqoHttp3Conn *conn, uint64_t stream_id);

Http3Event neqo_http3conn_event(NeqoHttp3Conn *conn);

nsresult neqo_http3conn_fetch(NeqoHttp3Conn *conn,
                              const nsACString *method,
                              const nsACString *scheme,
                              const nsACString *host,
                              const nsACString *path,
                              const nsACString *headers,
                              uint64_t *stream_id);

nsresult neqo_http3conn_get_data_to_send(NeqoHttp3Conn *conn, nsTArray<uint8_t> *packet);

nsresult neqo_http3conn_new(const nsACString *origin,
                            const nsACString *alpn,
                            const nsACString *local_addr,
                            const nsACString *remote_addr,
                            uint32_t max_table_size,
                            uint16_t max_blocked_streams,
                            NeqoHttp3Conn **result);

nsresult neqo_http3conn_peer_certificate_info(NeqoHttp3Conn *conn,
                                              NeqoCertificateInfo *neqo_certs_info);

void neqo_http3conn_process_http3(NeqoHttp3Conn *conn);

void neqo_http3conn_process_input(NeqoHttp3Conn *conn, const uint8_t *packet, uint32_t len);

uint64_t neqo_http3conn_process_output(NeqoHttp3Conn *conn);

nsresult neqo_http3conn_read_response_data(NeqoHttp3Conn *conn,
                                           uint64_t stream_id,
                                           uint8_t *buf,
                                           uint32_t len,
                                           uint32_t *read,
                                           bool *fin);

nsresult neqo_http3conn_read_response_headers(NeqoHttp3Conn *conn,
                                              uint64_t stream_id,
                                              nsTArray<uint8_t> *headers,
                                              bool *fin);

nsrefcnt neqo_http3conn_release(const NeqoHttp3Conn *conn);

nsresult neqo_http3conn_reset_stream(NeqoHttp3Conn *conn, uint64_t stream_id, uint64_t error);

nsresult neqo_http3conn_tls_info(NeqoHttp3Conn *conn, NeqoSecretInfo *secInfo);

nsresult neqo_htttp3conn_send_request_body(NeqoHttp3Conn *conn,
                                           uint64_t stream_id,
                                           const uint8_t *buf,
                                           uint32_t len,
                                           uint32_t *read);

} // extern "C"

} // namespace net
} // namespace mozilla
