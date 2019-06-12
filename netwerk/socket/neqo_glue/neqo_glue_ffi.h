/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Generated with cbindgen:0.8.7 */

/* DO NOT MODIFY THIS MANUALLY! This file was generated using cbindgen.
 */

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>

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
    uint16_t _0;
  };

  Tag tag;
  union {
    MalformedFrame_Body malformed_frame;
  };
};

struct Http3Event {
  enum class Tag {
    HeaderReady,
    /// New bytes available for reading.
    DataReadable,
    /// Peer reset the stream.
    Reset,
    /// A new push stream
    NewPushStream,
    RequestsCreatable,
    ConnectionConnected,
    GoawayReceived,
    ConnectionClosing,
    ConnectionClosed,
    NoEvent,
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

  Tag tag;
  union {
    HeaderReady_Body header_ready;
    DataReadable_Body data_readable;
    Reset_Body reset;
    NewPushStream_Body new_push_stream;
  };
};

class NeqoHttp3Conn;

struct Buffer {
  uint8_t *data;
  uint32_t len;
};

extern "C" {

nsrefcnt neqo_http3conn_addref(const NeqoHttp3Conn *conn);

void neqo_http3conn_close(NeqoHttp3Conn *conn, Http3AppError error);

nsresult neqo_http3conn_close_stream(NeqoHttp3Conn *conn, uint64_t stream_id);

Http3Event neqo_http3conn_event(NeqoHttp3Conn *conn);

nsresult neqo_http3conn_fetch(NeqoHttp3Conn *conn,
                              const nsACString *method,
                              const nsACString *scheme,
                              const nsACString *host,
                              const nsACString *path,
                              const nsACString *headers,
                              uint64_t *stream_id);

void neqo_http3conn_forget_buffer(Buffer buf);

Buffer neqo_http3conn_get_data_to_send(NeqoHttp3Conn *conn);

nsresult neqo_http3conn_get_headers(NeqoHttp3Conn *conn, uint64_t stream_id, nsCString *headers);

nsresult neqo_http3conn_new(NeqoHttp3Conn **result);

void neqo_http3conn_process_http3(NeqoHttp3Conn *conn);

void neqo_http3conn_process_input(NeqoHttp3Conn *conn,
                                  const uint8_t *packet,
                                  uint32_t len,
                                  uint64_t cur_time);

uint64_t neqo_http3conn_process_output(NeqoHttp3Conn *conn, uint64_t cur_time);

nsresult neqo_http3conn_read_data(NeqoHttp3Conn *conn,
                                  uint64_t stream_id,
                                  uint8_t *buf,
                                  uint32_t len,
                                  uint32_t *read,
                                  bool *fin);

nsrefcnt neqo_http3conn_release(const NeqoHttp3Conn *conn);

nsresult neqo_http3conn_reset_stream(NeqoHttp3Conn *conn, uint64_t stream_id, Http3AppError error);

} // extern "C"

} // namespace net
} // namespace mozilla
