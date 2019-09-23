/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use neqo_common::Datagram;
use neqo_crypto::{AuthenticationStatus, PRErrorCode, init};
use neqo_http3::Http3Connection;
use neqo_transport::{Connection, Output};

extern crate nserror;
use nserror::*;

extern crate nsstring;
use nsstring::*;

use std::net::SocketAddr;
use std::ops;
use std::ptr;
use std::slice;
use std::str;
use std::time::Instant;

use thin_vec::ThinVec;

extern crate xpcom;
use xpcom::interfaces::nsrefcnt;
use xpcom::{AtomicRefcnt, RefCounted, RefPtr};

#[repr(C)]
pub struct NeqoHttp3Conn {
    pub conn: Http3Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    refcnt: AtomicRefcnt,
    packets_to_send: Vec<Datagram>,
    events: Vec<neqo_http3::Http3Event>,
}

impl NeqoHttp3Conn {
    pub fn new(
        origin: &nsACString,
        alpn: &nsACString,
        local_addr: &nsACString,
        remote_addr: &nsACString,
        max_table_size: u32,
        max_blocked_streams: u16,
    ) -> Result<RefPtr<NeqoHttp3Conn>, nsresult> {
        init();

        let origin_conv = match str::from_utf8(origin) {
            Ok(v) => v,
            Err(_) => return Err(NS_ERROR_INVALID_ARG),
        };

        let alpn_conv = match str::from_utf8(alpn) {
            Ok(v) => v,
            Err(_) => return Err(NS_ERROR_INVALID_ARG),
        };

        let local: SocketAddr = match str::from_utf8(local_addr) {
            Ok(s) => match s.parse() {
                Ok(addr) => addr,
                Err(_) => return Err(NS_ERROR_INVALID_ARG),
            },
            Err(_) => return Err(NS_ERROR_INVALID_ARG),
        };

        let remote: SocketAddr = match str::from_utf8(remote_addr) {
            Ok(s) => match s.parse() {
                Ok(addr) => addr,
                Err(_) => return Err(NS_ERROR_INVALID_ARG),
            },
            Err(_) => return Err(NS_ERROR_INVALID_ARG),
        };

        let conn = match Connection::new_client(origin_conv, &[alpn_conv], local, remote) {
            Ok(c) => c,
            Err(_) => return Err(NS_ERROR_INVALID_ARG),
        };

        unsafe {
            match RefPtr::from_raw(Box::into_raw(Box::new(NeqoHttp3Conn {
                conn: Http3Connection::new(conn, max_table_size, max_blocked_streams, None),
                local_addr: local,
                remote_addr: remote,
                refcnt: AtomicRefcnt::new(),
                packets_to_send: Vec::new(),
                events: Vec::new(),
            }))) {
                Some(refp) => Ok(refp),
                None => return Err(NS_ERROR_FAILURE),
            }
        }
    }
}

impl ops::Deref for NeqoHttp3Conn {
    type Target = Http3Connection;
    fn deref(&self) -> &Http3Connection {
        &self.conn
    }
}
impl ops::DerefMut for NeqoHttp3Conn {
    fn deref_mut(&mut self) -> &mut Http3Connection {
        &mut self.conn
    }
}

#[no_mangle]
pub unsafe extern "C" fn neqo_http3conn_addref(conn: &NeqoHttp3Conn) -> nsrefcnt {
    conn.refcnt.inc()
}

#[no_mangle]
pub unsafe extern "C" fn neqo_http3conn_release(conn: &NeqoHttp3Conn) -> nsrefcnt {
    let rc = conn.refcnt.dec();
    if rc == 0 {
        Box::from_raw(conn as *const NeqoHttp3Conn as *mut NeqoHttp3Conn);
    }
    rc
}

// xpcom::RefPtr support
unsafe impl RefCounted for NeqoHttp3Conn {
    unsafe fn addref(&self) {
        neqo_http3conn_addref(self);
    }
    unsafe fn release(&self) {
        neqo_http3conn_release(self);
    }
}

// Allocate a new NeqoHttp3Conn object.
#[no_mangle]
pub extern "C" fn neqo_http3conn_new(
    origin: &nsACString,
    alpn: &nsACString,
    local_addr: &nsACString,
    remote_addr: &nsACString,
    max_table_size: u32,
    max_blocked_streams: u16,
    result: &mut *const NeqoHttp3Conn,
) -> nsresult {
    *result = ptr::null_mut();

    match NeqoHttp3Conn::new(
        origin,
        alpn,
        local_addr,
        remote_addr,
        max_table_size,
        max_blocked_streams,
    ) {
        Ok(http3_conn) => {
            http3_conn.forget(result);
            NS_OK
        }
        Err(e) => e,
    }
}

/* Process a packet.
 * packet holds packet data.
 */
#[no_mangle]
pub extern "C" fn neqo_http3conn_process_input(
    conn: &mut NeqoHttp3Conn,
    packet: *const u8,
    len: u32,
) {
    let array: &[u8];
    unsafe {
        array = slice::from_raw_parts(packet, len as usize);
    }
    conn.conn.process_input(
        Datagram::new(conn.remote_addr, conn.local_addr, array.to_vec()),
        Instant::now(),
    );
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_process_http3(conn: &mut NeqoHttp3Conn) {
    conn.conn.process_http3(Instant::now());
}

/* Process output and store data to be sent into conn.packets_to_send.
 * neqo_http3conn_get_data_to_send will be called to pick up this data.
 */
#[no_mangle]
pub extern "C" fn neqo_http3conn_process_output(conn: &mut NeqoHttp3Conn) -> u64 {
    loop {
        let out = conn.conn.process_output(Instant::now());
        match out {
            Output::Datagram(dg) => {
                conn.packets_to_send.push(dg);
            }
            Output::Callback(to) => {
                let timeout = to.as_millis() as u64;
                break timeout;
            }
            Output::None => break std::u64::MAX,
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_get_data_to_send(conn: &mut NeqoHttp3Conn, packet: &mut ThinVec<u8>) -> nsresult {
    match conn.packets_to_send.pop() {
        None => NS_BASE_STREAM_WOULD_BLOCK,
        Some(d) => {
            packet.extend_from_slice(&d);
            NS_OK
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_close(conn: &mut NeqoHttp3Conn, error: u64) {
    conn.conn.close(Instant::now(), error, "");
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_fetch(
    conn: &mut NeqoHttp3Conn,
    method: &nsACString,
    scheme: &nsACString,
    host: &nsACString,
    path: &nsACString,
    headers: &nsACString,
    stream_id: &mut u64,
) -> nsresult {
    let mut hdrs = Vec::new();
    // this is only used for headers built by Firefox.
    // Firefox supply all headers already prepared for sending over http1.
    // They need to be split into (String, String) pairs.
    unsafe {
        for elem in headers.as_str_unchecked().split("\r\n").skip(1) {
            if elem.starts_with(":") {
                // colon headers are for http/2 and 3 and this is http/1 input, so that
                // is probably a smuggling attack of some kind
                continue;
            }
            if elem.len() == 0 {
                continue;
            }
            let hdr_str: Vec<&str> = elem.splitn(2, ":").collect();
            let name = hdr_str[0].trim().to_lowercase();
            let mut value = String::new();
            if hdr_str.len() > 1 {
                value = String::from(hdr_str[1].trim());
            }

            hdrs.push((name, value));
        }
    }

    unsafe {
        match conn.conn.fetch(
            method.as_str_unchecked(),
            scheme.as_str_unchecked(),
            host.as_str_unchecked(),
            path.as_str_unchecked(),
            &hdrs,
        ) {
            Ok(id) => {
                *stream_id = id;
                NS_OK
            }
            Err(e) => {
                if e == neqo_http3::Error::TransportError(neqo_transport::Error::StreamLimitError) {
                    NS_BASE_STREAM_WOULD_BLOCK
                } else {
                    NS_ERROR_UNEXPECTED
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_htttp3conn_send_request_body(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    buf: *const u8,
    len: u32,
    read: &mut u32,
) -> nsresult {
    let array: &[u8];
    unsafe {
        array = slice::from_raw_parts(buf, len as usize);
    }
    match conn.conn.send_request_body(stream_id, array) {
        Ok(amount) => {
            *read = amount as u32;
            if amount == 0 {
                NS_BASE_STREAM_WOULD_BLOCK
            } else {
                NS_OK
            }
        },
        Err(_) => {
            NS_ERROR_UNEXPECTED
        }
    }
}

// This error codes are not used currently, they will be used for telemetry.
#[repr(C)]
pub enum Http3AppError {
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
    MalformedFrame(u64),
    DecompressionFailed,
    EncoderStreamError,
    DecoderStreamError,
}

impl Http3AppError {
    pub fn from_code(error: u64) -> Http3AppError {
        match error {
            0 => Http3AppError::NoError,
            1 => Http3AppError::WrongSettingsDirection,
            2 => Http3AppError::PushRefused,
            3 => Http3AppError::InternalError,
            4 => Http3AppError::PushAlreadyInCache,
            5 => Http3AppError::RequestCancelled,
            6 => Http3AppError::IncompleteRequest,
            7 => Http3AppError::ConnectError,
            8 => Http3AppError::ExcessiveLoad,
            9 => Http3AppError::VersionFallback,
            10 => Http3AppError::WrongStream,
            11 => Http3AppError::LimitExceeded,
            12 => Http3AppError::DuplicatePush,
            13 => Http3AppError::UnknownStreamType,
            14 => Http3AppError::WrongStreamCount,
            15 => Http3AppError::ClosedCriticalStream,
            16 => Http3AppError::WrongStreamDirection,
            17 => Http3AppError::EarlyResponse,
            18 => Http3AppError::MissingSettings,
            19 => Http3AppError::UnexpectedFrame,
            20 => Http3AppError::RequestRejected,
            0xff => Http3AppError::GeneralProtocolError,
            0x100..=0x1ff => Http3AppError::MalformedFrame(error - 0x100),
            0x200 => Http3AppError::DecompressionFailed,
            0x201 => Http3AppError::EncoderStreamError,
            0x202 => Http3AppError::DecoderStreamError,
            _ => Http3AppError::InternalError,
        }
    }
}

#[repr(C)]
pub enum QuicTransportError {
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
    CryptoAlert(u8),
}


impl QuicTransportError {
    pub fn from_code(error: u64) -> QuicTransportError {
        match error {
            0 => QuicTransportError::NoError,
            1 => QuicTransportError::InternalError,
            2 => QuicTransportError::ServerBusy,
            3 => QuicTransportError::FlowControlError,
            4 => QuicTransportError::StreamLimitError,
            5 => QuicTransportError::StreamStateError,
            6 => QuicTransportError::FinalSizeError,
            7 => QuicTransportError::FrameEncodingError,
            8 => QuicTransportError::TransportParameterError,
            10 => QuicTransportError::ProtocolViolation,
            12 => QuicTransportError::InvalidMigration,
            0x100..=0x1ff => QuicTransportError::CryptoAlert((error & 0xff) as u8),
            _ => QuicTransportError::InternalError,
        }
    }
}

#[repr(C)]
pub enum CloseError {
    QuicTransportError(QuicTransportError),
    Http3AppError(Http3AppError),
}

impl CloseError {
    pub fn from_neqo_error(error: neqo_transport::CloseError) -> CloseError {
        match error {
            neqo_transport::CloseError::Transport(c) => {
                CloseError::QuicTransportError(QuicTransportError::from_code(c))
            }
            neqo_transport::CloseError::Application(c) => {
                CloseError::Http3AppError(Http3AppError::from_code(c))
            }
        }
    }
}

// Reset a stream with streamId.
#[no_mangle]
pub extern "C" fn neqo_http3conn_reset_stream(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    error: u64,
) -> nsresult {
    match conn.conn.stream_reset(stream_id, error) {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

// Close sending side of a streeam with streamId
#[no_mangle]
pub extern "C" fn neqo_http3conn_close_stream(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
) -> nsresult {
    match conn.conn.stream_close_send(stream_id) {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

#[repr(C)]
pub enum Http3Event {
    /// A request stream has space for more data to be send.
    DataWritable {
        stream_id: u64,
    },
    /// A server has send STOP_SENDING frame.
    StopSending {
        stream_id: u64,
    },
    HeaderReady {
        stream_id: u64,
    },
    /// New bytes available for reading.
    DataReadable {
        stream_id: u64,
    },
    /// Peer reset the stream.
    Reset {
        stream_id: u64,
        error: Http3AppError,
    },
    /// A new push stream
    NewPushStream {
        stream_id: u64,
    },
    RequestsCreatable,
    AuthenticationNeeded,
    ConnectionConnected,
    GoawayReceived,
    ConnectionClosing {
        error: CloseError,
    },
    ConnectionClosed {
        error: CloseError,
    },
    NoEvent,
}

// conn.conn.events() returns multiple events that will be store in
// conn.events. The function returns single even.
#[no_mangle]
pub extern "C" fn neqo_http3conn_event(conn: &mut NeqoHttp3Conn) -> Http3Event {
    if conn.events.is_empty() {
        conn.events = conn.conn.events();
    }
    loop {
        match conn.events.pop() {
            None => break Http3Event::NoEvent,
            Some(e) => {
                let fe: Http3Event = e.into();
                match fe {
                    Http3Event::NoEvent => {},
                    _ => break fe,
                };
            }
        }
    }
}

impl From<neqo_http3::Http3Event> for Http3Event {
    fn from(event: neqo_http3::Http3Event) -> Self {
        match event {
            neqo_http3::Http3Event::DataWritable { stream_id } => Http3Event::DataWritable {
                stream_id: stream_id,
            },
            neqo_http3::Http3Event::StopSending { stream_id, .. } => Http3Event::StopSending {
                stream_id: stream_id,
            },
            neqo_http3::Http3Event::HeaderReady { stream_id } => Http3Event::HeaderReady {
                stream_id: stream_id,
            },
            neqo_http3::Http3Event::DataReadable { stream_id } => Http3Event::DataReadable {
                stream_id: stream_id,
            },
            neqo_http3::Http3Event::Reset { stream_id, error } => Http3Event::Reset {
                stream_id: stream_id,
                error: Http3AppError::from_code(error),
            },
            neqo_http3::Http3Event::NewPushStream { stream_id } => Http3Event::NewPushStream {
                stream_id: stream_id,
            },
            neqo_http3::Http3Event::RequestsCreatable => Http3Event::RequestsCreatable,
            neqo_http3::Http3Event::AuthenticationNeeded => Http3Event::AuthenticationNeeded,
            neqo_http3::Http3Event::GoawayReceived => Http3Event::GoawayReceived,
            neqo_http3::Http3Event::StateChange(state) =>
                match state {
                    neqo_http3::Http3State::Connected => Http3Event::ConnectionConnected,
                    neqo_http3::Http3State::Closing(error_code) => Http3Event::ConnectionClosing {
                        error: CloseError::from_neqo_error(error_code),
                    },
                    neqo_http3::Http3State::Closed(error_code) => Http3Event::ConnectionClosed {
                        error: CloseError::from_neqo_error(error_code),
                    },
                    _ => Http3Event::NoEvent,
                }
        }
    }
}

// Read response headers.
// Firefox needs these headers to look like http1 heeaders, so we are
// building that here.
#[no_mangle]
pub extern "C" fn neqo_http3conn_read_response_headers(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    headers: &mut ThinVec<u8>,
    fin: &mut bool,
) -> nsresult {
    match conn.conn.read_response_headers(stream_id) {
        Ok((h, fin_recvd)) => {

            let status_element: Vec<&(String, String)> = h.iter().filter(|elem| elem.0 == ":status").collect();
            if status_element.len() != 1 {
               return NS_ERROR_ILLEGAL_VALUE;
            }
            headers.extend_from_slice("HTTP/3.0 ".as_bytes());
            headers.extend_from_slice(status_element[0].1.as_bytes());
            headers.extend_from_slice("\r\n".as_bytes());

            for elem in h.iter().filter(|elem| elem.0 != ":status") {
                headers.extend_from_slice(&elem.0.as_bytes());
                headers.extend_from_slice(": ".as_bytes());
                headers.extend_from_slice(&elem.1.as_bytes());
                headers.extend_from_slice("\r\n".as_bytes());
            }
            headers.extend_from_slice("\r\n".as_bytes());
            *fin = fin_recvd;
            NS_OK
        }
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

// Read response data into buf.
#[no_mangle]
pub extern "C" fn neqo_http3conn_read_response_data(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    buf: *mut u8,
    len: u32,
    read: &mut u32,
    fin: &mut bool,
) -> nsresult {
    let array: &mut [u8] = unsafe {slice::from_raw_parts_mut(buf, len as usize)};
        match conn
            .conn
            .read_response_data(Instant::now(), stream_id, &mut array[..])
        {
            Ok((amount, fin_recvd)) => {
                *read = amount as u32;
                *fin = fin_recvd;
                NS_OK
            }
            Err(e) => match e {
                neqo_http3::Error::TransportError(neqo_transport::Error::InvalidStreamId) => {
                    NS_ERROR_INVALID_ARG
                }
                neqo_http3::Error::MalformedFrame(..) => NS_ERROR_ABORT,
                neqo_http3::Error::TransportError(neqo_transport::Error::NoMoreData) => {
                    NS_ERROR_INVALID_ARG
                }
                _ => NS_ERROR_UNEXPECTED,
            },
    }
}

#[repr(C)]
pub struct NeqoSecretInfo {
    set: bool,
    version: u16,
    cipher: u16,
    group: u16,
    resumed: bool,
    early_data: bool,
    alpn: nsCString,
    signature_scheme: u16,
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_tls_info(conn: &mut NeqoHttp3Conn, sec_info: &mut NeqoSecretInfo) -> nsresult {
    match conn.conn.tls_info() {
        Some(info) => {
            sec_info.set = true;
            sec_info.version = info.version();
            sec_info.cipher = info.cipher_suite();
            sec_info.group = info.key_exchange();
            sec_info.resumed = info.resumed();
            sec_info.early_data = info.early_data_accepted();
            sec_info.alpn = match info.alpn() {
                Some(a) => nsCString::from(a),
                None => nsCString::new(),
            };
            sec_info.signature_scheme = info.signature_scheme();
            NS_OK
        },
        None => NS_ERROR_NOT_AVAILABLE
    }
}

#[repr(C)]
pub struct NeqoCertificateInfo {
    certs: ThinVec<ThinVec<u8>>,
    stapled_ocsp_responses_present: bool,
    stapled_ocsp_responses: ThinVec<ThinVec<u8>>,
    signed_cert_timestamp_present: bool,
    signed_cert_timestamp: ThinVec<u8>,
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_peer_certificate_info(
    conn: &mut NeqoHttp3Conn,
    neqo_certs_info: &mut NeqoCertificateInfo,
) -> nsresult {
    let mut certs_info = match conn.peer_certificate() {
        Some(certs) => certs,
        None => return NS_ERROR_NOT_AVAILABLE,
    };

    let certs_vec: Vec<&[u8]> = certs_info.collect();
    for iter in certs_vec.iter() {
        let mut cert: ThinVec<u8> = ThinVec::new();
        cert.extend_from_slice(iter);
        neqo_certs_info.certs.push(cert);
    }

    match certs_info.stapled_ocsp_responses() {
        Some(ocsp_val) => {
            neqo_certs_info.stapled_ocsp_responses_present = true;
            for iter in ocsp_val.iter() {
                let mut ocsp: ThinVec<u8> = ThinVec::new();
                ocsp.extend_from_slice(iter);
                neqo_certs_info.stapled_ocsp_responses.push(ocsp);
            }
        },
        None => { neqo_certs_info.stapled_ocsp_responses_present = false; }
    };

    match certs_info.signed_cert_timestamp() {
        Some(sct_val) => {
            neqo_certs_info.signed_cert_timestamp_present = true;
            neqo_certs_info.signed_cert_timestamp.extend_from_slice(sct_val);
        },
        None => { neqo_certs_info.signed_cert_timestamp_present = false; }
    };

    return NS_OK;
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_authenticated(conn: &mut NeqoHttp3Conn, error: PRErrorCode) {
    conn.authenticated(AuthenticationStatus::from(error), Instant::now());
}
