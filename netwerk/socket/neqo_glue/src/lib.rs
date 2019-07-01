/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//extern crate neqo_http3;
use neqo_common::Datagram;
use neqo_http3::Http3Connection;
use neqo_transport::connection::Connection;

extern crate xpcom;
use std::net::SocketAddr;
use xpcom::interfaces::nsrefcnt;
use xpcom::{AtomicRefcnt, RefCounted, RefPtr};

use neqo_crypto::init_db;

extern crate nserror;
use nserror::*;

extern crate nsstring;
use nsstring::*;

use std::ops;
use std::ptr;
use std::slice;
use std::str;
use std::time::Instant;

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
        init_db(
            " /Users/draganadamjanovic/dragana_work/gecko-dev/netwerk/socket/neqo/test-fixture/db",
        );

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

#[no_mangle]
pub extern "C" fn neqo_http3conn_process_input(
    conn: &mut NeqoHttp3Conn,
    packet: *const u8,
    len: u32,
) {
    let mut input = Vec::new();
    unsafe {
        let array: &[u8] = slice::from_raw_parts(packet, len as usize);
        input.push(Datagram::new(
            conn.remote_addr,
            conn.local_addr,
            array.to_vec(),
        ));
    }
    conn.conn.process_input(input.drain(..), Instant::now());
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_process_http3(conn: &mut NeqoHttp3Conn) {
    conn.conn.process_http3(Instant::now());
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_process_output(conn: &mut NeqoHttp3Conn) -> u64 {
    let (mut datagrams, timeout) = conn.conn.process_output(Instant::now());
    conn.packets_to_send.append(&mut datagrams);
    match timeout {
        Some(t) => (t.as_micros() as u64),
        None => std::u64::MAX,
    }
}

#[repr(C)]
pub struct Buffer {
    data: *mut u8,
    len: u32,
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_get_data_to_send(conn: &mut NeqoHttp3Conn) -> Buffer {
    match conn.packets_to_send.pop() {
        None => Buffer {
            data: ptr::null_mut(),
            len: 0,
        },
        Some(d) => {
            let mut buf: Vec<u8> = d.to_vec();
            let data = buf.as_mut_ptr();
            let len = buf.len();
            std::mem::forget(buf);
            Buffer {
                data: data,
                len: len as u32,
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_forget_buffer(buf: Buffer) {
    let s = unsafe { std::slice::from_raw_parts_mut(buf.data, buf.len as usize) };
    let s = s.as_mut_ptr();
    unsafe {
        Box::from_raw(s);
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_close(conn: &mut NeqoHttp3Conn, error: Http3AppError) {
    conn.conn.close(Instant::now(), error.code(), "");
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_fetch(
    conn: &mut NeqoHttp3Conn,
    method: &nsACString,
    scheme: &nsACString,
    host: &nsACString,
    path: &nsACString,
    headers: &nsACString,
    stream_id: *mut u64,
) -> nsresult {
    let mut hdrs = Vec::new();
    unsafe {
        let hdrs_str: Vec<&str> = headers.as_str_unchecked().split("\r\n").collect();
        // this is only used for headers built by Firefox.
        let mut skip_first = true;
        for elem in hdrs_str.iter() {
            if skip_first {
                skip_first = false;
            } else {
                if elem.starts_with(":") {
                    // colon headers are for http/2 and 3 and this is http/1 input, so that
                    // is probably a smuggling attack of some kind
                    continue;
                }
                if elem.len() == 0 {
                    continue;
                }
                let hdr_str: Vec<&str> = elem.splitn(2, ":").collect();
                let name = hdr_str[0].to_lowercase();
                let mut value = String::new();
                if hdr_str.len() > 1 {
                    value = String::from(hdr_str[1]);
                }

                hdrs.push((name, value));
            }
        }

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
    MalformedFrame(u16),
    DecompressionFailed,
    EncoderStreamError,
    DecoderStreamError,
}

impl Http3AppError {
    pub fn from_code(error: u16) -> Http3AppError {
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
            0x100...0x1ff => Http3AppError::MalformedFrame(error - 0x100),
            0x200 => Http3AppError::DecompressionFailed,
            0x201 => Http3AppError::EncoderStreamError,
            0x202 => Http3AppError::DecoderStreamError,
            _ => Http3AppError::InternalError,
        }
    }

    pub fn code(&self) -> neqo_transport::AppError {
        match self {
            Http3AppError::NoError => 0,
            Http3AppError::WrongSettingsDirection => 1,
            Http3AppError::PushRefused => 2,
            Http3AppError::InternalError => 3,
            Http3AppError::PushAlreadyInCache => 4,
            Http3AppError::RequestCancelled => 5,
            Http3AppError::IncompleteRequest => 6,
            Http3AppError::ConnectError => 7,
            Http3AppError::ExcessiveLoad => 8,
            Http3AppError::VersionFallback => 9,
            Http3AppError::WrongStream => 10,
            Http3AppError::LimitExceeded => 11,
            Http3AppError::DuplicatePush => 12,
            Http3AppError::UnknownStreamType => 13,
            Http3AppError::WrongStreamCount => 14,
            Http3AppError::ClosedCriticalStream => 15,
            Http3AppError::WrongStreamDirection => 16,
            Http3AppError::EarlyResponse => 17,
            Http3AppError::MissingSettings => 18,
            Http3AppError::UnexpectedFrame => 19,
            Http3AppError::RequestRejected => 20,
            Http3AppError::GeneralProtocolError => 0xff,
            Http3AppError::MalformedFrame(t) => match t {
                0...0xfe => (*t as neqo_transport::AppError) + 0x100,
                _ => 0x1ff,
            },
            Http3AppError::DecompressionFailed => 0x200,
            Http3AppError::EncoderStreamError => 0x201,
            Http3AppError::DecoderStreamError => 0x202,
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_reset_stream(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    error: Http3AppError,
) -> nsresult {
    match conn.conn.stream_reset(stream_id, error.code()) {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

// TODO when sending request body has been implemented.
#[no_mangle]
pub extern "C" fn neqo_http3conn_close_stream(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
) -> nsresult {
    match conn.conn.stream_close_send(Instant::now(), stream_id) {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

#[repr(C)]
pub enum Http3Event {
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
    ConnectionConnected,
    GoawayReceived,
    ConnectionClosing,
    ConnectionClosed,
    NoEvent,
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_event(conn: &mut NeqoHttp3Conn) -> Http3Event {
    if conn.events.is_empty() {
        conn.events = conn.conn.events();
    }
    match conn.events.pop() {
        None => Http3Event::NoEvent,
        Some(e) => e.into(),
    }
}

impl From<neqo_http3::Http3Event> for Http3Event {
    fn from(event: neqo_http3::Http3Event) -> Self {
        match event {
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
            neqo_http3::Http3Event::ConnectionConnected => Http3Event::ConnectionConnected,
            neqo_http3::Http3Event::GoawayReceived => Http3Event::GoawayReceived,
            neqo_http3::Http3Event::ConnectionClosing => Http3Event::ConnectionClosing,
            neqo_http3::Http3Event::ConnectionClosed { .. } => Http3Event::ConnectionClosed,
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_get_headers(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    headers: &mut nsCString,
) -> nsresult {
    match conn.conn.get_headers(stream_id) {
        Ok(res) => {
            let mut res_str = String::new();
            if let Some(h) = res {
                for elem in h.iter() {
                    if elem.0 == ":status" {
                        res_str.push_str("HTTP/3.0 ");
                        res_str.push_str(&elem.1[..]);
                        res_str.push('\r');
                        res_str.push('\n');
                    }
                }
                for elem in h.iter() {
                    if elem.0 != ":status" {
                        res_str.push_str(&elem.0[..]);
                        res_str.push_str(": ");
                        res_str.push_str(&elem.1[..]);
                        res_str.push('\r');
                        res_str.push('\n');
                    }
                }
                res_str.push('\r');
                res_str.push('\n');
            }
            let mut r = nsCString::from(res_str);
            headers.take_from(&mut r);
            NS_OK
        }
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_read_data(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    buf: *mut u8,
    len: u32,
    read: *mut u32,
    fin: *mut bool,
) -> nsresult {
    unsafe {
        let array: &mut [u8] = slice::from_raw_parts_mut(buf, len as usize);
        match conn
            .conn
            .read_data(Instant::now(), stream_id, &mut array[..])
        {
            Ok(r) => {
                *read = r.0 as u32;
                *fin = r.1;
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
}
