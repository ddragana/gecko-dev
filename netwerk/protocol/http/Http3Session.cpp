/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=4 sw=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "HttpLog.h"
#include "Http3Stream.h"
#include "DNS.h"
#include "nsHttpHandler.h"
#include "mozilla/RefPtr.h"
#include "ASpdySession.h" // because of SoftStreamError()
#include "nsIOService.h"
#include "nsISSLSocketControl.h"
#include "ScopedNSSTypes.h"
#include "nsSocketTransportService2.h"
#include "nsThreadUtils.h"
#include "cert.h"
#include "sslerr.h"

namespace mozilla {
namespace net {

const uint64_t HTTP3_APP_ERROR_NO_ERROR               = 0x0;
const uint64_t HTTP3_APP_ERROR_GENERAL_PROTOCOL_ERROR = 0x1;
const uint64_t HTTP3_APP_ERROR_INTERNAL_ERROR         = 0x3;
const uint64_t HTTP3_APP_ERROR_REQUEST_CANCELLED      = 0x5;
const uint64_t HTTP3_APP_ERROR_INCOMPLETE_REQUEST     = 0x6;
const uint64_t HTTP3_APP_ERROR_CONNECT_ERROR          = 0x7;
const uint64_t HTTP3_APP_ERROR_EXCESSIVE_LOAD         = 0x8;
const uint64_t HTTP3_APP_ERROR_VERSION_FALLBACK       = 0x9;
const uint64_t HTTP3_APP_ERROR_WRONG_STREAM           = 0xa;
const uint64_t HTTP3_APP_ERROR_ID_ERROR               = 0xb;
const uint64_t HTTP3_APP_ERROR_STREAM_CREATION_ERROR  = 0xd;
const uint64_t HTTP3_APP_ERROR_CLOSED_CRITICAL_STREAM = 0xf;
const uint64_t HTTP3_APP_ERROR_EARLY_RESPONSE         = 0x0011;
const uint64_t HTTP3_APP_ERROR_MISSING_SETTINGS       = 0x0012;
const uint64_t HTTP3_APP_ERROR_UNEXPECTED_FRAME       = 0x0013;
const uint64_t HTTP3_APP_ERROR_REQUEST_REJECTED       = 0x0014;
const uint64_t HTTP3_APP_ERROR_SETTINGS_ERROR         = 0x00ff;

NS_IMPL_ADDREF(Http3Session)
NS_IMPL_RELEASE(Http3Session)
NS_INTERFACE_MAP_BEGIN(Http3Session)
  NS_INTERFACE_MAP_ENTRY(nsAHttpConnection)
  NS_INTERFACE_MAP_ENTRY(nsICertAuthenticationListener)
  NS_INTERFACE_MAP_ENTRY_AMBIGUOUS(nsISupports, nsICertAuthenticationListener)
NS_INTERFACE_MAP_END

Http3Session::Http3Session()
  : mState(INITIALIZING),
    mAuthenticationStarted(false),
    mCleanShutdown(false),
    mGoawayReceived(false),
    mShouldClose(false),
    mError(NS_OK),
    mBeforeConnectedError(false),
    mSegmentReader(nullptr),
    mSegmentWriter(nullptr) {
  mCurrentForegroundTabOuterContentWindowId =
      gHttpHandler->ConnMgr()->CurrentTopLevelOuterContentWindowId();
}

nsresult Http3Session::Init(const nsACString& aOrigin,
    nsISocketTransport* aSocketTransport, nsAHttpSegmentReader* reader,
      nsAHttpSegmentWriter* writer) {
  LOG3(("Http3Session::Init %p", this));
  mSocketTransport = aSocketTransport;
  mSegmentReader = reader;
  mSegmentWriter = writer;

  NetAddr selfAddr;
  if (NS_FAILED(mSocketTransport->GetSelfAddr(&selfAddr))) {
    LOG3(("Http3Session::Init GetSelfAddr failed [this=%p]", this));
    return NS_ERROR_FAILURE;
  }
  char buf[kIPv6CStrBufSize];
  NetAddrToString(&selfAddr, buf, kIPv6CStrBufSize);

  nsAutoCString selfAddrStr;
  if (selfAddr.raw.family == AF_INET6) {
    selfAddrStr.Append("[");
  }
  // Append terminating ']' and port.
  selfAddrStr.Append(buf, strlen(buf));
  if (selfAddr.raw.family == AF_INET6) {
    selfAddrStr.Append("]:");
    selfAddrStr.AppendInt(ntohs(selfAddr.inet6.port));
  } else {
    selfAddrStr.Append(":");
    selfAddrStr.AppendInt(ntohs(selfAddr.inet.port));
  }

  NetAddr peerAddr;
  if (NS_FAILED(mSocketTransport->GetPeerAddr(&peerAddr))) {
    LOG3(("Http3Session::Init GetPeerAddr failed [this=%p]", this));
    return NS_ERROR_FAILURE;
  }
  NetAddrToString(&peerAddr, buf, kIPv6CStrBufSize);

  nsAutoCString peerAddrStr;
  if (peerAddr.raw.family == AF_INET6) {
    peerAddrStr.Append("[");
  }
  peerAddrStr.Append(buf, strlen(buf));
  // Append terminating ']' and port.
  if (peerAddr.raw.family == AF_INET6) {
    peerAddrStr.Append("]:");
    peerAddrStr.AppendInt(ntohs(peerAddr.inet6.port));
  } else {
    peerAddrStr.Append(':');
    peerAddrStr.AppendInt(ntohs(peerAddr.inet.port));
  }

  LOG3(("Http3Session::Init origin=%s, alpn=%s, selfAddr=%s, peerAddr=%s,"
        " qpack table size=%u, max blocked streams=%u [this=%p]",
        PromiseFlatCString(aOrigin).get(),
        PromiseFlatCString(kHttp3Version).get(),
        selfAddrStr.get(), peerAddrStr.get(),
        gHttpHandler->DefaultQpackTableSize(),
        gHttpHandler->DefaultH3MaxBlockedStreams(), this));

  return NeqoHttp3Conn::Init(&aOrigin,
      &kHttp3Version,
      &selfAddrStr, &peerAddrStr,
      gHttpHandler->DefaultQpackTableSize(),
      gHttpHandler->DefaultH3MaxBlockedStreams(),
      getter_AddRefs(mHttp3Connection));
}

void Http3Session::Shutdown() {
  for (auto iter = mStreamTransactionHash.Iter(); !iter.Done(); iter.Next()) {
    nsAutoPtr<Http3Stream>& stream = iter.Data();

    if (mBeforeConnectedError) {
      stream->Close(mError);
    } else if (!stream->HasStreamId()) {
      stream->Transaction()->DoNotRemoveAltSvc();
      stream->Close(NS_ERROR_NET_RESET);
    } else if (stream->RecvdData()) {
      stream->Close(NS_ERROR_NET_PARTIAL_TRANSFER);
    } else {
      stream->Close(NS_ERROR_ABORT);
    }
    RemoveStreamFromQueues(stream);
    if (stream->HasStreamId()) {
      mStreamIdHash.Remove(stream->StreamId());
    }
  }

  mStreamTransactionHash.Clear();
}

Http3Session::~Http3Session() {
  LOG3(("Http3Session::~Http3Session %p", this));

  Shutdown();
}

PRIntervalTime Http3Session::IdleTime() {
  // Seting this value to 0 will never triger PruneDeadConnections for
  // this connection. We want to let neqo-transport perform close on idle
  // connections.
  // TODO check this.
  return 0;
}

nsresult Http3Session::ProcessInput() {
  MOZ_ASSERT(mSegmentWriter);

  LOG(("Http3Session::ProcessInput writer=%p [this=%p]",
       mSegmentWriter, this));

  if (!mSegmentWriter) {
    // the only way this could happen would be if Close() were called on the
    // stack with WriteSegments()
    return NS_ERROR_FAILURE;
  }

  uint8_t packet[2000];
  uint32_t read = 0;
  nsresult rv = mSegmentWriter->OnWriteSegment((char*)packet, 2000, &read);
  if (NS_FAILED(rv)) {
    return rv;
  }
  mHttp3Connection->process_input(packet, read);
  mHttp3Connection->process_http3();
  LOG(("Http3Session::Process status: state=%d [this=%p]",
       mState, this));
  if (mState == INITIALIZING) {
    bool notUsed;
    uint32_t n = 0;
    ProcessEvents(nsIOService::gDefaultSegmentSize, &n, &notUsed);
  }

  return NS_OK;
}

nsresult Http3Session::ProcessEvents(uint32_t count, uint32_t* countWritten,
    bool* again) {
  LOG(("Http3Session::ProcessEvents [this=%p]", this));
  Http3Event event = mHttp3Connection->get_event();

  while (event.tag != Http3Event::Tag::NoEvent) {
    switch (event.tag) {
      case Http3Event::Tag::HeaderReady:
      case Http3Event::Tag::DataReadable:
        {
          MOZ_ASSERT(mState == CONNECTED);
          uint64_t id;
          if (event.tag == Http3Event::Tag::HeaderReady) {
            LOG(("Http3Session::ProcessEvent - HeaderReady"));
            id = event.header_ready.stream_id;
          } else {
            LOG(("Http3Session::ProcessEvent - DataReadable"));
            id = event.data_readable.stream_id;
          }

          Http3Stream* stream = mStreamIdHash.Get(id);
          if (!stream) {
            *again = false;
            Unused << ResumeRecv();
            return NS_OK;
          }

          nsresult rv = NS_OK;
          bool pickupEOF = true; 
          while (pickupEOF) {
            rv = stream->WriteSegments(this, count, countWritten);
            if (ASpdySession::SoftStreamError(rv)) {
              CloseStream(stream,
                  (rv == NS_BINDING_RETARGETED) ? NS_BINDING_RETARGETED : NS_OK);
              *again = false;
              rv = ResumeRecv();
              if (NS_FAILED(rv)) {
                LOG3(("ResumeRecv returned code %x", static_cast<uint32_t>(rv)));
              }
              return NS_OK;
            }
            if (!stream->RecvdFin()) {
              // In RECEIVED_FIN state we need to give the httpTransaction the info
              // that the transaction is closed. This may be done also by changing
              // neqo-http3 events.
              pickupEOF = false;
            }
          }

          if (stream->Done()) {
            LOG3(("Http3Session::ProcessEvent session=%p stream=%p 0x%" PRIX64
                  "cleanup stream.\n", this, stream, stream->StreamId()));
            CloseStream(stream, NS_OK);
          }

          if (NS_FAILED(rv)) {
            LOG3(("Http3Session::ProcessEvent failed rv=%" PRIX32
                  " [this=%p].", static_cast<uint32_t>(rv), this));
            // maybe just blocked reading from network
            if (rv == NS_BASE_STREAM_WOULD_BLOCK) rv = NS_OK;
          }
          return rv;
        }
        break;
      case Http3Event::Tag::Reset:
         LOG(("Http3Session::Process event - Reset"));
         ResetRecvd(event.reset.stream_id, event.reset.error);
         break;
      case Http3Event::Tag::NewPushStream:
         LOG(("Http3Session::Process event - NewPushStream"));
         break;
      case Http3Event::Tag::RequestsCreatable:
         LOG(("Http3Session::Process event - StreamCreatable"));
         ProcessPending();
         break;
      case Http3Event::Tag::AuthenticationNeeded:
         LOG(("Http3Session::Process event - AuthenticationNeeded %d", mAuthenticationStarted));
         if (!mAuthenticationStarted) {
             mAuthenticationStarted =  true;
             LOG(("Http3Session::Process event - AuthenticationNeeded called"));
             CallCertVerification();
         }
         break;
      case Http3Event::Tag::ConnectionConnected:
         {
           LOG(("Http3Session::Process event - ConnectionConnected"));
           mState = CONNECTED;
           nsCOMPtr<nsISupports> securityInfo;
           mSocketTransport->GetSecurityInfo(getter_AddRefs(securityInfo));
           nsCOMPtr<nsISSLSocketControl> ssl = do_QueryInterface(securityInfo);
           MOZ_ASSERT(ssl);
           if (ssl) {
             mHttp3Connection->set_sec_info(ssl);
           }
         }
         break;
      case Http3Event::Tag::GoawayReceived:
         LOG(("Http3Session::Process event - GoawayReceived"));
         MOZ_ASSERT(!mGoawayReceived);
         mGoawayReceived = true;
         break;
      case Http3Event::Tag::ConnectionClosing:
         LOG(("Http3Session::Process event - ConnectionClosing"));
         if (NS_SUCCEEDED(mError)) {
           mError = NS_ERROR_NET_HTTP3_PROTOCOL_ERROR;
         }
         CloseInternal(false);
         break;
      case Http3Event::Tag::ConnectionClosed:
         LOG(("Http3Session::Process event - ConnectionClosed"));
         mState=CLOSED;
         break;
      default:
         break;
    }
    event = mHttp3Connection->get_event();
  }

  *again = false;
  Unused << ResumeRecv();
  return NS_OK;
}

nsresult Http3Session::Process() {
  nsresult rv = ProcessInput();
  if (NS_FAILED(rv) && rv != NS_BASE_STREAM_WOULD_BLOCK) {
    return rv;
  }

  bool notUsed;
  uint32_t n = 0;
  rv = ProcessEvents(nsIOService::gDefaultSegmentSize, &n, &notUsed);
  if (NS_FAILED(rv) && rv != NS_BASE_STREAM_WOULD_BLOCK) {
    return rv;
  }

  rv = ProcessOutput();
  if (NS_FAILED(rv) && rv != NS_BASE_STREAM_WOULD_BLOCK) {
    return rv;
  }

  n = 0;
  return ProcessEvents(nsIOService::gDefaultSegmentSize, &n, &notUsed);
}

nsresult Http3Session::ProcessOutput() {
  MOZ_ASSERT(mSegmentReader);

  LOG(("Http3Session::ProcessOutput reader=%p, [this=%p]",
       mSegmentReader, this));

  nsresult rv = NS_OK;
  if (mPacketToSend.Length()) {
    uint32_t written = 0;
    rv = mSegmentReader->OnReadSegment((const char*)mPacketToSend.Elements(),
        mPacketToSend.Length(), &written);
    if (NS_FAILED(rv)) {
      if ((rv == NS_BASE_STREAM_WOULD_BLOCK) && mConnection) {
        Unused << mConnection->ResumeSend();
      }
      return rv;
    }
    MOZ_ASSERT(written == mPacketToSend.Length());
    mPacketToSend.TruncateLength(0);
  }
  mHttp3Connection->process_http3();
  uint64_t timeout = mHttp3Connection->process_output();
  nsresult getDataRv = mHttp3Connection->get_data_to_send(mPacketToSend);
  LOG(("Http3Session::ProcessOutput sending packet with %d bytes [this=%p].",
       (int32_t)mPacketToSend.Length(), this));
  while (NS_SUCCEEDED(getDataRv) && mPacketToSend.Length()) {
    uint32_t written = 0;
    rv = mSegmentReader->OnReadSegment((const char*)mPacketToSend.Elements(),
        mPacketToSend.Length(), &written);
    if (NS_FAILED(rv)) {
      if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
        if (mConnection) {
           Unused << mConnection->ResumeSend();
        }
      }
      break;
    }
    mPacketToSend.TruncateLength(0);
    getDataRv = mHttp3Connection->get_data_to_send(mPacketToSend);
  }

  SetupTimer(timeout);
  return rv;
}

nsresult Http3Session::ProcessOutputAndEvents() {
  nsresult rv = ProcessOutput();
  if (NS_FAILED(rv)) {
    return rv;
  }
  mHttp3Connection->process_http3();
  bool notUsed;
  uint32_t n = 0;
  Unused << ProcessEvents(nsIOService::gDefaultSegmentSize, &n, &notUsed);
  return NS_OK;
}

void Http3Session::SetupTimer(uint64_t aTimeout) {
  LOG(("Http3Session::SetupTimer to %" PRIu64 "ms [this=%p].",
       aTimeout, this));
  if (!mTimer) mTimer = NS_NewTimer();

  if (!mTimer ||
      NS_FAILED(mTimer->InitWithCallback(this, aTimeout,
                                         nsITimer::TYPE_ONE_SHOT))) {
    NS_DispatchToCurrentThread(
        NewRunnableMethod("net::Http3Session::ProcessOutput", this,
                          &Http3Session::ProcessOutputAndEvents));
  }
}

NS_IMETHODIMP
Http3Session::Notify(nsITimer* aTimer) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  MOZ_ASSERT(aTimer == mTimer, "wrong timer");
  LOG(("Http3Session::Notify [this=%p].", this));
  Unused << ProcessOutputAndEvents();
  return NS_OK;
}

bool Http3Session::AddStream(nsAHttpTransaction* aHttpTransaction,
                     int32_t aPriority,
                     nsIInterfaceRequestor* aCallbacks) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  nsHttpTransaction* trans = aHttpTransaction->QueryHttpTransaction();

  if (!mConnection) {
    mConnection = aHttpTransaction->Connection();
  }

  if (mState == INITIALIZING) {
    // During initial phase we are going to initialize only one transaction
    // to drive handshake.
    if (mStreamTransactionHash.Count() > 0) {
      MOZ_ASSERT(false,
          "During initialization we should activate only one transaction!");
    }
  } else if (IsClosing()) {
    LOG3(
        ("Http3Session::AddStream %p atrans=%p trans=%p session unusable - "
         "resched.\n",
         this, aHttpTransaction, trans));
    aHttpTransaction->SetConnection(nullptr);
    nsresult rv = gHttpHandler->InitiateTransaction(trans, trans->Priority());
    if (NS_FAILED(rv)) {
      LOG3(
          ("Http3Session::AddStream %p atrans=%p trans=%p failed to initiate "
           "transaction (%08x).\n",
           this, aHttpTransaction, trans, static_cast<uint32_t>(rv)));
    }
    return true;
  }

  aHttpTransaction->SetConnection(this);
  aHttpTransaction->OnActivated();

  LOG3(("Http3Session::AddStream %p atrans=%p.\n",
         this, aHttpTransaction));
  Http3Stream* stream = new Http3Stream(aHttpTransaction, this);
  mStreamTransactionHash.Put(aHttpTransaction, stream);

  mReadyForWrite.Push(stream);

  if (mState == INITIALIZING) {
    // Don't call ReadSegments yet, wait untill handshake is done or fails.
    return true;
  }
  // Kick off the SYN transmit without waiting for the poll loop
  // This won't work for the first stream because there is no segment reader
  // yet.
  if (mSegmentReader) {
    uint32_t countRead;
    Unused << ReadSegments(nullptr, kDefaultReadAmount, &countRead);
  }
  return true;
}

bool Http3Session::CanReuse() {
  return (mState == CONNECTED) && !(mGoawayReceived || mShouldClose);
}

void Http3Session::QueueStream(Http3Stream* stream) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  MOZ_ASSERT(!stream->Queued());

  LOG3(("Http3Session::QueueStream %p stream %p queued.", this, stream));

  stream->SetQueued(true);
  mQueuedStreams.Push(stream);
}

void Http3Session::ProcessPending() {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  Http3Stream* stream;
  while ((stream = static_cast<Http3Stream*>(mQueuedStreams.PopFront()))) {
    LOG3(("Http3Session::ProcessPending %p stream %p woken from queue.", this,
          stream));
    MOZ_ASSERT(stream->Queued());
    stream->SetQueued(false);
    mReadyForWrite.Push(stream);
    Unused << mConnection->ResumeSend();
  }
}

static void RemoveStreamFromQueue(Http3Stream* aStream, nsDeque& queue) {
  size_t size = queue.GetSize();
  for (size_t count = 0; count < size; ++count) {
    Http3Stream* stream = static_cast<Http3Stream*>(queue.PopFront());
    if (stream != aStream) queue.Push(stream);
  }
}

void Http3Session::RemoveStreamFromQueues(Http3Stream* aStream) {
  RemoveStreamFromQueue(aStream, mReadyForWrite);
  RemoveStreamFromQueue(aStream, mQueuedStreams);
}

nsresult Http3Session::TryActivating(const nsACString& aMethod,
    const nsACString& aScheme, const nsACString& aAuthorityHeader,
    const nsACString& aPath, const nsACString& aHeaders, uint64_t* aStreamId,
    Http3Stream* aStream) {
  MOZ_ASSERT(*aStreamId == UINT64_MAX);

  LOG(("Http3Session::TryActivating [stream=%p, this=%p state=%d]",
       aStream, this, mState));

  if (IsClosing()) {
    if (NS_FAILED(mError)) {
      return mError;
    } else {
      return NS_ERROR_FAILURE;
    }
  }

  if (aStream->Queued()) {
    LOG3(("Http3Session::TryActivating %p stream=%p already queued.\n", this,
          aStream));
    return NS_BASE_STREAM_WOULD_BLOCK;
  }

  nsresult rv =  mHttp3Connection->fetch(&aMethod, &aScheme, &aAuthorityHeader,
      &aPath, &aHeaders, aStreamId);
  if (NS_FAILED(rv)) {
    LOG(("Http3Session::TryActivating returns error=%" PRIX32 "[stream=%p, "
         "this=%p]", static_cast<uint32_t>(rv), aStream, this));
    if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
      LOG3(
        ("Http3Session::TryActivating %p stream=%p no room for more concurrent "
         "streams\n",
         this, aStream));
      QueueStream(aStream);
    }
    return rv;
  }

  LOG(("Http3Session::TryActivating streamId=%llu for stream=%p [this=%p].",
       *aStreamId, aStream, this));

  MOZ_ASSERT(*aStreamId != UINT64_MAX);
mHttp3Connection->close_stream(*aStreamId);
  mStreamIdHash.Put(*aStreamId, aStream);
  mHttp3Connection->process_http3();
  return NS_OK;
}

void Http3Session::ResetRecvd(uint64_t aStreamId, Http3AppError aError) {
  Http3Stream* stream = mStreamIdHash.Get(aStreamId);
  if (!stream) {
    return;
  }

  stream->SetRecvdReset();

  // We only handle some of Http3 error as epecial, the res are just equivalent
  // to cancel.
  if (aError.tag == Http3AppError::Tag::VersionFallback) {
    // We will restart the request and the alt-svc will be removed
    // automatically.
    CloseStream(stream, NS_ERROR_NET_RESET); 
  } else if (aError.tag == Http3AppError::Tag::RequestRejected) {
    // This request was rejected because server is probably busy or going away.
    // We can restart the request using alt-svc. Without calling
    // DoNotRemoveAltSvc the alt-svc route will be removed.
    stream->Transaction()->DoNotRemoveAltSvc();
    CloseStream(stream, NS_ERROR_NET_RESET);
  } else {
    if (stream->RecvdData()) {
      CloseStream(stream, NS_ERROR_NET_PARTIAL_TRANSFER);
    } else {
      CloseStream(stream, NS_ERROR_NET_INTERRUPT);
    }
  }
}

void Http3Session::SetConnection(nsAHttpConnection* aConn) {
  mConnection = aConn;
}

void Http3Session::GetSecurityCallbacks(nsIInterfaceRequestor** aOut) {
  *aOut = nullptr;
}

// TODO
void Http3Session::OnTransportStatus(nsITransport* aTransport, nsresult aStatus,
                             int64_t aProgress) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
}

bool Http3Session::IsDone() { return mState == CLOSED; }

nsresult Http3Session::Status() {
  MOZ_ASSERT(false, "Http3Session::Status()");
  return NS_ERROR_UNEXPECTED;
}

uint32_t Http3Session::Caps() {
  MOZ_ASSERT(false, "Http3Session::Caps()");
  return 0;
}

void Http3Session::SetDNSWasRefreshed() {
  MOZ_ASSERT(false, "Http3Session::SetDNSWasRefreshed()");
}

nsresult Http3Session::ReadSegments(nsAHttpSegmentReader* reader,
                            uint32_t count, uint32_t* countRead) {
  bool again = false;
  return ReadSegmentsAgain(reader, count, countRead, &again);
}

nsresult Http3Session::ReadSegmentsAgain(nsAHttpSegmentReader* reader,
                            uint32_t count, uint32_t* countRead, bool* again) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  LOG(("Http3Session::ReadSegmentsAgain [this=%p]", this));
  *again = false;

  if (reader) {
    mSegmentReader = reader;
  }

  *countRead = 0;

  Http3Stream* stream = static_cast<Http3Stream*>(mReadyForWrite.PopFront());
  if (!stream) {
    LOG(("Http3Session::ReadSegmentsAgain we do not have a stream ready to write."));
    ProcessOutput();
    return NS_BASE_STREAM_WOULD_BLOCK;
  }

  LOG(("Http3Session::ReadSegmentsAgain call ReadSegments from stream=%p "
       "[this=%p]", stream, this));
  nsresult rv = stream->ReadSegments(this, count, countRead);

  if (stream->RequestBlockedOnRead()) {
    // We are blocked waiting for input - either more http headers or
    // any request body data. When more data from the request stream
    // becomes available the httptransaction will call conn->ResumeSend().

    LOG3(("Http3Session::ReadSegments %p dealing with block on read", this));

    // call readsegments again if there are other streams ready
    // to run in this session
    if (mReadyForWrite.GetSize() > 0) {
      rv = NS_OK;
    } else {
      rv = NS_BASE_STREAM_WOULD_BLOCK;
    }

  } else if (NS_FAILED(rv)) {
    LOG3(("Http3Session::ReadSegmentsAgain %p returns error code %" PRIX32,
          this, static_cast<uint32_t>(rv)));
    if (rv != NS_BASE_STREAM_WOULD_BLOCK) {
      CloseStream(stream, rv);
      if (ASpdySession::SoftStreamError(rv)) {
        LOG3(("Http3Session::ReadSegments %p soft error override\n", this));
        *again = false;
        rv = NS_OK;
      }
    }
  } else if (*countRead > 0) {
    mReadyForWrite.Push(stream);
  }

  // Call neqo-transaction.
  ProcessOutput();

  Unused << mConnection->ResumeRecv();
  // TODO block on max_stream_data

  if (mReadyForWrite.GetSize() > 0) {
    Unused << mConnection->ResumeSend();
  }
  return rv;
}

nsresult Http3Session::WriteSegments(nsAHttpSegmentWriter* writer,
                             uint32_t count, uint32_t* countWritten) {
  bool again = false;
  return WriteSegmentsAgain(writer, count, countWritten, &again);
}

nsresult Http3Session::WriteSegmentsAgain(nsAHttpSegmentWriter* writer,
                                  uint32_t count,
                                  uint32_t* countWritten, bool* again) {
  if (mState == CLOSED) return NS_ERROR_FAILURE;

  if (writer) {
    mSegmentWriter = writer;
  }
  nsresult rv = ProcessInput();
  if (NS_FAILED(rv)) {
    LOG3(("Http3Session %p buffering frame header read failure %" PRIX32 "\n",
          this, static_cast<uint32_t>(rv)));
    // maybe just blocked reading from network
    if (rv == NS_BASE_STREAM_WOULD_BLOCK) rv = NS_OK;
    return rv;
  }
  rv = ProcessEvents(count, countWritten, again);
  Unused << mConnection->ResumeRecv();
  return rv;
}

void Http3Session::Close(nsresult aReason) {
  mError = aReason;
  CloseInternal(true);
}

void Http3Session::CloseInternal(bool aCallNeqoClose) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  if (IsClosing()) return;

  LOG(("Http3Session::Closing [this=%p]", this));

  if (mState != CONNECTED) {
    mBeforeConnectedError = true;
  }
  mState = CLOSING;
  Shutdown();

  if (aCallNeqoClose) {
    mHttp3Connection->close(HTTP3_APP_ERROR_NO_ERROR);
  }

  mStreamIdHash.Clear();
  mStreamTransactionHash.Clear();
}

void Http3Session::ConnectionClosed() {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  if (mState == CLOSED) return;

  LOG3(("Http3Session::Close [this=%p]", this));

  mState = CLOSED;

  Shutdown();

  mStreamIdHash.Clear();
  mStreamTransactionHash.Clear();

  mConnection = nullptr;
  mSegmentReader = nullptr;
  mSegmentWriter = nullptr;

  if (mTimer) {
    mTimer->Cancel();
  }
}

nsHttpConnectionInfo* Http3Session::ConnectionInfo() {
  RefPtr<nsHttpConnectionInfo> ci;
  GetConnectionInfo(getter_AddRefs(ci));
  return ci.get();
}

void Http3Session::SetProxyConnectFailed() {
  MOZ_ASSERT(false, "Http3Session::SetProxyConnectFailed()");
}

nsHttpRequestHead* Http3Session::RequestHead() {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  MOZ_ASSERT(false,
             "Http3Session::RequestHead() "
             "should not be called after http/3 is setup");
  return nullptr;
}

uint32_t Http3Session::Http1xTransactionCount() { return 0; }

nsresult Http3Session::TakeSubTransactions(
    nsTArray<RefPtr<nsAHttpTransaction> >& outTransactions) {
  return NS_OK;
}

PRIntervalTime Http3Session::ResponseTimeout()  {
  return gHttpHandler->ResponseTimeout();
}

//-----------------------------------------------------------------------------
// Pass through methods of nsAHttpConnection
//-----------------------------------------------------------------------------

nsAHttpConnection* Http3Session::Connection() {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  return mConnection;
}

nsresult Http3Session::OnHeadersAvailable(nsAHttpTransaction* transaction,
                                  nsHttpRequestHead* requestHead,
                                  nsHttpResponseHead* responseHead,
                                  bool* reset) {
  return mConnection->OnHeadersAvailable(transaction, requestHead, responseHead,
                                         reset);
}

bool Http3Session::IsReused() { return mConnection->IsReused(); }

nsresult Http3Session::PushBack(const char* buf, uint32_t len) {
  return mConnection->PushBack(buf, len);
}

already_AddRefed<nsHttpConnection> Http3Session::TakeHttpConnection() {
  MOZ_ASSERT(false, "TakeHttpConnection of Http3Session");
  return nullptr;
}

already_AddRefed<nsHttpConnection> Http3Session::HttpConnection() {
  if (mConnection) {
    return mConnection->HttpConnection();
  }
  return nullptr;
}

void Http3Session::CloseTransaction(nsAHttpTransaction* aTransaction,
                            nsresult aResult) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  LOG3(("Http3Session::CloseTransaction %p %p %" PRIX32, this, aTransaction,
        static_cast<uint32_t>(aResult)));

  // Generally this arrives as a cancel event from the connection manager.

  // need to find the stream and call CloseStream() on it.
  Http3Stream* stream = mStreamTransactionHash.Get(aTransaction);
  if (!stream) {
    LOG3(("Http3Session::CloseTransaction %p %p %" PRIX32 " - not found.",
          this, aTransaction, static_cast<uint32_t>(aResult)));
    return;
  }
  LOG3(
      ("Http3Session::CloseTransaction probably a cancel. this=%p, "
       "trans=%p, result=%" PRIX32 ", streamId=0x%" PRIX64 " stream=%p",
       this, aTransaction, static_cast<uint32_t>(aResult),
       stream->StreamId(), stream));
  CloseStream(stream,  aResult);
}

void Http3Session::CloseStream(Http3Stream *aStream,  nsresult aResult) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  if (!aStream->RecvdFin() && !aStream->RecvdReset() &&
      (aStream->HasStreamId())) {
    mHttp3Connection->reset_stream(aStream->StreamId(),
        HTTP3_APP_ERROR_REQUEST_CANCELLED);
  }
  aStream->Close(aResult);
  if (aStream->HasStreamId()) {
    mStreamIdHash.Remove(aStream->StreamId());
  }
  RemoveStreamFromQueues(aStream);
  if ((mShouldClose || mGoawayReceived) &&
      !mStreamTransactionHash.Count()) {
    MOZ_ASSERT(!IsClosing());
    Close(NS_OK);
  }
}

nsresult Http3Session::TakeTransport(nsISocketTransport**,
                             nsIAsyncInputStream**,
                             nsIAsyncOutputStream**) {
  MOZ_ASSERT(false, "TakeTransport of Http3Session");
  return NS_ERROR_UNEXPECTED;
}

bool Http3Session::IsPersistent() { return true; }

void Http3Session::DontReuse() {
  LOG3(("Http3Session::DontReuse %p\n", this));
  if (!OnSocketThread()) {
    LOG3(("Http3Session %p not on socket thread\n", this));
    nsCOMPtr<nsIRunnable> event = NewRunnableMethod(
        "Http3Session::DontReuse", this, &Http3Session::DontReuse);
    gSocketTransportService->Dispatch(event, NS_DISPATCH_NORMAL);
    return;
  }

  if (mGoawayReceived || IsClosing()) {
    return;
  }

  mShouldClose = true;
  if (!mStreamTransactionHash.Count()) {
    Close(NS_OK);
  }
}

void Http3Session::TopLevelOuterContentWindowIdChanged(uint64_t windowId) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  mCurrentForegroundTabOuterContentWindowId = windowId;

  for (auto iter = mStreamTransactionHash.Iter(); !iter.Done(); iter.Next()) {
    iter.Data()->TopLevelOuterContentWindowIdChanged(windowId);
  }
}

nsresult Http3Session::OnReadSegment(const char* buf, uint32_t count,
                             uint32_t* countRead) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  LOG3(("Http3Session::OnReadSegment"));
  return NS_OK;
}

nsresult Http3Session::OnWriteSegment(char* buf, uint32_t count,
                              uint32_t* countWritten) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  LOG3(("Http3Session::OnWriteSegment"));
  return NS_OK;
}

nsresult Http3Session::ReadResponseHeaders(uint64_t aStreamId,
    nsTArray<uint8_t>* aResponseHeaders, bool* aFin) {
  return mHttp3Connection->read_response_headers(aStreamId, aResponseHeaders,
      aFin);
}

nsresult Http3Session::ReadResponseData(uint64_t aStreamId, char* aBuf, uint32_t aCount,
    uint32_t* aCountWritten, bool* aFin) {

  return mHttp3Connection->read_response_data(aStreamId, (uint8_t*)aBuf, aCount,
      aCountWritten, aFin);
}

void Http3Session::TransactionHasDataToWrite(nsAHttpTransaction* caller) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  LOG3(("Http3Session::TransactionHasDataToWrite %p trans=%p", this, caller));

  // a trapped signal from the http transaction to the connection that
  // it is no longer blocked on read.

  Http3Stream* stream = mStreamTransactionHash.Get(caller);
  if (!stream) {
    LOG3(("Http3Session::TransactionHasDataToWrite %p caller %p not found",
          this, caller));
    return;
  }

  LOG3(("Http3Session::TransactionHasDataToWrite %p ID is 0x%" PRIX64,
        this, stream->StreamId()));

  if (mState != CLOSED) {
    mReadyForWrite.Push(stream);
    Unused << mConnection->ResumeSend();
  } else {
    LOG3(
        ("Http3Session::TransactionHasDataToWrite %p closed so not setting "
         "Ready4Write\n",
         this));
  }

  // NSPR poll will not poll the network if there are non system PR_FileDesc's
  // that are ready - so we can get into a deadlock waiting for the system IO
  // to come back here if we don't force the send loop manually.
  Unused << ForceSend();
}

bool Http3Session::TestJoinConnection(const nsACString& hostname,
                                      int32_t port) {
  return RealJoinConnection(hostname, port, true);
}

bool Http3Session::JoinConnection(const nsACString& hostname, int32_t port) {
  return RealJoinConnection(hostname, port, false);
}

// TODO test
bool Http3Session::RealJoinConnection(const nsACString& hostname, int32_t port,
                                      bool justKidding) {
  if (!mConnection || (mState != CONNECTED) || mShouldClose ||
      mGoawayReceived) {
    return false;
  }

  nsHttpConnectionInfo* ci = ConnectionInfo();
  if (nsCString(hostname).EqualsIgnoreCase(ci->Origin()) &&
      (port == ci->OriginPort())) {
    return true;
  }

  nsAutoCString key(hostname);
  key.Append(':');
  key.Append(justKidding ? 'k' : '.');
  key.AppendInt(port);
  bool cachedResult;
  if (mJoinConnectionCache.Get(key, &cachedResult)) {
    LOG(("joinconnection [%p %s] %s result=%d cache\n", this,
         ConnectionInfo()->HashKey().get(), key.get(), cachedResult));
    return cachedResult;
  }

  nsresult rv;
  bool isJoined = false;

  nsCOMPtr<nsISupports> securityInfo;
  nsCOMPtr<nsISSLSocketControl> sslSocketControl;

  mConnection->GetSecurityInfo(getter_AddRefs(securityInfo));
  sslSocketControl = do_QueryInterface(securityInfo, &rv);
  if (NS_FAILED(rv) || !sslSocketControl) {
    return false;
  }

  bool joinedReturn = false;
  if (justKidding) {
    rv = sslSocketControl->TestJoinConnection(kHttp3Version,
                                              hostname, port, &isJoined);
  } else {
    rv = sslSocketControl->JoinConnection(kHttp3Version, hostname,
                                          port, &isJoined);
  }
  if (NS_SUCCEEDED(rv) && isJoined) {
    joinedReturn = true;
  }

  LOG(("joinconnection [%p %s] %s result=%d lookup\n", this,
       ConnectionInfo()->HashKey().get(), key.get(), joinedReturn));
  mJoinConnectionCache.Put(key, joinedReturn);
  if (!justKidding) {
    // cache a kidding entry too as this one is good for both
    nsAutoCString key2(hostname);
    key2.Append(':');
    key2.Append('k');
    key2.AppendInt(port);
    if (!mJoinConnectionCache.Get(key2)) {
      mJoinConnectionCache.Put(key2, joinedReturn);
    }
  }
  return joinedReturn;
}

void Http3Session::CallCertVerification() {
  LOG(("Http3Session::CallCertVerification [this=%p]", this));

  NeqoCertificateInfo certInfo;

  if (NS_FAILED(mHttp3Connection->peer_certificate_info(&certInfo))) {
    LOG(("Http3Session::CallCertVerification [this=%p] - no cert",
         this));
    mHttp3Connection->peer_authenticated(SSL_ERROR_BAD_CERTIFICATE);
    mError = psm::GetXPCOMFromNSSError(SSL_ERROR_BAD_CERTIFICATE);
    return;
  }

  UniqueCERTCertificate cert;
  UniqueCERTCertList certChain(CERT_NewCertList());
  for (auto& cert_der : certInfo.certs) {
    SECItem der = {
        SECItemType::siBuffer,
        cert_der.Elements(),
        (uint32_t)cert_der.Length()
    };

    if (!cert) {
      cert.reset(CERT_NewTempCertificate(
          CERT_GetDefaultCertDB(), &der, nullptr, false, true));
      if (!cert) {
        LOG(("Http3Session::CallCertVerification [this=%p] cert failed",
             this));
        mHttp3Connection->peer_authenticated(SSL_ERROR_BAD_CERTIFICATE);
        mError = psm::GetXPCOMFromNSSError(SSL_ERROR_BAD_CERTIFICATE);
        return;
      }
    }

    if (CERT_AddCertToListTail(certChain.get(), CERT_NewTempCertificate(
                               CERT_GetDefaultCertDB(), &der, nullptr,
                               false, true)) != SECSuccess) {
      LOG(("Http3Session::CallCertVerification [this=%p] cert chain failed",
           this));
      mHttp3Connection->peer_authenticated(SSL_ERROR_BAD_CERTIFICATE);
      mError = psm::GetXPCOMFromNSSError(SSL_ERROR_BAD_CERTIFICATE);
      return;
    }
  }

  SECItemArray ocsp;
  ocsp.items = nullptr;
  ocsp.len = 0;
  if (certInfo.stapled_ocsp_responses_present &&
      certInfo.stapled_ocsp_responses.Length()) {
    SECITEM_AllocArray(NULL, &ocsp,
        certInfo.stapled_ocsp_responses.Length());
    if (!ocsp.items) {
      LOG(("Http3Session::CallCertVerification [this=%p] ocsp failed",
           this));
      mHttp3Connection->peer_authenticated(SSL_ERROR_BAD_CERTIFICATE);
      mError = psm::GetXPCOMFromNSSError(SSL_ERROR_BAD_CERTIFICATE);
      return;
    }

    for (uint32_t i = 0; i < certInfo.stapled_ocsp_responses.Length(); i++) {
      ocsp.items[i].data = (unsigned char *)PORT_Alloc(certInfo.stapled_ocsp_responses[i].Length());
      if (!ocsp.items[i].data) {
        LOG(("Http3Session::CallCertVerification [this=%p] ocsp failed",
             this));
        mHttp3Connection->peer_authenticated(SSL_ERROR_BAD_CERTIFICATE);
        mError = psm::GetXPCOMFromNSSError(SSL_ERROR_BAD_CERTIFICATE);
        SECITEM_FreeArray(&ocsp, PR_FALSE);
        return;
      }
      PORT_Memcpy(ocsp.items[i].data, certInfo.stapled_ocsp_responses[i].Elements(),
          certInfo.stapled_ocsp_responses[i].Length());
      ocsp.items[i].len = certInfo.stapled_ocsp_responses[i].Length();
      ocsp.items[i].type = SECItemType::siBuffer;
    }
  }

  SECItem scts = {
      SECItemType::siBuffer,
      certInfo.signed_cert_timestamp_present ?
          certInfo.signed_cert_timestamp.Elements() :
          nullptr,
      certInfo.signed_cert_timestamp_present ?
          (uint32_t)certInfo.signed_cert_timestamp.Length() :
          0
  };

  nsCOMPtr<nsISupports> securityInfo;
  mSocketTransport->GetSecurityInfo(getter_AddRefs(securityInfo));
  nsCOMPtr<nsISSLSocketControl> ssl = do_QueryInterface(securityInfo);
  MOZ_ASSERT(ssl);

  if (!ssl ||
      NS_FAILED(ssl->AuthCertificate(cert, certChain,
      certInfo.stapled_ocsp_responses_present ? &ocsp : nullptr,
      certInfo.signed_cert_timestamp_present ? &scts : nullptr, this))) {
    LOG(("Http3Session::CallCertVerification [this=%p] AuthCertificate failed",
         this));
    mHttp3Connection->peer_authenticated(SSL_ERROR_BAD_CERTIFICATE);
    mError = psm::GetXPCOMFromNSSError(SSL_ERROR_BAD_CERTIFICATE);
  }

  if (ocsp.items) {
    SECITEM_FreeArray(&ocsp, PR_FALSE);
  }
}

NS_IMETHODIMP
Http3Session::Authenticated(int32_t aError) {
  LOG(("Http3Session::Authenticated error=%x [this=%p].",
       aError, this));
  if (mState == INITIALIZING) {
    if (psm::IsNSSErrorCode(aError)) {
      mError = psm::GetXPCOMFromNSSError(aError);
      LOG(("Http3Session::Authenticated psm-error=%x [this=%p].",
           mError, this));
    }
    mHttp3Connection->peer_authenticated(aError);
  }

  if (mConnection) {
    Unused << mConnection->ResumeSend();
  }

  return NS_OK;
}

}
}
