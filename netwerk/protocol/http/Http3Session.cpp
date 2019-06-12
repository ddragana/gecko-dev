/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=4 sw=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "HttpLog.h"
#include "Http3Stream.h"
#include "nsHttpHandler.h"
#include "mozilla/RefPtr.h"
#include "ASpdySession.h" // because of SoftStreamError()

namespace mozilla {
namespace net {

NS_IMPL_ADDREF(Http3Session)
NS_IMPL_RELEASE(Http3Session)
NS_INTERFACE_MAP_BEGIN(Http3Session)
  NS_INTERFACE_MAP_ENTRY_AMBIGUOUS(nsISupports, nsAHttpConnection)
NS_INTERFACE_MAP_END

Http3Session::Http3Session()
  : mConnected(false),
    mClosing(false),
    mClosed(false),
    mCleanShutdown(false),
    mGoawayReceived(false),
    mShouldClose(false),
    mPacketToSendLen(0),
    mSegmentReader(nullptr),
    mSegmentWriter(nullptr) {
  Unused << NeqoHttp3Conn::Init(getter_AddRefs(mHttp3Connection));

  mCurrentForegroundTabOuterContentWindowId =
      gHttpHandler->ConnMgr()->CurrentTopLevelOuterContentWindowId();
}

void Http3Session::Shutdown() {
  for (auto iter = mStreamTransactionHash.Iter(); !iter.Done(); iter.Next()) {
    nsAutoPtr<Http3Stream>& stream = iter.Data();

    if (stream->StreamID() == UINT64_MAX) {
      CloseStream(stream, NS_ERROR_NET_RESET);
    } else if (stream->RecvdData()) {
      CloseStream(stream, NS_ERROR_NET_PARTIAL_TRANSFER);
    } else {
      CloseStream(stream, NS_ERROR_ABORT);
    }
  }
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

nsresult Http3Session::ProcessInput(nsIAsyncInputStream *aIn) {
  MOZ_ASSERT(aIn || mSegmentWriter);

  LOG(("Http3Session::ProcessInput writer=%p, aIn=%p [this=%p]",
       mSegmentWriter, aIn, this));

  uint8_t packet[2000];
  uint32_t read = 0;
  nsresult rv;
  if (aIn) {
    rv = aIn->Read((char*)packet, 2000, &read);
  } else {
    rv = mSegmentWriter->OnWriteSegment((char*)packet, 2000, &read);
  }
  mHttp3Connection->process_input(packet, read, 0);
  mHttp3Connection->process_http3();
  LOG(("Http3Session::Process status: connected=%d", mConnected));
  if (!mConnected) {
    bool notUsed;
    ProcessEvents(0, nullptr, &notUsed);
  }

  return NS_OK;
}

nsresult Http3Session::ProcessEvents(uint32_t count, uint32_t* countWritten,
    bool* again) {
  Http3Event event = mHttp3Connection->get_event();

  if (event.tag == Http3Event::Tag::NoEvent) {
    *again = false;
    Unused << ResumeRecv();
    return NS_OK;
  }

  switch (event.tag) {
    case Http3Event::Tag::HeaderReady:
    case Http3Event::Tag::DataReadable:
      {
        MOZ_ASSERT(mConnected);
        uint64_t id;
        if (event.tag == Http3Event::Tag::HeaderReady) {
          LOG(("Http3Session::ProcessEvent - HeaderReady"));
          id = event.header_ready.stream_id;
        } else {
          LOG(("Http3Session::ProcessEvent - DataReadable"));
          id = event.data_readable.stream_id;
        }

        Http3Stream* stream = mStreamIDHash.Get(id);
        if (!stream) {
          *again = false;
          Unused << ResumeRecv();
          return NS_OK;
        }

        nsresult rv = stream->WriteSegments(this, count, countWritten);
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

        if (stream->Done()) {
          LOG3(("Http3Session::ProcessEvent session=%p stream=%p 0x%" PRIx64 "\n"
                "cleanup stream.\n",
                this, stream, stream->StreamID()));
          CloseStream(stream, NS_OK);
        }

        if (NS_FAILED(rv)) {
          LOG3(("Http3Session::ProcessEvent failed rv=%" PRIx32 " [this=%p].",
                static_cast<uint32_t>(rv), this));
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
    case Http3Event::Tag::ConnectionConnected:
       LOG(("Http3Session::Process event - ConnectionConnected"));
       mConnected = true;
       break;
    case Http3Event::Tag::GoawayReceived:
       LOG(("Http3Session::Process event - GoawayReceived"));
       MOZ_ASSERT(!mGoawayReceived);
       mGoawayReceived = true;
       break;
    case Http3Event::Tag::ConnectionClosing:
       LOG(("Http3Session::Process event - ConnectionClosing"));
       mClosing = true;
       break;
    case Http3Event::Tag::ConnectionClosed:
       LOG(("Http3Session::Process event - ConnectionClosed"));
       CloseInternal(NS_OK, false);
       break;
    default:
       break;
  }

  return NS_OK;
}

nsresult Http3Session::Process(nsIAsyncOutputStream *aOut, nsIAsyncInputStream *aIn) {
  nsresult rv = ProcessInput(aIn);
  if (NS_FAILED(rv)) {
    return rv;
  }

  return ProcessOutput(aOut);
}

nsresult Http3Session::ProcessOutput(nsIAsyncOutputStream *aOut) {
  MOZ_ASSERT(aOut || mSegmentReader);

  LOG(("Http3Session::ProcessOutput reader=%p, aOut=%p [this=%p]", mSegmentReader, aOut, this));

  nsresult rv = NS_OK;
  if (mPacketToSendLen) {
    uint32_t written = 0;
    if (aOut) {
      rv = aOut->Write((const char*)mPacketToSend.get(), mPacketToSendLen, &written);
    } else {
      rv = mSegmentReader->OnReadSegment((const char*)mPacketToSend.get(), mPacketToSendLen, &written);
    }
    if (NS_FAILED(rv)) {
      if ((rv == NS_BASE_STREAM_WOULD_BLOCK) && mConnection) {
        Unused << mConnection->ResumeSend();
      }
      return rv;
    }
    MOZ_ASSERT(written == mPacketToSendLen);
    mPacketToSendLen = 0;
    mPacketToSend = nullptr;
  }
  mHttp3Connection->process_http3();
  mHttp3Connection->process_output(0);
  Buffer buf = neqo_http3conn_get_data_to_send(mHttp3Connection);
  while (buf.len > 0) {
    uint32_t written = 0;
    if (aOut) {
      rv = aOut->Write((const char*)buf.data, buf.len, &written);
    } else {
      rv = mSegmentReader->OnReadSegment((const char*)buf.data, buf.len, &written);
    }
    if (NS_FAILED(rv)) {
      if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
        mPacketToSend = MakeUnique<char[]>(buf.len);
        memcpy(mPacketToSend.get(), buf.data, buf.len);
        mPacketToSendLen = buf.len;
        if (mConnection) {
           Unused << mConnection->ResumeSend();
        }
      }
      break;
    }
    neqo_http3conn_forget_buffer(buf);
    buf = neqo_http3conn_get_data_to_send(mHttp3Connection);
  }
  neqo_http3conn_forget_buffer(buf);
  return rv;
}

bool Http3Session::AddStream(nsAHttpTransaction* aHttpTransaction,
                     int32_t aPriority,
                     nsIInterfaceRequestor* aCallbacks) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  nsHttpTransaction* trans = aHttpTransaction->QueryHttpTransaction();

  if (mClosed || mClosing) {
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
  return !(mClosing || mClosed || mGoawayReceived || mShouldClose) && mConnected;
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

nsresult Http3Session::TryActivating(const nsACString& aMethod, const nsACString& aScheme,
    const nsACString& aAuthorityHeader, const nsACString& aPath,
    const nsACString& aHeaders, uint64_t& aStreamId, Http3Stream* aStream) {
  MOZ_ASSERT(aStreamId == UINT64_MAX);

  if (aStream->Queued()) {
    LOG3(("Http3Session::TryActivating %p stream=%p already queued.\n", this,
          aStream));
    return NS_BASE_STREAM_WOULD_BLOCK;
  }

  nsresult rv =  mHttp3Connection->fetch(&aMethod, &aScheme, &aAuthorityHeader, &aPath,
      &aHeaders, &aStreamId);
  if (NS_FAILED(rv)) {
    if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
      LOG3(
        ("Http3Session::TryActivating %p stream=%p no room for more concurrent "
         "streams\n",
         this, aStream));
      QueueStream(aStream);
    }
    return rv;
  }

  mStreamIDHash.Put(aStreamId, aStream);
  mHttp3Connection->process_http3();
  return NS_OK;
}

void Http3Session::ResetRecvd(uint64_t aStreamId, Http3AppError aError) {
  Http3Stream* stream = mStreamIDHash.Get(aStreamId);
  if (!stream) {
    return;
  }

  stream->SetRecvdReset();

  // We only handle some of Http3 error as epecial, the res are just equivalent to
  // cancel.
  if (aError.tag == Http3AppError::Tag::VersionFallback) {
    // TODO disable http3
    CloseStream(stream, NS_ERROR_NET_RESET); 
  } else if (aError.tag == Http3AppError::Tag::RequestRejected) {
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

bool Http3Session::IsDone() { return false; }//TODO return !mStreamTransactionHash.Count(); }

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
    ProcessOutput(nullptr);
    return NS_BASE_STREAM_WOULD_BLOCK;
  }

  LOG(("Http3Session::ReadSegmentsAgain call ReadSegments fro stream=%p [this=%p]",
       stream, this));
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
    LOG3(("Http3Session::ReadSegmentsAgain %p may return FAIL code %" PRIX32, this,
          static_cast<uint32_t>(rv)));
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
  ProcessOutput(nullptr);

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
  *again = false;
  if (writer) {
    mSegmentWriter = writer;
  }
  nsresult rv = ProcessInput(nullptr);
  if (NS_FAILED(rv)) {
    LOG3(("Http3Session %p buffering frame header read failure %" PRIx32 "\n",
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
  CloseInternal(aReason, true);
}

void Http3Session::CloseInternal(nsresult aReason, bool aCloseTransport) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  if (mClosing || mClosed) return;

  LOG3(("Http3Session::Close %p %" PRIX32, this,
        static_cast<uint32_t>(aReason)));

  mClosed = true;

  if (aCloseTransport) {
//    Http3AppError error;
//    error.tag = Http3AppError::Tag::NoError;
    mHttp3Connection->close({ Http3AppError::Tag::NoError });
  }

  Shutdown();

  mStreamIDHash.Clear();
  mStreamTransactionHash.Clear();

  mConnection = nullptr;
  mSegmentReader = nullptr;
  mSegmentWriter = nullptr;
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
  LOG3(("Http3Session::CloseTransaction %p %p %" PRIx32, this, aTransaction,
        static_cast<uint32_t>(aResult)));

  // Generally this arrives as a cancel event from the connection manager.

  // need to find the stream and call CloseStream() on it.
  Http3Stream* stream = mStreamTransactionHash.Get(aTransaction);
  if (!stream) {
    LOG3(("Http3Session::CloseTransaction %p %p %" PRIx32 " - not found.", this,
          aTransaction, static_cast<uint32_t>(aResult)));
    return;
  }
  LOG3(
      ("Http3Session::CloseTransaction probably a cancel. "
       "this=%p, trans=%p, result=%" PRIx32 ", streamID=0x%" PRIx64 " stream=%p",
       this, aTransaction, static_cast<uint32_t>(aResult), stream->StreamID(),
       stream));
  CloseStream(stream,  aResult);
}

void Http3Session::CloseStream(Http3Stream *aStream,  nsresult aResult) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  if (!aStream->RecvdFin() && !aStream->RecvdReset() &&
      (aStream->StreamID() != UINT64_MAX)) {
    mHttp3Connection->reset_stream(aStream->StreamID(),
        { Http3AppError::Tag::RequestCancelled });
  }
  aStream->Close(aResult);
  if (aStream->StreamID() != UINT64_MAX) {
    mStreamIDHash.Remove(aStream->StreamID());
  }
  RemoveStreamFromQueues(aStream);
  mStreamTransactionHash.Remove(aStream->Transaction());

  if ((mShouldClose || mGoawayReceived) &&
      !mStreamTransactionHash.Count()) {
    MOZ_ASSERT(!mClosing && !mClosed);
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

  if (mGoawayReceived || mClosing || mClosed) {
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

nsresult Http3Session::GetResponseHeaders(uint64_t aStreamId,
    UniquePtr<char[]>& aResponseHeaders, uint32_t& aResponseHeadersLen) {
  nsCString headers;
  nsresult rv = mHttp3Connection->get_headers(aStreamId, &headers);
  if (NS_FAILED(rv)) {
    return rv;
  }

  aResponseHeadersLen = headers.Length();
  aResponseHeaders =  MakeUnique<char[]>(aResponseHeadersLen);
  memcpy(aResponseHeaders.get(), PromiseFlatCString(headers).get(), aResponseHeadersLen);
  return NS_OK;
}

nsresult Http3Session::ReadData(uint64_t aStreamId, char* aBuf, uint32_t aCount,
    uint32_t* aCountWritten, bool* aFin) {

  return mHttp3Connection->read_data(aStreamId, (uint8_t*)aBuf, aCount, aCountWritten, aFin);
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

  LOG3(("Http3Session::TransactionHasDataToWrite %p ID is 0x%" PRIx64 "\n", this,
        stream->StreamID()));

  if (!mClosed) {
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

bool Http3Session::RealJoinConnection(const nsACString& hostname, int32_t port,
                                      bool justKidding) {
  if (!mConnection || !mConnected || mClosing || mClosed || mShouldClose ||
      mGoawayReceived) {
    return false;
  }

  nsHttpConnectionInfo* ci = ConnectionInfo();
  if (nsCString(hostname).EqualsIgnoreCase(ci->Origin()) &&
      (port == ci->OriginPort())) {
    return true;
  }
  return true;
  //TODO
/*
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

  // try all the coalescable versions we support.
  const SpdyInformation* info = gHttpHandler->SpdyInfo();
  static_assert(SpdyInformation::kCount == 1, "assume 1 alpn version");
  bool joinedReturn = false;
  if (info->ProtocolEnabled(0)) {
    if (justKidding) {
      rv = sslSocketControl->TestJoinConnection(info->VersionString[0],
                                                hostname, port, &isJoined);
    } else {
      rv = sslSocketControl->JoinConnection(info->VersionString[0], hostname,
                                            port, &isJoined);
    }
    if (NS_SUCCEEDED(rv) && isJoined) {
      joinedReturn = true;
    }
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
  return joinedReturn;*/
}

}
}
