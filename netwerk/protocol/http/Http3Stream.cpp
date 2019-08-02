/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=8 et tw=80 : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// HttpLog.h should generally be included first
#include "HttpLog.h"
#include "Http3Session.h"
#include "Http3Stream.h"
#include "nsHttpRequestHead.h"
#include "nsISocketTransport.h"
#include "nsSocketTransportService2.h"

#include <stdio.h>

namespace mozilla {
namespace net {

Http3Stream::Http3Stream(nsAHttpTransaction* httpTransaction,
                         Http3Session* session)
  : mState(PREPARING_HEADERS),
    mStreamId(UINT64_MAX),
    mSession(session),
    mTransaction(httpTransaction),
    mRequestHeadersDone(false),
    mRequestStarted(false),
    mQueued(false),
    mRequestBlockedOnRead(false),
    mDataReceived(false),
    mFlatResponseHeaders(nullptr),
    mFlatResponseHeadersLen(0),
    mFlatResponseHeadersOffset(0),
    mSocketTransport(session->SocketTransport()),
    mTotalSent(0),
    mTotalRead(0)
{}

void Http3Stream::Close(nsresult aResult) {
  mTransaction->Close(aResult);
}

void Http3Stream::GetHeadersString(const char* buf, uint32_t avail,
                                   uint32_t* countUsed) {
  LOG3(("Http3Stream::GetHeadersString %p "
         "avail=%d.", this, avail));

  mFlatHttpRequestHeaders.Append(buf, avail);
  // We can use the simple double crlf because firefox is the
  // only client we are parsing
  int32_t endHeader = mFlatHttpRequestHeaders.Find("\r\n\r\n");

  if (endHeader == kNotFound) {
    // We don't have all the headers yet
    LOG3(
        ("Http3Stream::GetHeadersString %p "
         "Need more header bytes. Len = %d",
         this, mFlatHttpRequestHeaders.Length()));
    *countUsed = avail;
    return;
  }

  uint32_t oldLen = mFlatHttpRequestHeaders.Length();
  mFlatHttpRequestHeaders.SetLength(endHeader + 2);
  *countUsed = avail - (oldLen - endHeader) + 4;
  mRequestHeadersDone = true;
}

nsresult Http3Stream::TryActivating() {
  LOG(("Http3Stream::TryActivating [this=%p]", this));
  nsHttpRequestHead* head = mTransaction->RequestHead();

  nsAutoCString authorityHeader;
  nsresult rv = head->GetHeader(nsHttp::Host, authorityHeader);
  if (NS_FAILED(rv)) {
    MOZ_ASSERT(false);
    return rv;
  }

  nsDependentCString scheme(head->IsHTTPS() ? "https" : "http");

  nsAutoCString method;
  nsAutoCString path;
  head->Method(method);
  head->Path(path);

  mRequestStarted = true;
  rv =  mSession->TryActivating(method, scheme, authorityHeader,
      path, mFlatHttpRequestHeaders, &mStreamId, this);
  if (NS_SUCCEEDED(rv)) {
    mRequestStarted = true;
  }

  return rv;
}

nsresult Http3Stream::OnReadSegment(const char* buf, uint32_t count,
                                    uint32_t* countRead) {

  LOG(("Http3Stream::OnReadSegment count=%x state=%d [this=%p]",
       count, mState, this));

  switch (mState) {
    case PREPARING_HEADERS:
      GetHeadersString(buf, count, countRead);

      if (*countRead) {
        mTotalSent = *countRead;
        mTransaction->OnTransportStatus(mSocketTransport, NS_NET_STATUS_SENDING_TO,
            mTotalSent);
      }
      if (mRequestHeadersDone && !mRequestStarted) {
        nsresult rv = TryActivating();
        if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
          LOG3(("Http3Stream::OnReadSegment %p cannot activate now. queued.\n",
                this));
          return *countRead ? NS_OK : NS_BASE_STREAM_WOULD_BLOCK;
        }
        if (NS_FAILED(rv)) {
          LOG3(("Http3Stream::OnReadSegment %p cannot activate error=%" PRIX32
                ".", this, static_cast<uint32_t>(rv)));
          return rv;
        }
      }

      if (mRequestStarted) {
        mTransaction->OnTransportStatus(mSocketTransport, NS_NET_STATUS_WAITING_FOR,
            0);

        mState = READING_HEADERS;
      }
      break;
//    case SENDING_BODY:
    default:
      // TODO early response
      *countRead = count;
      break;
  }
  return NS_OK;
}

nsresult Http3Stream::OnWriteSegment(char* buf, uint32_t count,
                                     uint32_t* countWritten) {
  LOG(("Http3Stream::OnWriteSegment [this=%p, state=%d", this, mState));
  nsresult rv = NS_OK;
  switch (mState) {
    case PREPARING_HEADERS:
//    case SENDING_BODY:
      // TODO early response
      MOZ_ASSERT(false);
      break;
    case READING_HEADERS:
      {
        if (!mFlatResponseHeadersLen) {
          mSession->GetResponseHeaders(mStreamId, mFlatResponseHeaders,
              mFlatResponseHeadersLen);
          LOG(("Http3Stream::OnWriteSegment [this=%p, read %d bytes of headers",
               this, mFlatResponseHeadersLen));
        }
        *countWritten = (mFlatResponseHeadersLen > count) ?
            count : mFlatResponseHeadersLen;
        memcpy(buf, mFlatResponseHeaders.get() + mFlatResponseHeadersOffset, *countWritten);
        mFlatResponseHeadersOffset += *countWritten;

        if (mFlatResponseHeadersLen == mFlatResponseHeadersOffset) {
          mFlatResponseHeadersLen = 0;
          mFlatResponseHeadersOffset = 0;
          mFlatResponseHeaders = nullptr;
          mState = READING_DATA;
        }
        if (*countWritten == 0 ) {
          rv = NS_BASE_STREAM_WOULD_BLOCK;
        } else {
          mTotalRead += *countWritten;
          mTransaction->OnTransportStatus(mSocketTransport,
              NS_NET_STATUS_RECEIVING_FROM, mTotalRead);
        }
      }
      break;
    case READING_DATA:
      {
        bool fin;
        rv = mSession->ReadData(mStreamId, buf, count, countWritten, &fin);
        if (fin) {
          mState = RECEIVED_FIN;
        }
        if (*countWritten == 0) {
          if (fin) {
            mState = DONE;
            rv = NS_BASE_STREAM_CLOSED;
          } else {
            rv = NS_BASE_STREAM_WOULD_BLOCK;
          }
        } else {
          mTotalRead += *countWritten;
          mTransaction->OnTransportStatus(mSocketTransport,
              NS_NET_STATUS_RECEIVING_FROM, mTotalRead);
        }
      }
      break;
    case RECEIVED_FIN:
    case RECEIVED_RESET:
      rv = NS_BASE_STREAM_CLOSED;
      break;
    case DONE:
      rv= NS_ERROR_UNEXPECTED;
   }

  return rv;
}

nsresult Http3Stream::ReadSegments(nsAHttpSegmentReader* reader, uint32_t count,
                                   uint32_t* countRead) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  mRequestBlockedOnRead = false;

  nsresult rv = NS_OK;
  switch (mState) {
    case PREPARING_HEADERS:
//    case SENDING_BODY:
      {
        rv = mTransaction->ReadSegments(this, count, countRead);
        LOG(("Http3Stream::ReadSegments rv=%x [this=%p]", rv, this));
        if (NS_SUCCEEDED(rv) && !mRequestHeadersDone) {
          mSession->TransactionHasDataToWrite(mTransaction);
        }
        if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
          mRequestBlockedOnRead = true;
        }

        // A transaction that had already generated its headers before it was
        // queued at the session level (due to concurrency concerns) may not call
        // onReadSegment off the ReadSegments() stack above.
        if (NS_SUCCEEDED(rv)) {
          LOG3(
              ("Http3Stream %p ReadSegments forcing OnReadSegment call\n", this));
          uint32_t wasted = 0;
          Unused << OnReadSegment("", 0, &wasted);
        }
      }   
      break;
    default:
      *countRead = 0;
      rv = NS_OK;
      break;
  }
  LOG(("Http3Stream::ReadSegments rv=%x [this=%p]", rv, this));
  return rv;
}

nsresult Http3Stream::WriteSegments(nsAHttpSegmentWriter* writer, uint32_t count,
                                    uint32_t* countWritten) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  LOG(("Http3Stream::WriteSegments [this=%p]", this));
  nsresult rv = mTransaction->WriteSegments(this, count, countWritten);
  LOG(("Http3Stream::WriteSegments rv=%x [this=%p]", rv, this));
  return rv;
}

}
}
