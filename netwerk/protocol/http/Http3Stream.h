/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_Http3Stream_h
#define mozilla_net_Http3Stream_h

#include "nsAHttpTransaction.h"

namespace mozilla {
namespace net {

class Http3Session;

class Http3Stream final : public nsAHttpSegmentReader,
                          public nsAHttpSegmentWriter {
 public:
  NS_DECL_NSAHTTPSEGMENTREADER
  NS_DECL_NSAHTTPSEGMENTWRITER

  Http3Stream(nsAHttpTransaction* httpTransaction, Http3Session* session);

  bool HasStreamId() { return mStreamId != UINT64_MAX; }
  uint64_t StreamId() { return mStreamId; }

  nsresult TryActivating();

  // TODO priorities
  void TopLevelOuterContentWindowIdChanged(uint64_t windowId) {};

  MOZ_MUST_USE nsresult ReadSegments(nsAHttpSegmentReader*, uint32_t,
                                     uint32_t*);
  MOZ_MUST_USE nsresult WriteSegments(nsAHttpSegmentWriter*, uint32_t,
                                      uint32_t*);

  bool RequestBlockedOnRead() { return mRequestBlockedOnRead; }

  void SetQueued(bool aStatus) { mQueued = aStatus; }
  bool Queued() { return mQueued; }

  ~Http3Stream() = default;

  bool Done() { return mState == DONE; }

  void Close(nsresult aResult);
  bool RecvdData() { return mDataReceived; }

  nsAHttpTransaction* Transaction() { return mTransaction; }
  bool RecvdFin() { return mState == RECEIVED_FIN; }
  bool RecvdReset() { return mState == RECEIVED_RESET; }
  void SetRecvdReset() {  mState = RECEIVED_RESET; }
 private:

  void GetHeadersString(const char* buf, uint32_t avail, uint32_t* countUsed);
  nsresult StartRequest();
  void FindRequestContentLength();

  enum StreamState {
    PREPARING_HEADERS,
    SENDING_BODY,
    EARLY_RESPONSE,
    READING_HEADERS,
    READING_DATA,
    RECEIVED_FIN,
    RECEIVED_RESET,
    DONE
  } mState;

  uint64_t mStreamId;
  Http3Session* mSession;
  RefPtr<nsAHttpTransaction> mTransaction;
  nsCString mFlatHttpRequestHeaders;
  bool mRequestHeadersDone;
  bool mRequestStarted;
  bool mQueued;
  bool mRequestBlockedOnRead;
  bool mDataReceived;
  nsTArray<uint8_t> mFlatResponseHeaders;
  uint32_t mRequestBodyLenRemaining;

  // The underlying socket transport object is needed to propogate some events
  nsISocketTransport* mSocketTransport;

  // For Progress Events
  uint64_t mTotalSent;
  uint64_t mTotalRead;

  bool mFin;
};

}
}

#endif // mozilla_net_Http3Stream_h
