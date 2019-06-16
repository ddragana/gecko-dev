/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=4 sw=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
  * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef Http3Session_H__
#define Http3Session_H__

#include "nsISupportsImpl.h"
#include "mozilla/net/NeqoHttp3Conn.h"
#include "nsRefPtrHashtable.h"
#include "nsAHttpConnection.h"
#include "HttpTrafficAnalyzer.h"
#include "mozilla/UniquePtr.h"
#include "nsDeque.h"

namespace mozilla {
namespace net {

class Http3Stream;

class Http3Session final : public nsAHttpTransaction,
                           public nsAHttpConnection,
                           public nsAHttpSegmentReader,
                           public nsAHttpSegmentWriter
{
 public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSAHTTPTRANSACTION
  NS_DECL_NSAHTTPCONNECTION(mConnection)
  NS_DECL_NSAHTTPSEGMENTREADER
  NS_DECL_NSAHTTPSEGMENTWRITER

  Http3Session();

  nsresult Process(nsIAsyncOutputStream *aOut, nsIAsyncInputStream *aIn);

  void CloseInternal(nsresult aReason, bool aCloseTransport);
  void Shutdown();

  bool AddStream(nsAHttpTransaction* aHttpTransaction,
                 int32_t aPriority,
                 nsIInterfaceRequestor* aCallbacks);

  bool CanReuse();

  bool RoomForMoreStreams() { return mQueuedStreams.GetSize() == 0; }

  // We will let neqo-transport handle connection timeouts.
  uint32_t ReadTimeoutTick(PRIntervalTime now) { return UINT32_MAX; }

  bool IsConnected() {return mConnected;}

  // overload of nsAHttpTransaction
  MOZ_MUST_USE nsresult ReadSegmentsAgain(nsAHttpSegmentReader*, uint32_t,
                                          uint32_t*, bool*) final;
  MOZ_MUST_USE nsresult WriteSegmentsAgain(nsAHttpSegmentWriter*, uint32_t,
                                           uint32_t*, bool*) final;

  bool ResponseTimeoutEnabled() const final { return true; }
  PRIntervalTime ResponseTimeout() final;

  nsresult TryActivating(const nsACString& aMethod, const nsACString& aScheme,
    const nsACString& aHost, const nsACString& aPath,
    const nsACString& aHeaders, uint64_t& aStreamId, Http3Stream* aStream);

  const static uint32_t kDefaultReadAmount = 2048;

  nsresult GetResponseHeaders(uint64_t aStreamId,
      UniquePtr<char[]>& aResponseHeaders, uint32_t& aResponseHeadersLen);
  nsresult ReadData(uint64_t aStreamId, char* aBuf, uint32_t aCount,
      uint32_t* aCountWritten, bool* aFin);
  void CloseStream(Http3Stream *aStream,  nsresult aResult);

  void SetCleanShutdown(bool aCleanShutdown) {
    mCleanShutdown = aCleanShutdown;
  }

  void ResetRecvd(uint64_t aStreamId, Http3AppError aError);

  PRIntervalTime IdleTime();

  bool TestJoinConnection(const nsACString& hostname, int32_t port);
  bool JoinConnection(const nsACString& hostname, int32_t port);

  void TransactionHasDataToWrite(nsAHttpTransaction* caller) override;

  void SetSocketTransport(nsISocketTransport* aSocketTransport) {
    mSocketTransport = aSocketTransport;
  }
  nsISocketTransport* SocketTransport() { return mSocketTransport; }
 private:
  ~Http3Session();

  bool RealJoinConnection(const nsACString& hostname, int32_t port,
      bool justKidding);
  void Shutdown(uint64_t aGoawayId);

  nsresult ProcessOutput(nsIAsyncOutputStream* aOut);
  nsresult ProcessInput(nsIAsyncInputStream* aIn);
  nsresult ProcessEvents(uint32_t count, uint32_t* countWritten, bool* again);

  void QueueStream(Http3Stream* stream);
  void RemoveStreamFromQueues(Http3Stream*);
  void ProcessPending();

  RefPtr<NeqoHttp3Conn> mHttp3Connection;
  RefPtr<nsAHttpConnection> mConnection;
  nsDataHashtable<nsUint64HashKey, Http3Stream*> mStreamIDHash;
  nsClassHashtable<nsPtrHashKey<nsAHttpTransaction>, Http3Stream>
      mStreamTransactionHash;

  nsDeque mReadyForWrite;
  nsDeque mQueuedStreams;
  bool mConnected;
  bool mClosing;
  bool mClosed;
  bool mCleanShutdown;
  bool mGoawayReceived;
  bool mShouldClose;
  uint64_t mCurrentForegroundTabOuterContentWindowId;

  uint32_t mPacketToSendLen;
  UniquePtr<char[]> mPacketToSend;

  nsAHttpSegmentReader* mSegmentReader;
  nsAHttpSegmentWriter* mSegmentWriter;

  // The underlying socket transport object is needed to propogate some events
  nsISocketTransport* mSocketTransport;
};

}
}

#endif // Http3Session_H__
