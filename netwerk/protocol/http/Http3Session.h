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
                           public nsAHttpSegmentWriter,
                           public nsICertAuthenticationListener,
                           public nsITimerCallback
{
 public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSAHTTPTRANSACTION
  NS_DECL_NSAHTTPCONNECTION(mConnection)
  NS_DECL_NSAHTTPSEGMENTREADER
  NS_DECL_NSAHTTPSEGMENTWRITER
  NS_DECL_NSICERTAUTHENTICATIONLISTENER
  NS_DECL_NSITIMERCALLBACK

  Http3Session();
  nsresult Init(const nsACString& aOrigin,
      nsISocketTransport* aSocketTransport, nsAHttpSegmentReader* reader,
      nsAHttpSegmentWriter* writer);

  bool Initialized() const { return mHttp3Connection; }
  bool IsConnected() { return mState == CONNECTED; }
  bool IsClosing() { return (mState == CLOSING || mState == CLOSED); }
  nsresult GetError() { return mError; }

  nsresult Process();

  void CloseInternal(bool aCallNeqoClose);
  void Shutdown();
  void ConnectionClosed();

  bool AddStream(nsAHttpTransaction* aHttpTransaction,
                 int32_t aPriority,
                 nsIInterfaceRequestor* aCallbacks);

  bool CanReuse();

  bool RoomForMoreStreams() { return mQueuedStreams.GetSize() == 0; }

  // We will let neqo-transport handle connection timeouts.
  uint32_t ReadTimeoutTick(PRIntervalTime now) { return UINT32_MAX; }

  // overload of nsAHttpTransaction
  MOZ_MUST_USE nsresult ReadSegmentsAgain(nsAHttpSegmentReader*, uint32_t,
                                          uint32_t*, bool*) final;
  MOZ_MUST_USE nsresult WriteSegmentsAgain(nsAHttpSegmentWriter*, uint32_t,
                                           uint32_t*, bool*) final;

  bool ResponseTimeoutEnabled() const final { return true; }
  PRIntervalTime ResponseTimeout() final;

  nsresult TryActivating(const nsACString& aMethod, const nsACString& aScheme,
    const nsACString& aHost, const nsACString& aPath,
    const nsACString& aHeaders, uint64_t* aStreamId, Http3Stream* aStream);

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

  nsISocketTransport* SocketTransport() { return mSocketTransport; }
 private:
  ~Http3Session();

  bool RealJoinConnection(const nsACString& hostname, int32_t port,
      bool justKidding);
  void Shutdown(uint64_t aGoawayId);

  nsresult ProcessOutput();
  nsresult ProcessInput();
  nsresult ProcessEvents(uint32_t count, uint32_t* countWritten, bool* again);
  nsresult ProcessOutputAndEvents();

  void SetupTimer(uint64_t aTimeout);

  void QueueStream(Http3Stream* stream);
  void RemoveStreamFromQueues(Http3Stream*);
  void ProcessPending();

  void CallCertVerification();

  RefPtr<NeqoHttp3Conn> mHttp3Connection;
  RefPtr<nsAHttpConnection> mConnection;
  nsDataHashtable<nsUint64HashKey, Http3Stream*> mStreamIdHash;
  nsClassHashtable<nsPtrHashKey<nsAHttpTransaction>, Http3Stream>
      mStreamTransactionHash;

  nsDeque mReadyForWrite;
  nsDeque mQueuedStreams;

  enum State {
   INITIALIZING,
   CONNECTED,
   CLOSING,
   CLOSED
  } mState;

  bool mCleanShutdown;
  bool mGoawayReceived;
  bool mShouldClose;
  nsresult mError;
  bool mBeforeConnectedError;
  uint64_t mCurrentForegroundTabOuterContentWindowId;

  nsTArray<uint8_t> mPacketToSend;

  nsAHttpSegmentReader* mSegmentReader;
  nsAHttpSegmentWriter* mSegmentWriter;

  // The underlying socket transport object is needed to propogate some events
  nsISocketTransport* mSocketTransport;

  nsCOMPtr<nsITimer> mTimer;

  nsDataHashtable<nsCStringHashKey, bool> mJoinConnectionCache;
};

}
}

#endif // Http3Session_H__
