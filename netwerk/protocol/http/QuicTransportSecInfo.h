/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef QuicTransportSecInfo_h
#define QuicTransportSecInfo_h

#include "nsISSLSocketControl.h"
#include "TransportSecurityInfo.h"

namespace mozilla {
namespace net {

class Http3Session;

// IID for the QuicTransportSecInfo interface
#define NS_QUICTRANSPORTSECINFO_IID                  \
  {                                                  \
    0xdbc67fd0, 0x1ac6, 0x457b, {                    \
      0x91, 0x4e, 0x4c, 0x86, 0x60, 0xff, 0x00, 0x69 \
    }                                                \
  }

class QuicTransportSecInfo final : public mozilla::psm::TransportSecurityInfo, 
                                   public nsISSLSocketControl {
 public:
  NS_DECLARE_STATIC_IID_ACCESSOR(NS_QUICTRANSPORTSECINFO_IID)

  NS_DECL_ISUPPORTS_INHERITED
  NS_DECL_NSISSLSOCKETCONTROL

  explicit QuicTransportSecInfo(uint32_t providerFlags);

  void SetSSLVersionUsed(uint16_t aVersion);
  void SetNegotiatedNPN(const nsACString& aValue);
  void SetResumed(bool aResumed);
  void SetInfo(uint16_t aCipherSuite, uint16_t aProtocolVersion,
    uint16_t aKeaGroup, uint16_t aSignatureScheme);

  void SetAuthenticationCallback(Http3Session *aHttp3Session);
  void CallAuthenticated();

  void HandshakeCompleted();
  void SetCertVerificationResult(PRErrorCode errorCode) override;
 private:
  ~QuicTransportSecInfo() = default;
  nsCString mNegotiatedNPN;
  bool mNPNCompleted;
  bool mHandshakeCompleted;
  bool mJoined;
  bool mFailedVerification;
  mozilla::Atomic<bool, mozilla::Relaxed> mResumed;
  uint16_t mSSLVersionUsed;
  uint32_t mProviderFlags;

  // For Authentication done callback.
  nsWeakPtr mHttp3Session;
};

NS_DEFINE_STATIC_IID_ACCESSOR(QuicTransportSecInfo, NS_QUICTRANSPORTSECINFO_IID)

}
}

#endif // QuicTransportSecInfo_h
