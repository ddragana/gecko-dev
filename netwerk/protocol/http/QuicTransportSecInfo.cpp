/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "QuicTransportSecInfo.h"
#include "SharedCertVerifier.h"
#include "nsNSSComponent.h"
#include "nsWeakReference.h"
#include "sslt.h"
#include "ssl.h"

namespace mozilla {
namespace net {

NS_IMPL_ISUPPORTS_INHERITED(QuicTransportSecInfo, TransportSecurityInfo,
    nsISSLSocketControl, QuicTransportSecInfo)

QuicTransportSecInfo::QuicTransportSecInfo(uint32_t aProviderFlags)
    : mNPNCompleted(false),
      mHandshakeCompleted(false),
      mJoined(false),
      mFailedVerification(false),
      mResumed(false),
      mSSLVersionUsed(nsISSLSocketControl::SSL_VERSION_UNKNOWN),
      mProviderFlags(aProviderFlags) {
}

NS_IMETHODIMP
QuicTransportSecInfo::GetProviderFlags(uint32_t* aProviderFlags) {
  *aProviderFlags = mProviderFlags;
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::GetSSLVersionUsed(int16_t* aSSLVersionUsed) {
  *aSSLVersionUsed = mSSLVersionUsed;
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::GetSSLVersionOffered(int16_t* aSSLVersionOffered) {
  *aSSLVersionOffered = nsISSLSocketControl::TLS_VERSION_1_3;
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::GetClientCertSent(bool* arg) {
  *arg = false;
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::GetFailedVerification(bool* arg) {
  *arg = mFailedVerification;
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::GetServerRootCertIsBuiltInRoot(bool* aIsBuiltInRoot) {
  *aIsBuiltInRoot = false;

  if (!HasServerCert()) {
    return NS_ERROR_NOT_AVAILABLE;
  }

  nsCOMPtr<nsIX509CertList> certList;
  nsresult rv = GetSucceededCertChain(getter_AddRefs(certList));
  if (NS_SUCCEEDED(rv)) {
    if (!certList) {
      return NS_ERROR_NOT_AVAILABLE;
    }
    RefPtr<nsNSSCertList> nssCertList = certList->GetCertList();
    nsCOMPtr<nsIX509Cert> cert;
    rv = nssCertList->GetRootCertificate(cert);
    if (NS_SUCCEEDED(rv)) {
      if (!cert) {
        return NS_ERROR_NOT_AVAILABLE;
      }
      rv = cert->GetIsBuiltInRoot(aIsBuiltInRoot);
    }
  }
  return rv;
}

NS_IMETHODIMP
QuicTransportSecInfo::GetNotificationCallbacks(nsIInterfaceRequestor** aCallbacks) {
  *aCallbacks = mCallbacks;
  NS_IF_ADDREF(*aCallbacks);
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::SetNotificationCallbacks(nsIInterfaceRequestor* aCallbacks) {
  mCallbacks = aCallbacks;
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::GetNegotiatedNPN(nsACString& aNegotiatedNPN) {
  if (!mNPNCompleted) return NS_ERROR_NOT_CONNECTED;

  aNegotiatedNPN = mNegotiatedNPN;
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::JoinConnection(const nsACString& npnProtocol,
                                     const nsACString& hostname, int32_t port,
                                     bool* _retval) {
  nsresult rv = TestJoinConnection(npnProtocol, hostname, port, _retval);
  if (NS_SUCCEEDED(rv) && *_retval) {
    // All tests pass - this is joinable
    mJoined = true;
  }
  return rv;
}

NS_IMETHODIMP
QuicTransportSecInfo::TestJoinConnection(const nsACString& npnProtocol,
                                         const nsACString& hostname, int32_t port,
                                         bool* _retval) {
  *_retval = false;

  // Different ports may not be joined together
  if (port != GetPort()) return NS_OK;

  // Make sure NPN has been completed and matches requested npnProtocol
  if (!mNPNCompleted || !mNegotiatedNPN.Equals(npnProtocol)) return NS_OK;

  IsAcceptableForHost(hostname, _retval);  // sets _retval
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::IsAcceptableForHost(const nsACString& hostname,
                                          bool* _retval) {
  NS_ENSURE_ARG(_retval);

  *_retval = false;

  // If this is the same hostname then the certicate status does not
  // need to be considered. They are joinable.
  if (hostname.Equals(GetHostName())) {
    *_retval = true;
    return NS_OK;
  }

  // Before checking the server certificate we need to make sure the
  // handshake has completed.
  if (!mHandshakeCompleted || !HasServerCert()) {
    return NS_OK;
  }

  // If the cert has error bits (e.g. it is untrusted) then do not join.
  // The value of mHaveCertErrorBits is only reliable because we know that
  // the handshake completed.
  if (mHaveCertErrorBits) {
    return NS_OK;
  }

  // Ensure that the server certificate covers the hostname that would
  // like to join this connection

  UniqueCERTCertificate nssCert;

  nsCOMPtr<nsIX509Cert> cert;
  if (NS_FAILED(GetServerCert(getter_AddRefs(cert)))) {
    return NS_OK;
  }
  if (cert) {
    nssCert.reset(cert->GetCert());
  }

  if (!nssCert) {
    return NS_OK;
  }

  // Attempt to verify the joinee's certificate using the joining hostname.
  // This ensures that any hostname-specific verification logic (e.g. key
  // pinning) is satisfied by the joinee's certificate chain.
  // This verification only uses local information; since we're on the network
  // thread, we would be blocking on ourselves if we attempted any network i/o.
  // TODO(bug 1056935): The certificate chain built by this verification may be
  // different than the certificate chain originally built during the joined
  // connection's TLS handshake. Consequently, we may report a wrong and/or
  // misleading certificate chain for HTTP transactions coalesced onto this
  // connection. This may become problematic in the future. For example,
  // if/when we begin relying on intermediate certificates being stored in the
  // securityInfo of a cached HTTPS response, that cached certificate chain may
  // actually be the wrong chain. We should consider having JoinConnection
  // return the certificate chain built here, so that the calling Necko code
  // can associate the correct certificate chain with the HTTP transactions it
  // is trying to join onto this connection.
  RefPtr<psm::SharedCertVerifier> certVerifier(psm::GetDefaultCertVerifier());
  if (!certVerifier) {
    return NS_OK;
  }
  psm::CertVerifier::Flags flags = psm::CertVerifier::FLAG_LOCAL_ONLY;
  UniqueCERTCertList unusedBuiltChain;
  mozilla::pkix::Result result = certVerifier->VerifySSLServerCert(
      nssCert,
      Maybe<nsTArray<uint8_t>>(),  // stapledOCSPResponse
      Maybe<nsTArray<uint8_t>>(),  // sctsFromTLSExtension
      mozilla::pkix::Now(),
      nullptr,  // pinarg
      hostname, unusedBuiltChain,
      false,  // save intermediates
      flags);
  if (result != mozilla::pkix::Success) {
    return NS_OK;
  }

  // All tests pass
  *_retval = true;
  return NS_OK;
}

NS_IMETHODIMP
QuicTransportSecInfo::GetResumed(bool* aResumed) {
  *aResumed = mResumed;
  return NS_OK;
}

void QuicTransportSecInfo::SetSSLVersionUsed(uint16_t aVersion) {
  mSSLVersionUsed = aVersion;
} 

void QuicTransportSecInfo::SetNegotiatedNPN(const nsACString& aValue) {
  mNegotiatedNPN = aValue;
  mNPNCompleted = true;
} 
  
void QuicTransportSecInfo::SetResumed(bool aResumed) {
  mResumed = aResumed;
}

void QuicTransportSecInfo::SetCertVerificationResult(PRErrorCode errorCode) {
  if (errorCode) {
    mFailedVerification = true;
    SetCanceled(errorCode);
  }

  if (OnSocketThread()) {
    CallAuthenticated();
  } else {
    DebugOnly<nsresult> rv = gSocketTransportService->Dispatch(
        NewRunnableMethod(
            "QuicTransportSecInfo::CallAuthenticated", this,
            &QuicTransportSecInfo::CallAuthenticated),
        NS_DISPATCH_NORMAL);
  }
}

void QuicTransportSecInfo::CallAuthenticated() {
  if (mHttp3Session) {
    RefPtr<Http3Session> http3Session = do_QueryReferent(mHttp3Session);
    http3Session->Authenticated(GetErrorCode());
  }
  mHttp3Session = nullptr;
}

void QuicTransportSecInfo::SetAuthenticationCallback(Http3Session *aHttp3Session) {
  mHttp3Session = do_GetWeakReference(
      static_cast<nsISupportsWeakReference*>(aHttp3Session));
}

void QuicTransportSecInfo::HandshakeCompleted() {
  psm::RememberCertErrorsTable::GetInstance().LookupCertErrorBits(this);

  uint32_t state = nsIWebProgressListener::STATE_IS_SECURE;

  bool distrustImminent;
  nsresult srv =
      IsCertificateDistrustImminent(mSucceededCertChain, distrustImminent);
  if (NS_SUCCEEDED(srv) && distrustImminent) {
    state |= nsIWebProgressListener::STATE_CERT_DISTRUST_IMMINENT;
  }

  // If we're here, the TLS handshake has succeeded. Thus if any of these
  // booleans are true, the user has added an override for a certificate error.
  if (mIsDomainMismatch || mIsUntrusted || mIsNotValidAtThisTime) {
    state |= nsIWebProgressListener::STATE_CERT_USER_OVERRIDDEN;
  }

  SetSecurityState(state);
  mHandshakeCompleted = true;
}

void QuicTransportSecInfo::SetInfo(uint16_t aCipherSuite,
    uint16_t aProtocolVersion, uint16_t aKeaGroup, uint16_t aSignatureScheme) {
  SSLCipherSuiteInfo cipherInfo;
  if (SSL_GetCipherSuiteInfo(aCipherSuite, &cipherInfo,
                             sizeof cipherInfo) == SECSuccess) {
    mHaveCipherSuiteAndProtocol = true;
    mCipherSuite = aCipherSuite;
    mProtocolVersion = aProtocolVersion & 0xFF;
    mKeaGroup = getKeaGroupName(aKeaGroup);
    mSignatureSchemeName = getSignatureName(aSignatureScheme);
  }
}

}
}
