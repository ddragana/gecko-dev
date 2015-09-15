/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_NetworkTestImp
#define mozilla_net_NetworkTestImp

#include "NetworkTest.h"
#include "prnetdb.h"
#include "nsString.h"
#include "nsAutoPtr.h"
#include "nsIThread.h"
#include "nsIUUIDGenerator.h"

namespace NetworkPath {

class NetworkTestImp final : public NetworkTest
{
public:
  NS_DECL_THREADSAFE_ISUPPORTS

  NetworkTestImp();
  NS_IMETHOD RunTest(NetworkTestListener *aListener);

  void AllTests();

private:
  static const int kNumberOfPorts = 5;
  static const uint16_t mPorts[kNumberOfPorts];
  static const int kNumberOfRepeats = 5;

  ~NetworkTestImp();
  int GetHostAddr(nsAutoCString &aAddr);
  nsresult GetNextAddr(PRNetAddr *aAddr);
  void AddPort(PRNetAddr *aAddr, uint16_t aPort);
  nsresult UdpReachability(PRNetAddr *aNetAddr);
  nsresult TcpReachability(PRNetAddr *aNetAddr);
  nsresult UdpVsTcpPerformanceFromServerToClient(PRNetAddr *aNetAddr,
                                                 uint16_t aRemotePort,
                                                 char *aIdStr);
  nsresult UdpVsTcpPerformanceFromClientToServer(PRNetAddr *aNetAddr,
                                                 uint16_t aRemotePort,
                                                 char *aIdStr);

  void SendResults(PRNetAddr *aNetAddr,uint16_t aRemotePort, char *aIdStr);
  void TestsFinished();
  void ReachabilityTestsFinished();
  PRAddrInfo *mAddrInfo;
  void *mIter;
  bool mTCPReachabilityResults[kNumberOfPorts];
  bool mUDPReachabilityResults[kNumberOfPorts];
  uint64_t mTCPFromServerRates[kNumberOfRepeats];
  uint64_t mUDPFromServerRates[kNumberOfRepeats];
  uint64_t mTCPToServerRates[kNumberOfRepeats];
  uint64_t mUDPToServerRates[kNumberOfRepeats];
  nsCOMPtr<NetworkTestListener> mCallback;
  nsCOMPtr<nsIThread> mThread;
};

} // namespace NetworkPath
#endif // mozilla_net_NetworkTestImp
