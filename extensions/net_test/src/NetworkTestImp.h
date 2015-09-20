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
  NS_IMETHOD RunTest(NetworkTestListener *aListener, uint32_t aTestType);

  void AllTests();

private:
  static const int kNumberOfPorts = 5;
  static const uint16_t mPorts[kNumberOfPorts];
  static const int kNumberOfRepeats = 5;
  static const int kNumberOfRateTests = 6;

  ~NetworkTestImp();
  int GetHostAddr(nsAutoCString &aAddr);
  nsresult GetNextAddr(PRNetAddr *aAddr);
  void AddPort(PRNetAddr *aAddr, uint16_t aPort);
  void RunReachabilityTest();
  void RunTestWithFactor(uint16_t aPort, uint32_t aRateTestInx);
  nsresult UdpReachability();
  nsresult TcpReachability();
  nsresult UdpVsTcpPerformanceFromServerToClient(uint16_t aRemotePort,
    uint32_t aRateTestInx);
  nsresult UdpVsTcpPerformanceFromClientToServer(uint16_t aRemotePort,
    uint32_t aRateTestInx);

  void SendResults(uint16_t aRemotePort);
  void CallTestsFinished();
  void CallReachabilityTestsFinished();
  void CallRateTestsFinished(uint32_t aRateTestInx);
  PRAddrInfo *mAddrInfo;
  void *mIter;
  bool mTCPReachabilityResults[kNumberOfPorts];
  bool mUDPReachabilityResults[kNumberOfPorts];
  uint64_t mTCPFromServerRates[kNumberOfRateTests][kNumberOfRepeats];
  uint64_t mUDPFromServerRates[kNumberOfRateTests][kNumberOfRepeats];
  uint64_t mTCPToServerRates[kNumberOfRateTests][kNumberOfRepeats];
  uint64_t mUDPToServerRates[kNumberOfRateTests][kNumberOfRepeats];
  nsCOMPtr<NetworkTestListener> mCallback;
  uint32_t mTestType;
  nsCString mIdStr;
  PRNetAddr mAddr;
  nsCOMPtr<nsIThread> mThread;
};

} // namespace NetworkPath
#endif // mozilla_net_NetworkTestImp
