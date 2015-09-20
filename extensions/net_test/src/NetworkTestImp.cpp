/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set sw=2 ts=2 et ft=cpp : */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "NetworkTestImp.h"
#include "TCP.h"
#include "UDP.h"
#include "mozilla/Module.h"
#include "prlog.h"
#include "nsTArray.h"
#include "nsThreadUtils.h"
#include "nsServiceManagerUtils.h"
#include "nsPrintfCString.h"
#include <string>

namespace NetworkPath {

PRLogModuleInfo* gClientTestLog;
#define LOG(args) PR_LOG(gClientTestLog, PR_LOG_DEBUG, args)

uint64_t maxBytes = (1<<21);
uint32_t maxTime = 4; //TODO:change this to 12s or better make it dependent on the rate

// 61590 is in the ephemeral range
// 2708 is in the reserved but no priv range
// 891 is privd but unused
// 443 is special
// 80 is special
const uint16_t NetworkTestImp::mPorts[] = { 61590, 2708, 891, 443, 80 };

// todo pref
static nsAutoCString address(NS_LITERAL_CSTRING("localhost"));

NS_IMPL_ISUPPORTS(NetworkTestImp, NetworkTest)

NetworkTestImp::NetworkTestImp()
{
  gClientTestLog = PR_NewLogModule("NetworkTestClient");
}

NetworkTestImp::~NetworkTestImp()
{
  PR_FreeAddrInfo(mAddrInfo);
}

class CloseNetworkTestThread final : public nsIRunnable
{
public:
  NS_DECL_THREADSAFE_ISUPPORTS

  CloseNetworkTestThread(nsIThread* aThread)
  : mThread(aThread)
  {
  }

  NS_METHOD Run()
  {
    LOG(("NetworkTest client side: Shutdown thread."));
    if (mThread) {
      mThread->Shutdown();
    }
    return NS_OK;
  }

private:
  ~CloseNetworkTestThread() {}
  nsCOMPtr<nsIThread> mThread;
};

NS_IMPL_ISUPPORTS(CloseNetworkTestThread, nsIRunnable)

void
NetworkTestImp::CallTestsFinished()
{
  if (mCallback) {
    mCallback->TestsFinished();
  }

  nsresult rv = NS_DispatchToMainThread(new CloseNetworkTestThread(mThread));
  if (NS_FAILED(rv)) {
    if (mThread) {
      mThread->Shutdown();
    }
  }
}

void
NetworkTestImp::AllTests()
{
  nsresult rv;
  nsCOMPtr<nsIUUIDGenerator> uuidGenerator;
  uuidGenerator = do_GetService("@mozilla.org/uuid-generator;1", &rv);
  if (NS_FAILED(rv)) {
    goto done;
  }

  nsID id;
  rv = uuidGenerator->GenerateUUIDInPlace(&id);
  if (NS_WARN_IF(NS_FAILED(rv))) {
    goto done;
  }

  char idStr[NSID_LENGTH];
  id.ToProvidedString(idStr);
  idStr[NSID_LENGTH-2] = '\0';
  mIdStr.Append(idStr + 1, NSID_LENGTH-3);

  LOG(("Get host addr."));
  if (GetHostAddr(address) != 0) {
    goto done;
  }

  mIter = nullptr;
  if (NS_FAILED(GetNextAddr(&mAddr))) {
    goto done;
  }

  // should probably record if this is v4/v6

  {
    char host[164] = {0};
    PR_NetAddrToString(&mAddr, host, sizeof(host));
    LOG(("Get host: %s", host));
  }

  for (int inx = 0; inx < kNumberOfPorts; inx++) {
    mTCPReachabilityResults[inx] = false;
    mUDPReachabilityResults[inx] = false;
  }

  for (int inx1 = 0; inx1 < kNumberOfRateTests; inx1++) {
    for (int inx2 = 0; inx2 < kNumberOfRepeats; inx2++) {
      mTCPFromServerRates[inx1][inx2] = 0;
      mUDPFromServerRates[inx1][inx2] = 0;
      mTCPToServerRates[inx1][inx2] = 0;
      mUDPToServerRates[inx1][inx2] = 0;
    }
  }

  if (mTestType & REACHABILITY_TEST) {
    RunReachabilityTest();
  }

  {
    uint16_t port = 0;
    if (!(mTestType & REACHABILITY_TEST)) {
      port = 80;
    } else {
      for (int inx = 0; inx < kNumberOfPorts; inx++) {
        if (mTCPReachabilityResults[inx] && mUDPReachabilityResults[inx]) {
          port = mPorts[inx];
          break;
        }
      }
    }

    if (port != 0) {
      for (uint32_t i = 1; i <= kNumberOfRateTests; i++) {
        if (mTestType & (1 << i)) {
          RunTestWithFactor(port, i - 1);
        }
      }
    }
  }

done:

  int port = 80;
  for (int inx = kNumberOfPorts - 1; inx >= 0; inx--) {
    if (mTCPReachabilityResults[inx]) {
      port = mPorts[inx];
      break;
    }
  }
  if (port != -1) {
    SendResults(port);
  }

  rv = NS_DispatchToMainThread(
    NS_NewRunnableMethod(this, &NetworkTestImp::CallTestsFinished));
  if (NS_FAILED(rv)) {
    if (mThread) {
      mThread->Shutdown();
    }
  }
}

void
NetworkTestImp::RunReachabilityTest()
{
  UdpReachability();
  TcpReachability();

  // Check if there is a at least one port reachable over tcp that we can send
  // data. If not there is no need of writing data to a file.
  int portInx = -1;
  for (int inx = 0; inx < kNumberOfPorts; inx++) {
    if (mTCPReachabilityResults[inx] && mUDPReachabilityResults[inx]) {
      portInx = inx;
      break;
    }
  }
  if (portInx != -1) {
    FileWriter logFile;
    logFile.Init(nsPrintfCString("%s_test1and2", mIdStr.get()));
    char logStr[100];
    for (int inx = 0; inx < kNumberOfPorts; ++inx) {
      sprintf(logStr, "Reachability on port %d with TCP - %s\n", mPorts[inx],
              (mTCPReachabilityResults[inx]) ? "yes" : "no");
      logFile.WriteNonBlocking(logStr, strlen(logStr));
      sprintf(logStr, "Reachability on port %d with UDP - %s\n", mPorts[inx],
              (mUDPReachabilityResults[inx]) ? "yes" : "no");
      logFile.WriteNonBlocking(logStr, strlen(logStr));
    }
    logFile.Done();
  }

  NS_DispatchToMainThread(NS_NewRunnableMethod(this,
                          &NetworkTestImp::CallReachabilityTestsFinished));
}

void
NetworkTestImp::CallRateTestsFinished(uint32_t aRateTestInx)
{
  if (mCallback) {
    float factor = 1.0 + 0.2 * (aRateTestInx);
    mCallback->RateTestsFinished(factor,
                                 kNumberOfRepeats,
                                 mTCPFromServerRates[aRateTestInx],
                                 mUDPFromServerRates[aRateTestInx],
                                 mTCPToServerRates[aRateTestInx],
                                 mUDPToServerRates[aRateTestInx]);
  }
}

void
NetworkTestImp::RunTestWithFactor(uint16_t aPort, uint32_t aRateTestInx)
{
  UdpVsTcpPerformanceFromServerToClient(aPort, aRateTestInx);
  UdpVsTcpPerformanceFromClientToServer(aPort, aRateTestInx);

  if (mCallback) {
    NS_DispatchToMainThread(NS_NewRunnableMethodWithArg<uint32_t>(
      this,
      &NetworkTestImp::CallRateTestsFinished,
      aRateTestInx));
  }
}

NS_IMETHODIMP
NetworkTestImp::RunTest(NetworkTestListener *aCallback, uint32_t aTestType)
{
  NS_ENSURE_ARG(aCallback);
  if (mCallback) {
    return NS_ERROR_NOT_AVAILABLE;
  }
  mCallback = aCallback;
  mTestType = aTestType;
  nsresult rv = NS_NewThread(getter_AddRefs(mThread),
                             NS_NewRunnableMethod(this, &NetworkTestImp::AllTests));
  if (NS_FAILED(rv)) {
    LOG(("NetworkTest client side: Error creating the test thread"));
    return rv;
  }
  return NS_OK;
}

void
NetworkTestImp::CallReachabilityTestsFinished()
{
  if (mCallback) {
    nsCOMPtr<NetworkTestListener> callback;
    callback = mCallback;
    callback->ReachabilityTestsFinished(kNumberOfPorts,
                                        const_cast<uint16_t*>(mPorts),
                                        mTCPReachabilityResults,
                                        mUDPReachabilityResults);
  }
}

int
NetworkTestImp::GetHostAddr(nsAutoCString &aAddr)
{
  int flags = PR_AI_ADDRCONFIG;
  uint16_t af = PR_AF_UNSPEC;
  mAddrInfo = PR_GetAddrInfoByName(aAddr.get(), af, flags);
  return 0;
}

nsresult
NetworkTestImp::GetNextAddr(PRNetAddr *aAddr)
{
  mIter = PR_EnumerateAddrInfo(mIter, mAddrInfo, 0, aAddr);

  if (!mIter) {
    return NS_ERROR_FAILURE;
  }
  return NS_OK;
}

void
NetworkTestImp::AddPort(PRNetAddr *aAddr, uint16_t aPort)
{
  aPort = htons(aPort);
  if (aAddr->raw.family == AF_INET) {
    aAddr->inet.port = aPort;
  }
  else if (aAddr->raw.family == AF_INET6) {
    aAddr->ipv6.port = aPort;
  }
}

// UDP reachability
nsresult
NetworkTestImp::UdpReachability()
{
  nsresult rv;
  for (int inx = 0; inx < kNumberOfPorts; ++inx) {
    LOG(("NetworkTest: Testing udp reachability on port %d.", mPorts[inx]));
    AddPort(&mAddr, mPorts[inx]);
    UDP udp(&mAddr);
    bool testSuccess = false;
    // This is test number 1.
    rv = udp.Start(1, 0, EmptyCString(), testSuccess);
    if (NS_FAILED(rv) || !testSuccess) {
      LOG(("NetworkTest: Testing udp reachability on port %d - failed.",
           mPorts[inx]));
    } else {
      mUDPReachabilityResults[inx] = true;
      LOG(("NetworkTest: Testing udp reachability on port %d - succeeded.",
           mPorts[inx]));
    }
  }
  return NS_OK;
}

// TCP reachability
nsresult
NetworkTestImp::TcpReachability()
{
  nsresult rv;
  for (int inx = 0; inx < kNumberOfPorts; inx++) {
    LOG(("NetworkTest: Testing tcp reachability on port %d.", mPorts[inx]));
    AddPort(&mAddr, mPorts[inx]);

    TCP tcp(&mAddr);
    // This is test 2.
    rv = tcp.Start(2, EmptyCString());
    if (NS_FAILED(rv)) {
      LOG(("NetworkTest: Testing tcp reachability on port %d - failed.",
           mPorts[inx]));
    } else {
      mTCPReachabilityResults[inx] = true;
      LOG(("NetworkTest: Testing tcp reachability on port %d - succeeded.",
           mPorts[inx]));
    }
  }
  return NS_OK;
}

// UDP vs TCP performance from a server to a client.
nsresult
NetworkTestImp::UdpVsTcpPerformanceFromServerToClient(uint16_t aRemotePort,
                                                      uint32_t aRateTestInx)
{
  float factor = 1.0 + 0.2 * (aRateTestInx);

  LOG(("NetworkTest: Testing UDP vs TCP performance from the server to the "
       "client on port %d, factor %f.", aRemotePort, factor));

  AddPort(&mAddr, aRemotePort);
  TCP tcp(&mAddr);
  bool testSuccess = false;
  nsresult rv;

  for (int iter = 0; iter < kNumberOfRepeats; iter++) {
    rv = tcp.Start(3,
                   nsPrintfCString("%s_test3_f%.1f_itr%d", mIdStr.get(), factor, iter));
    LOG(("NetworkTest: Testing UDP vs TCP performance from the server to the "
         "client on port %d iteration %d - achieved tcp rate: %llu",
         aRemotePort, iter, tcp.GetRate()));
    if (NS_FAILED(rv)) {
      return rv;
    }

    UDP udp(&mAddr);
    rv = udp.Start(5,
                   factor * tcp.GetRate(),
                   nsPrintfCString("%s_test5_f%.1f_itr%d", mIdStr.get(), factor, iter),
                   testSuccess);
    if (NS_FAILED(rv) && !testSuccess) {
      return rv;
    }
    LOG(("NetworkTest: Testing UDP vs TCP performance from the server to the "
         " client on port %d iteration %d - achieved udp rate: %llu",
         aRemotePort, iter, udp.GetRate()));
    mTCPFromServerRates[aRateTestInx][iter] = tcp.GetRate();
    mUDPFromServerRates[aRateTestInx][iter] = udp.GetRate();
  }
  return rv;
}

// UDP vs. TCP performance from a client to a server.
nsresult
NetworkTestImp::UdpVsTcpPerformanceFromClientToServer(uint16_t aRemotePort,
                                                      uint32_t aRateTestInx)
{
  float factor = 1.0 + 0.2 * aRateTestInx;
  LOG(("NetworkTest: Testing UDP vs TCP performance from the client to the "
       "server on port %d %f.", aRemotePort, factor));
  AddPort(&mAddr, aRemotePort);
  TCP tcp(&mAddr);
  bool testSuccess = false;
  nsresult rv;

  for (int iter = 0; iter < kNumberOfRepeats; iter++) {
    rv = tcp.Start(4,
                   nsPrintfCString("%s_test4_f%.1f_itr%d", mIdStr.get(), factor, iter));
    LOG(("NetworkTest: Testing UDP vs TCP performance from the client to the "
         "server on port %d iteration %d - achieved tcp rate: %llu",
         aRemotePort, iter, tcp.GetRate()));

    if (NS_FAILED(rv)) {
      return rv;
    }

    UDP udp(&mAddr);
    rv = udp.Start(6,
                   factor * tcp.GetRate(),
                   nsPrintfCString("%s_test6_f%.1f_itr%d", mIdStr.get(), factor, iter),
                   testSuccess);
    if (NS_FAILED(rv) && !testSuccess) {
      LOG(("NetworkTest: UdpVsTcpPerformanceFromClientToServer error: %d %d",
           rv, testSuccess));
      return rv;
    }
    LOG(("NetworkTest: Testing UDP vs TCP performance from the client to the "
         "server on port %d iteration %d - achieved udp rate: %llu",
         aRemotePort, iter, udp.GetRate()));
    mTCPToServerRates[aRateTestInx][iter] = tcp.GetRate();
    mUDPToServerRates[aRateTestInx][iter] = udp.GetRate();
  }
  return rv;
}

void
NetworkTestImp::SendResults(uint16_t aRemotePort)
{
  AddPort(&mAddr, aRemotePort);
  {
    TCP tcp(&mAddr);
    tcp.SendResult(nsPrintfCString("%s_test1and2", mIdStr.get()));
  }
  for (int test = 3; test <= 6; test++) {
    for (int iter = 0; iter < kNumberOfRepeats; iter++) {
      for (int aRateTestInx = 0; aRateTestInx < kNumberOfRateTests; aRateTestInx++) {
        float factor = 1.0 + 0.2 * aRateTestInx;
        TCP tcp(&mAddr);
        tcp.SendResult(nsPrintfCString("%s_test%d_f%.1f_itr%d", mIdStr.get(),
                                       test, factor, iter));
      }
    }
  }
}

} // namespace NetworkPath

static nsresult
NetworkTestContructor(nsISupports *aOuter, REFNSIID aIID, void **aResult)
{
  *aResult = nullptr;
  if (nullptr != aOuter) {
    return NS_ERROR_NO_AGGREGATION;
  }

  nsRefPtr<NetworkPath::NetworkTestImp> inst = new NetworkPath::NetworkTestImp();
  return inst->QueryInterface(aIID, aResult);
}

NS_DEFINE_NAMED_CID(NETWORKTEST_CID);

static const mozilla::Module::CIDEntry kNetworkTestCIDs[] = {
  { &kNETWORKTEST_CID, false, nullptr, NetworkTestContructor },
  { nullptr }
};

static const mozilla::Module::ContractIDEntry kNetworkTestContracts[] = {
  { NETWORKTEST_CONTRACTID, &kNETWORKTEST_CID },
  { nullptr }
};

static const mozilla::Module kNetworkTestModule = {
  mozilla::Module::kVersion,
  kNetworkTestCIDs,
  kNetworkTestContracts,
  nullptr,
  nullptr,
  nullptr,
  nullptr
};

NSMODULE_DEFN(NetworkTestModule) = &kNetworkTestModule;
