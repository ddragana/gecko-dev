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

void
NetworkTestImp::AllTests()
{
  // worker thread
  for (int inx = 0; inx < kNumberOfPorts; inx++) {
    mTCPReachabilityResults[inx] = false;
    mUDPReachabilityResults[inx] = false;
  }

  for (int inx = 0; inx < kNumberOfRepeats; ++inx){
    mTCPFromServerRates[inx] = 0;
    mUDPFromServerRates[inx] = 0;
    mTCPToServerRates[inx] = 0;
    mUDPToServerRates[inx] = 0;
  }

  mIter = nullptr;

  bool complete = false;

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

  LOG(("Get host addr."));
  if (GetHostAddr(address) != 0) {
    goto done;
  }

  PRNetAddr addr;
  if (NS_FAILED(GetNextAddr(&addr))) {
    goto done;
  }

  // should probably record if this is v4/v6
  // should probably separate out reports from same client

  {
    char host[164] = {0};
    PR_NetAddrToString(&addr, host, sizeof(host));
    LOG(("Get host: %s", host));
  }

  UdpReachability(&addr);

  TcpReachability(&addr);

  NS_DispatchToMainThread(NS_NewRunnableMethod(this, &NetworkTestImp::ReachabilityTestsFinished));

  { // scoping for declaration and goto
    int portInx = -1;
    for (int inx = 0; inx < kNumberOfPorts; inx++) {
      if (mTCPReachabilityResults[inx] && mUDPReachabilityResults[inx]) {
        portInx = inx;
        break;
      }
    }
    if (portInx != -1) {
      FileWriter logFile;
      logFile.Init(nsPrintfCString("%s_test1and2", idStr + 1));
      char logStr[100];
      for (int inx = 0; inx < kNumberOfPorts; ++inx) {
        sprintf(logStr, "Port %d is %s reachable using TCP\n", mPorts[inx],
                (mTCPReachabilityResults[inx]) ? "" : "not");
        logFile.WriteNonBlocking(logStr, strlen(logStr));
         sprintf(logStr, "Port %d is %s reachable using UDP\n", mPorts[inx],
                (mUDPReachabilityResults[inx]) ? "" : "not");
        logFile.WriteNonBlocking(logStr, strlen(logStr));
      }
      logFile.Done();
      UdpVsTcpPerformanceFromServerToClient(&addr, mPorts[portInx], idStr + 1);
      UdpVsTcpPerformanceFromClientToServer(&addr, mPorts[portInx], idStr + 1);
    }
  }

  complete = true;

done:
  LOG(("NetworkTest client side: Tests finished %s.", complete ? "ok" : "failed"));
  int portInx = -1;
  for (int inx = kNumberOfPorts - 1; inx >= 0; inx--) {
    if (mTCPReachabilityResults[inx]) {
      portInx = inx;
      break;
    }
  }
  if (portInx != -1) {
    SendResults(&addr, mPorts[portInx], idStr + 1);
  }
  NS_DispatchToMainThread(NS_NewRunnableMethod(this, &NetworkTestImp::TestsFinished));
}

NS_IMETHODIMP
NetworkTestImp::RunTest(NetworkTestListener *aCallback)
{
  NS_ENSURE_ARG(aCallback);
  if (mCallback) {
    return NS_ERROR_NOT_AVAILABLE;
  }
  mCallback = aCallback;
  nsresult rv = NS_NewThread(getter_AddRefs(mThread),
                             NS_NewRunnableMethod(this, &NetworkTestImp::AllTests));
  if (NS_FAILED(rv)) {
    LOG(("NetworkTest client side: Error creating the test thread"));
    return rv;
  }
  return NS_OK;
}

void
NetworkTestImp::TestsFinished()
{
  LOG(("NetworkTest client side: Shutdown thread."));
  if (mThread) {
    mThread->Shutdown();
  }

  if (mCallback) {
    nsCOMPtr<NetworkTestListener> callback;
    callback.swap(mCallback);
    callback->TestsFinished(kNumberOfRepeats,
                            mTCPFromServerRates,
                            mUDPFromServerRates,
                            mTCPToServerRates,
                            mUDPToServerRates);
  }
}

void
NetworkTestImp::ReachabilityTestsFinished()
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
NetworkTestImp::UdpReachability(PRNetAddr *aNetAddr)
{
  nsresult rv;
  for (int inx = 0; inx < kNumberOfPorts; ++inx) {
    LOG(("NetworkTest: Testing udp reachability on port %d.", mPorts[inx]));
    AddPort(aNetAddr, mPorts[inx]);
    UDP udp(aNetAddr);
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
NetworkTestImp::TcpReachability(PRNetAddr *aNetAddr)
{
  nsresult rv;
  for (int inx = 0; inx < kNumberOfPorts; inx++) {
    LOG(("NetworkTest: Testing tcp reachability on port %d.", mPorts[inx]));
    AddPort(aNetAddr, mPorts[inx]);

    TCP tcp(aNetAddr);
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
NetworkTestImp::UdpVsTcpPerformanceFromServerToClient(PRNetAddr *aNetAddr,
                                                      uint16_t aRemotePort,
                                                      char *aIdStr)
{
  LOG(("NetworkTest: Testing UDP vs TCP performance from the server to the "
       "client on port %d.", aRemotePort));
  AddPort(aNetAddr, aRemotePort);
  TCP tcp(aNetAddr);
  bool testSuccess = false;
  nsresult rv;

  for (int iter = 0; iter < kNumberOfRepeats; iter++) {
    rv = tcp.Start(3,
                   nsPrintfCString("%s_test3_itr%d", aIdStr, iter));
    LOG(("NetworkTest: Testing UDP vs TCP performance from the server to the "
         "client on port %d iteration %d - achieved tcp rate: %llu",
         aRemotePort, iter, tcp.GetRate()));
    if (NS_FAILED(rv)) {
      return rv;
    }

    UDP udp(aNetAddr);
    rv = udp.Start(5,
                   tcp.GetRate(),
                   nsPrintfCString("%s_test5_itr%d", aIdStr, iter),
                   testSuccess);
    if (NS_FAILED(rv) && !testSuccess) {
      return rv;
    }
    LOG(("NetworkTest: Testing UDP vs TCP performance from the server to the "
         " client on port %d iteration %d - achieved udp rate: %llu",
         aRemotePort, iter, udp.GetRate()));
    mTCPFromServerRates[iter] = tcp.GetRate();
    mUDPFromServerRates[iter] = udp.GetRate();
  }
  return rv;
}

// UDP vs. TCP performance from a client to a server.
nsresult
NetworkTestImp::UdpVsTcpPerformanceFromClientToServer(PRNetAddr *aNetAddr,
                                                      uint16_t aRemotePort,
                                                      char *aIdStr)
{
  LOG(("NetworkTest: Testing UDP vs TCP performance from the client to the "
       "server on port %d.", aRemotePort));
  AddPort(aNetAddr, aRemotePort);
  TCP tcp(aNetAddr);
  bool testSuccess = false;
  nsresult rv;

  for (int iter = 0; iter < kNumberOfRepeats; iter++) {
    rv = tcp.Start(4,
                   nsPrintfCString("%s_test4_itr%d", aIdStr, iter));
    LOG(("NetworkTest: Testing UDP vs TCP performance from the client to the "
         "server on port %d iteration %d - achieved tcp rate: %llu",
         aRemotePort, iter, tcp.GetRate()));
    if (NS_FAILED(rv)) {
      return rv;
    }

    UDP udp(aNetAddr);
    rv = udp.Start(6,
                   tcp.GetRate(),
                   nsPrintfCString("%s_test6_itr%d", aIdStr, iter),
                   testSuccess);
    if (NS_FAILED(rv) && !testSuccess) {
      LOG(("NetworkTest: UdpVsTcpPerformanceFromClientToServer error: %d %d",
           rv, testSuccess));
      return rv;
    }
    LOG(("NetworkTest: Testing UDP vs TCP performance from the client to the "
         "server on port %d iteration %d - achieved udp rate: %llu",
         aRemotePort, iter, udp.GetRate()));
    mTCPToServerRates[iter] = tcp.GetRate();
    mUDPToServerRates[iter] = udp.GetRate();
  }
  return rv;
}

void
NetworkTestImp::SendResults(PRNetAddr *aNetAddr, uint16_t aRemotePort, char *aIdStr)
{
  AddPort(aNetAddr, aRemotePort);
  {
    TCP tcp(aNetAddr);
    tcp.SendResult(nsPrintfCString("%s_test1and2", aIdStr));
  }
  for (int test = 3; test <= 6; test++) {
    for (int iter = 0; iter < kNumberOfRepeats; iter++) {
      TCP tcp(aNetAddr);
      tcp.SendResult(nsPrintfCString("%s_test%d_itr%d", aIdStr, test, iter));
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
