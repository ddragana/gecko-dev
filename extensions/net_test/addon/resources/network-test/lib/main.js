var { Cc, Ci } = require("chrome");
var buttons = require('sdk/ui/button/action');
var tabs = require("sdk/tabs");
var mod = require("sdk/page-mod");
var self = require("sdk/self");

var working = false;

var button = buttons.ActionButton({
  id: "network-tester",
  label: "Start network tester",
  icon: {
    "16": "./icon-16.png",
    "32": "./icon-32.png",
    "64": "./icon-64.png"
  },
  onClick: handleClick
});

var listener = function(worker) {
this.worker = worker;
};

listener.prototype = {
  reachabilityTestsFinished: function(count, ports, tcpReached, udpReached) {
    console.log("Network reachability tests finished");
    this.worker.port.emit("reachability", [ JSON.stringify(ports),
                                            JSON.stringify(tcpReached),
                                            JSON.stringify(udpReached)
                                          ]);

  },
  rateTestsFinished: function(factor, count, ratesTCPfromS, ratesUDPfromS, ratesTCPfromC, ratesUDPfromC) {
    console.log("Network rate tests finished");
    this.worker.port.emit("rateTestsFinished", [ factor,
                                                 JSON.stringify(ratesTCPfromS),
                                                 JSON.stringify(ratesUDPfromS),
                                                 JSON.stringify(ratesTCPfromC),
                                                 JSON.stringify(ratesUDPfromC),
                                               ]);
    working = false;
  },
  testsFinished: function() {
    console.log("Network tests finished");
    this.worker.port.emit("testsFinished");
  },
  QueryInterface: function(aIID) {
    if (aIID.equals(Ci.NetworkTestListener) ||
        aIID.equals(Ci.nsISupports)) {
      return this;
    }
    throw Cr.NS_ERROR_NO_INTERFACE;
  }
};

function startTest(worker) {
  console.log("launching network tester");
  var netTest = Cc["@mozilla.org/network-test;1"].getService(Ci.NetworkTest);
  netTest.runTest(new listener(worker),
                  Ci.NetworkTest.REACHABILITY_TEST |
                  Ci.NetworkTest.RATE_TEST |
                  Ci.NetworkTest.RATE_TEST_WITH_FACTOR_2_0);
}

function handleClick(state) {
  if (!working) {
    working = true;
  }
  var pageUrl = self.data.url("./NetworkTestPage.html");

  var pageMod = mod.PageMod({
    include: pageUrl,
    contentScriptFile: self.data.url("./resultsScript.js"),
    onAttach: startTest
  });

  tabs.open(pageUrl)
}
