self.port.on("reachability", function(result) {

  var ports = JSON.parse(result[0]);
  var tcps = JSON.parse(result[1]);
  var udps = JSON.parse(result[2]);

  var test = document.getElementById("reachability");
  test.innerHTML = "Reachability test finished";
  var udpDesc = document.createElement("p");
  udpDesc.innerHTML = "UDP resultes:";
  var tcpDesc = document.createElement("p");
  tcpDesc.innerHTML = "TCP resultes:";

  var udpList = document.createElement("ul");
  var tcpList = document.createElement("ul");

  for (var i = 0; i < ports.length; i++) {
    var el = document.createElement("li");
    el.innerHTML = "Port " + ports[i] + ((udps[i]) ? " is " : " is not ") +
                   "reachable using UDP protocol";
    udpList.appendChild(el);

    var el = document.createElement("li");
    el.innerHTML = "Port " + ports[i] + ((tcps[i]) ? " is " : " is not ") +
                   "reachable using TCP protocol";
    tcpList.appendChild(el);
  }

  var testResults = document.getElementById("reachabilityResults");
  testResults.appendChild(udpDesc);
  testResults.appendChild(udpList);
  testResults.appendChild(tcpDesc);
  testResults.appendChild(tcpList);

});

self.port.on("rateTestFinished", function(result) {

  var tcpS = JSON.parse(result[0]);
  var udpS = JSON.parse(result[1]);
  var tcpC = JSON.parse(result[2]);
  var udpC = JSON.parse(result[3]);

  var tcpSstr = "";
  var udpSstr = "";
  var tcpCstr = "";
  var udpCstr = "";

  for (var i = 0; i < tcpS.length; i++) {
    tcpSstr += tcpS[i];
    udpSstr += udpS[i];
    tcpCstr += tcpC[i];
    udpCstr += udpC[i];

    if (i != tcpS.length - 1) {
      tcpSstr += ", ";
      udpSstr += ", ";
      tcpCstr += ", ";
      udpCstr += ", ";
    }
  }

  var test = document.getElementById("rate");
  test.innerHTML = "Rate test finished";

  var desc1 = document.createElement("p");
  desc1.innerHTML = "Sending from the server to the client: ";

  var udpSDesc = document.createElement("p");
  udpSDesc.innerHTML = "UDP rate: " + udpSstr;
  var tcpSDesc = document.createElement("p");
  tcpSDesc.innerHTML = "TCP rate: " + tcpSstr;

  var desc2 = document.createElement("p");
  desc2.innerHTML = "Sending from the client to the server: ";

  var udpCDesc = document.createElement("p");
  udpCDesc.innerHTML = "UDP rate: " + udpCstr;
  var tcpCDesc = document.createElement("p");
  tcpCDesc.innerHTML = "TCP rate: " + tcpCstr;

  var testResults = document.getElementById("rateResults");
  testResults.appendChild(desc1);
  testResults.appendChild(udpSDesc);
  testResults.appendChild(tcpSDesc);
  testResults.appendChild(desc2);
  testResults.appendChild(udpCDesc);
  testResults.appendChild(tcpCDesc);
});
