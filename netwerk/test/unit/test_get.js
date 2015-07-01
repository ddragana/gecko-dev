//
// GET
//

Cu.import("resource://testing-common/httpd.js");
Cu.import("resource://gre/modules/Services.jsm");


function run_test() {

  var channel = setupChannel();
  channel.requestMethod = "GET";

  channel.asyncOpen(new ChannelListener(checkRequest, channel), null);

  do_test_pending();
}

function setupChannel(path) {
  var ios = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
    return chan = ios.newChannel2(
	"https://www.ducksong.com/resources/mcmanus-headshot.jpg",
                               "",
                               null,
                               null,      // aLoadingNode
                               Services.scriptSecurityManager.getSystemPrincipal(),
                               null,      // aTriggeringPrincipal
                               Ci.nsILoadInfo.SEC_NORMAL,
                               Ci.nsIContentPolicy.TYPE_OTHER)
                   .QueryInterface(Ci.nsIHttpChannel);
}


function checkRequest(request, data, context) {
    do_test_finished();
}
