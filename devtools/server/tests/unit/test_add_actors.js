/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

// Get the object, from the server side, for a given actor ID
function getActorInstance(connID, actorID) {
  return DebuggerServer._connections[connID].getActor(actorID);
}

/**
 * The purpose of these tests is to verify that it's possible to add actors
 * both before and after the DebuggerServer has been initialized, so addons
 * that add actors don't have to poll the object for its initialization state
 * in order to add actors after initialization but rather can add actors anytime
 * regardless of the object's state.
 */
add_task(async function() {
  DebuggerServer.addActors("resource://test/pre_init_global_actors.js");
  DebuggerServer.addActors("resource://test/pre_init_tab_actors.js");

  const client = await startTestDebuggerServer("example tab");

  DebuggerServer.addActors("resource://test/post_init_global_actors.js");
  DebuggerServer.addActors("resource://test/post_init_tab_actors.js");

  let actors = await client.listTabs();
  Assert.equal(actors.tabs.length, 1);

  let reply = await client.request({
    to: actors.preInitGlobalActor,
    type: "ping",
  });
  Assert.equal(reply.message, "pong");

  reply = await client.request({
    to: actors.tabs[0].preInitTabActor,
    type: "ping",
  });
  Assert.equal(reply.message, "pong");

  reply = await client.request({
    to: actors.postInitGlobalActor,
    type: "ping",
  });
  Assert.equal(reply.message, "pong");

  reply = await client.request({
    to: actors.tabs[0].postInitTabActor,
    type: "ping",
  });
  Assert.equal(reply.message, "pong");

  // Consider that there is only one connection, and the first one is ours
  const connID = Object.keys(DebuggerServer._connections)[0];
  const postInitGlobalActor = getActorInstance(connID, actors.postInitGlobalActor);
  const preInitGlobalActor = getActorInstance(connID, actors.preInitGlobalActor);
  actors = await client.listTabs();
  Assert.equal(postInitGlobalActor,
    getActorInstance(connID, actors.postInitGlobalActor));
  Assert.equal(preInitGlobalActor,
    getActorInstance(connID, actors.preInitGlobalActor));

  await client.close();
});
