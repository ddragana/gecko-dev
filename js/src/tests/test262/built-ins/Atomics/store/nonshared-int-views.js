// |reftest| skip-if(!this.hasOwnProperty('Atomics')) -- Atomics is not enabled unconditionally
// Copyright (C) 2017 Mozilla Corporation.  All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

/*---
esid: sec-atomics.store
description: >
  Test Atomics.store on non-shared integer TypedArrays
includes: [testTypedArray.js]
features: [ArrayBuffer, Atomics, BigInt, TypedArray]
---*/

var buffer = new ArrayBuffer(16);
var views = intArrayConstructors.slice();

if (typeof BigInt !== "undefined") {
  views.push(BigInt64Array);
  views.push(BigUint64Array);
}

testWithTypedArrayConstructors(function(TA) {
  assert.throws(TypeError, (() => Atomics.store(new TA(buffer), 0, 0)));
}, views);

reportCompare(0, 0);
