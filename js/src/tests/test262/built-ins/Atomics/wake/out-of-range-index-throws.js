// |reftest| skip-if(!this.hasOwnProperty('Atomics')||!this.hasOwnProperty('SharedArrayBuffer')) -- Atomics,SharedArrayBuffer is not enabled unconditionally
// Copyright (C) 2018 Amal Hussein. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

/*---
esid: sec-atomics.wake
description: >
  Throws a RangeError if value of index arg is out of range
  info: |
  Atomics.wake( typedArray, index, count )

  2.Let i be ? ValidateAtomicAccess(typedArray, index).
    ...
    2.Let accessIndex be ? ToIndex(requestIndex).
    ...
    5. If accessIndex ≥ length, throw a RangeError exception.
features: [Atomics, SharedArrayBuffer, TypedArray]
---*/

var int32Array = new Int32Array(new SharedArrayBuffer(4));
var poisoned = {
  valueOf: function() {
    throw new Test262Error("should not evaluate this code");
  }
};

assert.throws(RangeError, function() {
  Atomics.wake(int32Array, Infinity, poisoned);
});
assert.throws(RangeError, function() {
  Atomics.wake(int32Array, 2, poisoned);
});
assert.throws(RangeError, function() {
  Atomics.wake(int32Array, 200, poisoned);
});

reportCompare(0, 0);
