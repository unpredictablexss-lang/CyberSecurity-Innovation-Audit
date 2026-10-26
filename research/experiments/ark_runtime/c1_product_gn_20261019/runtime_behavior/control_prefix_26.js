/*
 * Behavior controls for the Ark Runtime species investigation.
 * Portable across Node and the Ark JS host test runner; no native bindings.
 * The Node result is a reference-engine check, not product-runtime evidence.
 */
function assert(condition, message) {
    if (!condition) {
        throw new Error("assertion failed: " + message);
    }
}

function sameArray(actual, expected, message) {
    assert(actual.length === expected.length, message + " length");
    for (let i = 0; i < expected.length; i++) {
        assert(actual[i] === expected[i], message + "[" + i + "]");
    }
}

const results = [];

// Same-typed default species control.
const defaultSource = new Int8Array([3, -1, 7]);
const defaultResult = defaultSource.filter(() => true);
assert(defaultResult.constructor === Int8Array, "default Filter constructor");
sameArray(defaultResult, [3, -1, 7], "default Filter values");
results.push("default_filter_same_type");

test_end();
