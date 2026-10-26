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

// A legal Number-content species changes element width and signedness.
const speciesEvents = [];
class Uint16Species extends Uint16Array {
    constructor(length) {
        speciesEvents.push("constructor:" + length);
        super(length);
    }
}
class CrossTypeSource extends Int8Array {
    static get [Symbol.species]() {
        speciesEvents.push("species_getter");
        return Uint16Species;
    }
}
const crossSource = new CrossTypeSource([1, -1, 3]);
const crossResult = crossSource.filter(() => true);
assert(crossResult instanceof Uint16Species, "custom Number species constructor");
sameArray(crossResult, [1, 65535, 3], "custom Number species values");
assert(speciesEvents.join(",") === "species_getter,constructor:3", "species side-effect order");
results.push("filter_cross_number_type");

// Number-to-BigInt content-type changes are rejected.
class BigIntSpeciesSource extends Int8Array {
    static get [Symbol.species]() {
        return BigInt64Array;
    }
}
let incompatibleThrewTypeError = false;
try {
    new BigIntSpeciesSource([1]).filter(() => true);
} catch (error) {
    incompatibleThrewTypeError = error instanceof TypeError;
}
assert(incompatibleThrewTypeError, "Number/BigInt species mismatch must throw TypeError");
results.push("number_bigint_content_type_rejected");

test_end();
