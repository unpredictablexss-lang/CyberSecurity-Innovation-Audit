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

// Callback side effects occur before species construction; constructor errors propagate.
const sentinel = { marker: "species-constructor-error" };
let callbackCount = 0;
const throwEvents = [];
class ThrowingSpeciesSource extends Int8Array {
    static get [Symbol.species]() {
        throwEvents.push("species_getter");
        return class {
            constructor() {
                throwEvents.push("species_constructor");
                throw sentinel;
            }
        };
    }
}
let propagatedSameSentinel = false;
try {
    new ThrowingSpeciesSource([4, 5, 6]).filter(() => {
        callbackCount++;
        return true;
    });
} catch (error) {
    propagatedSameSentinel = error === sentinel;
}
assert(propagatedSameSentinel, "species constructor error identity");
assert(callbackCount === 3, "Filter callbacks before species construction");
assert(throwEvents.join(",") === "species_getter,species_constructor", "throwing species order");
results.push("species_error_propagation_and_prior_callback_effects");

// Invalidate the species protector from inside the callback, after Filter's
// entry checks but before the result TypedArray is created.
const mutationEvents = [];
let mutationCallbacks = 0;
const mutationSource = new Int32Array([0x1234, 0x5678]);
let mutationResult;
try {
    mutationResult = mutationSource.filter(() => {
        mutationCallbacks++;
        mutationEvents.push("callback:" + mutationCallbacks);
        if (mutationCallbacks === 1) {
            Object.defineProperty(Int32Array, Symbol.species, {
                configurable: true,
                value: Uint8Array,
            });
            mutationEvents.push("species_mutated");
        }
        return true;
    });
} finally {
    delete Int32Array[Symbol.species];
}
assert(mutationResult instanceof Uint8Array, "species mutation during Filter callback");
sameArray(mutationResult, [0x34, 0x78], "mutated species Filter values");
assert(mutationCallbacks === 2, "mutation callback count");
assert(mutationEvents.join(",") === "callback:1,species_mutated,callback:2",
    "species mutation precedes result construction after callbacks");
results.push("callback_changes_own_species_before_result_creation");

// The shared %TypedArray% constructor species mutation is the source-level
// protector invalidation path. Record engine behavior without assuming that
// this reference engine exercises the same optimization/deoptimization path.
const sharedTypedArrayConstructor = Object.getPrototypeOf(Int32Array);
const sharedSpeciesDescriptor = Object.getOwnPropertyDescriptor(sharedTypedArrayConstructor, Symbol.species);
let sharedMutationCallbacks = 0;
let sharedMutationResult;
try {
    sharedMutationResult = new Int32Array([0x1234]).filter(() => {
        sharedMutationCallbacks++;
        if (sharedMutationCallbacks === 1) {
            Object.defineProperty(sharedTypedArrayConstructor, Symbol.species, {
                configurable: true,
                value: Uint8Array,
            });
        }
        return true;
    });
} finally {
    Object.defineProperty(sharedTypedArrayConstructor, Symbol.species, sharedSpeciesDescriptor);
}
const sharedMutationOutcome = sharedMutationResult.constructor.name;
assert(sharedMutationOutcome === "Uint8Array", "shared species mutation result constructor");
assert(sharedMutationCallbacks === 1, "shared species mutation callback count");
sameArray(sharedMutationResult, [0x34], "shared species mutation values");
results.push("shared_typedarray_species_mutation_observed:" + sharedMutationOutcome);

// In-place operations and TypedArray.prototype.with must not consult @@species.
let forbiddenSpeciesReads = 0;
class NoSpeciesAccess extends Int8Array {
    static get [Symbol.species]() {
        forbiddenSpeciesReads++;
        throw new Error("unexpected species lookup");
    }
}
const inPlace = new NoSpeciesAccess([1, 2, 3]);
inPlace.set([9], 0);
inPlace.copyWithin(1, 0, 1);
const withResult = inPlace.with(0, 7);
assert(forbiddenSpeciesReads === 0, "Set/CopyWithin/With must not read @@species");
assert(withResult.constructor === Int8Array, "With creates same intrinsic typed-array type");
sameArray(withResult, [7, 9, 3], "With values");
results.push("set_copywithin_with_no_species_lookup");

const engine = typeof process === "undefined" ? "non-node" : process.version;
const emit = typeof print === "function" ? print : console.log;
emit(JSON.stringify({ engine, status: "passed", controls: results,
    source_specific_mutation_observation: sharedMutationOutcome }));
if (typeof test_end === "function") { test_end(); }