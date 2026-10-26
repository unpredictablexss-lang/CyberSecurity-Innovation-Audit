function check(condition, message) { if (!condition) throw new Error(message); }
let bigIntThrew = false;
const numberSource = new Int8Array([1]);
numberSource.constructor = { [Symbol.species]: BigInt64Array };
try { numberSource.filter(() => true); } catch (error) { bigIntThrew = error instanceof TypeError; }
check(bigIntThrew, "Number/BigInt content-type mismatch must throw");
print("number_bigint_mismatch:pass");
const sentinel = { marker: "species-constructor-error" };
let callbackCount = 0;
let eventOrder = [];
const throwingSource = new Int8Array([4, 5, 6]);
throwingSource.constructor = { [Symbol.species]: class { constructor(length) { eventOrder.push("species:" + length); throw sentinel; } } };
let sameSentinel = false;
try { throwingSource.filter(() => { callbackCount++; eventOrder.push("callback:" + callbackCount); return true; }); } catch (error) { sameSentinel = error === sentinel; }
check(sameSentinel, "species constructor exception identity");
check(callbackCount === 3, "all callbacks precede species construction");
check(eventOrder.join(",") === "callback:1,callback:2,callback:3,species:3", "callback/species order");
print("species_error_and_callback_order:pass");
let mutationCalls = 0;
const mutationSource = new Int32Array([0x1234]);
const mutationResult = mutationSource.filter(() => { mutationCalls++; if (mutationCalls === 1) mutationSource.constructor = { [Symbol.species]: Uint8Array }; return true; });
check(mutationResult.constructor === Uint8Array, "callback's constructor mutation observed");
check(mutationResult[0] === 0x34, "callback mutation result conversion");
print("callback_constructor_mutation:pass");
let forbiddenSpeciesReads = 0;
class NoSpeciesAccess extends Int8Array { static get [Symbol.species]() { forbiddenSpeciesReads++; throw new Error("unexpected @@species read"); } }
const inPlace = new NoSpeciesAccess([1, 2, 3]);
inPlace.set([9], 0);
inPlace.copyWithin(1, 0, 1);
const withResult = inPlace.with(0, 7);
check(forbiddenSpeciesReads === 0, "Set/CopyWithin/With must not read @@species");
check(withResult.constructor === Int8Array, "With creates intrinsic same-type result");
check(withResult.join(",") === "7,9,3", "With values");
print("set_copywithin_with_species_safety:pass");
test_end();