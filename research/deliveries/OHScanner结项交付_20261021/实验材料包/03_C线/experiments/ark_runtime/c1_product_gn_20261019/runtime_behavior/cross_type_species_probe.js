function assert(condition, message) { if (!condition) throw new Error(message); }
function sameArray(actual, expected) { assert(actual.length === expected.length, "length:" + actual.length); for (let i = 0; i < expected.length; i++) assert(actual[i] === expected[i], "value:" + i + ":" + actual[i]); }
print("start");
const events = [];
class Uint16Species extends Uint16Array { constructor(length) { events.push("constructor:" + length); super(length); } }
class CrossTypeSource extends Int8Array { static get [Symbol.species]() { events.push("species_getter"); return Uint16Species; } }
try { const source = new CrossTypeSource([1, -1, 3]); print("source:" + source.constructor.name); const result = source.filter(() => true); print("result:" + result.constructor.name + ":" + Array.from(result).join(",")); assert(result instanceof Uint16Species, "wrong species result"); sameArray(result, [1,65535,3]); print("events:" + events.join(",")); } catch (e) { print("caught:" + e + ":" + e.stack); }
test_end();