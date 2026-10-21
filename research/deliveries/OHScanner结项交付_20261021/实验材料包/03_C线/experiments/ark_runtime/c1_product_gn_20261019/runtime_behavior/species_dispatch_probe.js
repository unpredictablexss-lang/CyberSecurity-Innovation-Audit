function describe(name, source) { const events = []; try { const result = source.filter((x) => { events.push("callback:" + x); return true; }); print(name + " result=" + result.constructor.name + " values=" + Array.from(result).join(",") + " events=" + events.join("|")); } catch (e) { print(name + " threw=" + e + " events=" + events.join("|")); } }
class Uint16Species extends Uint16Array { constructor(length) { print("species_ctor:" + length); super(length); } }
class CrossTypeSource extends Int8Array { static get [Symbol.species]() { print("species_getter"); return Uint16Species; } }
describe("subclass_static_species", new CrossTypeSource([1,-1,3]));
const own = new Int8Array([1,-1,3]); own.constructor = { [Symbol.species]: Uint16Species }; describe("instance_constructor_species", own);
const ownReturnOther = new Int8Array([1,-1,3]); ownReturnOther.constructor = { [Symbol.species]: Uint16Array }; describe("instance_species_builtin", ownReturnOther);
test_end();