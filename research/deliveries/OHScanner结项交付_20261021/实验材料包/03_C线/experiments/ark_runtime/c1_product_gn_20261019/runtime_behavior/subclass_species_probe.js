const output = typeof print === "function" ? print : console.log;
class DefaultDerived extends Int8Array {}
class Uint16Species extends Uint16Array { constructor(length) { super(length); } }
class CustomDerived extends Int8Array { static get [Symbol.species]() { return Uint16Species; } }
output("default-species-getter=" + DefaultDerived[Symbol.species].name);
output("custom-species-getter=" + CustomDerived[Symbol.species].name);
for (const C of [DefaultDerived, CustomDerived]) {
 const source = new C([1,-1,3]);
 const result = source.filter(() => true);
 output(C.name + " source=" + source.constructor.name + " result=" + result.constructor.name + " values=" + Array.from(result).join(","));
}
if (typeof test_end === "function") test_end();