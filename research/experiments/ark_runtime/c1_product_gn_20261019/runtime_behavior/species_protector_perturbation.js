let speciesReads = 0;
class Derived extends Int8Array {}
const source = new Derived([5, 6, 7]);
function kind(value) { return value.constructor.name; }
const before = source.filter((value) => value > 5);
print('before=' + kind(before));
const TypedArrayBase = Object.getPrototypeOf(Int8Array);
Object.defineProperty(TypedArrayBase, Symbol.species, {
  configurable: true,
  get() {
    speciesReads++;
    return Uint16Array;
  },
});
const after = source.filter((value) => value > 5);
print('species_reads=' + speciesReads);
print('after=' + kind(after));
print('after_value=' + after[0]);
if (typeof test_end === 'function') test_end();
