let speciesReads = 0;
let callbackCalls = 0;
class Source extends Int32Array {}
const input = new Source([305419896, 305419897]);
const TypedArrayBase = Object.getPrototypeOf(Int8Array);
const output = input.filter((value, index) => {
  callbackCalls++;
  if (index === 0) {
    Object.defineProperty(TypedArrayBase, Symbol.species, {
      configurable: true,
      get() {
        speciesReads++;
        return Uint8Array;
      },
    });
  }
  return true;
});
print('callback_calls=' + callbackCalls);
print('species_reads=' + speciesReads);
print('output_type=' + output.constructor.name);
print('output_length=' + output.length);
print('output_first=' + output[0]);
print('output_second=' + output[1]);
if (typeof test_end === 'function') test_end();
