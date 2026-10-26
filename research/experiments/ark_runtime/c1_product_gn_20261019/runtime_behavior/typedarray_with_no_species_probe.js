function check(condition, message) { if (!condition) throw new Error(message); }
let speciesReads = 0;
class SpeciesTrap extends Int8Array {
    static get [Symbol.species]() { speciesReads++; throw new Error("unexpected species read"); }
}
const value = new SpeciesTrap([1, 2, 3]);
const result = value.with(0, 7);
check(speciesReads === 0, "With must not read @@species");
check(result.constructor === Int8Array, "With creates intrinsic same-type result");
check(result.join(",") === "7,2,3", "With result values");
print("with_no_species_read_intrinsic_result:pass");
test_end();
