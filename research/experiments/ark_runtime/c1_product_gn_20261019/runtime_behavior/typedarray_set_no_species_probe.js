function check(condition, message) { if (!condition) throw new Error(message); }
let speciesReads = 0;
class SpeciesTrap extends Int8Array {
    static get [Symbol.species]() { speciesReads++; throw new Error("unexpected species read"); }
}
const value = new SpeciesTrap([1, 2, 3]);
value.set([9], 1);
check(speciesReads === 0, "Set must not read @@species");
check(value.join(",") === "1,9,3", "Set result values");
print("set_no_species_read:pass");
test_end();
