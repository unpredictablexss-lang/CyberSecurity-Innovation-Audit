function check(condition, message) { if (!condition) throw new Error(message); }
let speciesReads = 0;
class SpeciesTrap extends Int8Array {
    static get [Symbol.species]() { speciesReads++; throw new Error("unexpected species read"); }
}
const value = new SpeciesTrap([1, 2, 3]);
value.copyWithin(1, 0, 1);
check(speciesReads === 0, "CopyWithin must not read @@species");
check(value.join(",") === "1,1,3", "CopyWithin result values");
print("copywithin_no_species_read:pass");
test_end();
