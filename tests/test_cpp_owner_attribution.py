import unittest

from src.ohscanner.facts import build_syntax_facts
from src.parser.ast import parse_source


TYPEDARRAY_OWNER = "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder"


class CppOwnerAttributionTests(unittest.TestCase):
    def test_qualified_filter_and_map_keep_owner_and_legacy_name(self):
        source = """
namespace panda::ecmascript::kungfu {
class BuiltinsTypedArrayStubBuilder {
public:
    void Filter(int value);
    void Map(int value);
};
void BuiltinsTypedArrayStubBuilder::Filter(int value) {}
void BuiltinsTypedArrayStubBuilder::Map(int value) {}
}
"""
        index = parse_source(source, "cpp")
        self.assertEqual(index.parse_status, "complete")
        methods = {item.name: item for item in index.functions}
        self.assertEqual(set(methods), {"Filter", "Map"})
        for name, item in methods.items():
            with self.subTest(method=name):
                self.assertEqual(item.owner, TYPEDARRAY_OWNER)
                self.assertEqual(item.qualified_name, f"{TYPEDARRAY_OWNER}::{name}")
                self.assertEqual(item.owner_resolution, "syntax_qualified")

        facts = build_syntax_facts({"typedarray.cpp": index.to_dict()})["typedarray.cpp"]
        for function in facts["functions"]:
            self.assertEqual(function["owner"], TYPEDARRAY_OWNER)
            self.assertEqual(function["owner_resolution"], "syntax_qualified")

    def test_unrelated_class_is_not_attributed_to_typedarray_owner(self):
        source = """
namespace panda::ecmascript::kungfu {
class UnrelatedBuilder {
public:
    void Filter();
    void Map();
};
void UnrelatedBuilder::Filter() {}
void UnrelatedBuilder::Map() {}
}
"""
        index = parse_source(source, "cpp")
        methods = {item.name: item for item in index.functions}
        self.assertEqual(set(methods), {"Filter", "Map"})
        self.assertTrue(all(item.owner == "panda::ecmascript::kungfu::UnrelatedBuilder"
                            for item in methods.values()))
        self.assertTrue(all(item.owner != TYPEDARRAY_OWNER for item in methods.values()))

    def test_lexical_class_owner_is_recorded_and_free_function_stays_unowned(self):
        source = """
namespace panda::ecmascript::kungfu {
class LocalBuilder {
public:
    void Filter() {}
};
void Map() {}
}
"""
        index = parse_source(source, "cpp")
        local = next(item for item in index.functions if item.name == "Filter")
        free = next(item for item in index.functions if item.name == "Map")
        self.assertEqual(local.owner, "panda::ecmascript::kungfu::LocalBuilder")
        self.assertEqual(local.owner_resolution, "lexical_class")
        self.assertIsNone(free.owner)
        self.assertEqual(free.owner_resolution, "unknown")


if __name__ == "__main__":
    unittest.main()
