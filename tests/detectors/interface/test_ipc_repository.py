import unittest

from src.ohscanner.detectors.interface.ipc_repository import RepositoryIndex, macro_catalog


HEADER = b"""
class Demo : public IRemoteStub<I> {
public: int OnRemoteRequest(int code, MessageParcel& data, MessageParcel& reply);
int Handle(MessageParcel& data, MessageParcel& reply);
};
"""
DISPATCH = b"""
int Demo::OnRemoteRequest(int code, MessageParcel& data, MessageParcel& reply) {
 switch(code) {case 7: return Handle(data, reply); default: return 0;}
}
int Demo::Handle(MessageParcel& data, MessageParcel& reply) {
 unsigned token = IPCSkeleton::GetCallingTokenID();
 return Helper(token);
}
"""
HELPER = b"""
bool Helper(unsigned token) {
 const char *permission = "demo.permission";
 return AccessTokenKit::VerifyAccessToken(token, permission) == 0;
}
"""


def index(sources=None):
    return RepositoryIndex(sources or {"stub.h": HEADER, "stub.cpp": DISPATCH, "helper.cpp": HELPER}, "synthetic/ipc", "d"*40)


class IpcRepositoryTests(unittest.TestCase):
    def test_switch_entry_and_cross_file_permission(self):
        idx = index()
        entries = idx.entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["transaction_values"], ["7"])
        row = idx.trace_permissions(entries[0])
        self.assertEqual(row["requirements"][0]["permission"]["value"], "demo.permission")
        self.assertEqual(row["requirements"][0]["subject"]["origin"], "caller_token_api")
        self.assertEqual(row["requirements"][0]["call_chain"], ["Demo::Handle", "Helper"])
        self.assertEqual(row["requirements"][0]["path_coverage"], "unknown")

    def test_fake_named_function_without_stub_base_not_entry(self):
        self.assertEqual(index({"stub.h": HEADER.replace(b"IRemoteStub<I>", b"Unrelated"), "stub.cpp": DISPATCH}).entries(), [])

    def test_map_must_be_used_in_dispatch(self):
        source = b"""int Demo::OnRemoteRequest(int code, MessageParcel& data, MessageParcel& reply) {
        std::map<int, Fn> routes = {{7, &Demo::Handle}};
        return 0; }"""
        self.assertEqual(index({"stub.h": HEADER, "stub.cpp": source}).entries(), [])

    def test_map_entry(self):
        source = b"""int Demo::OnRemoteRequest(int code, MessageParcel& data, MessageParcel& reply) {
        std::map<int, Fn> routes = {{7, &Demo::Handle}};
        auto it = routes.find(code);
        if (it != routes.end()) return (this->*it->second)(data, reply);
        return 0; }"""
        self.assertEqual(len(index({"stub.h": HEADER, "stub.cpp": source}).entries()), 1)

    def test_overload_is_not_guessed(self):
        idx = index({"stub.h": HEADER, "stub.cpp": DISPATCH, "helper.cpp": HELPER+b"bool Helper(int t, int x) {return true;}"})
        row = idx.trace_permissions(idx.entries()[0])
        self.assertEqual(row["requirements"], [])
        self.assertTrue(any(r["reason"] == "ambiguous_overload" for r in row["unresolved"]))

    def test_unknown_receiver_is_not_guessed(self):
        idx = index({"stub.h": HEADER, "stub.cpp": DISPATCH.replace(b"Helper(token)", b"object.Helper(token)"), "helper.cpp": HELPER})
        self.assertEqual(idx.trace_permissions(idx.entries()[0])["requirements"], [])

    def test_caller_token_assignment_invalidates_provenance(self):
        idx = index({"stub.h": HEADER, "stub.cpp": DISPATCH.replace(b"return Helper", b"token = 7; return Helper"), "helper.cpp": HELPER})
        requirement = idx.trace_permissions(idx.entries()[0])["requirements"][0]
        self.assertEqual(requirement["subject"]["origin"], "modified_unknown")

    def test_later_declaration_not_applied_to_earlier_call(self):
        source = DISPATCH.replace(b"unsigned token = IPCSkeleton::GetCallingTokenID();\n return Helper(token);", b"Helper(token); unsigned token = IPCSkeleton::GetCallingTokenID(); return 0;")
        idx = index({"stub.h": HEADER, "stub.cpp": source, "helper.cpp": HELPER})
        requirement = idx.trace_permissions(idx.entries()[0])["requirements"][0]
        self.assertNotEqual(requirement["subject"]["origin"], "caller_token_api")

    def test_spoofed_api_name_not_caller_identity(self):
        idx = index({"stub.h": HEADER, "stub.cpp": DISPATCH.replace(b"IPCSkeleton::GetCallingTokenID", b"Fake::GetCallingTokenID"), "helper.cpp": HELPER})
        requirement = idx.trace_permissions(idx.entries()[0])["requirements"][0]
        self.assertEqual(requirement["subject"]["origin"], "unresolved_expression")

    def test_depth_and_state_budget(self):
        idx = index()
        entry = idx.entries()[0]
        self.assertEqual(idx.trace_permissions(entry, max_depth=0)["requirements"], [])
        self.assertEqual(idx.trace_permissions(entry, max_states=1)["requirements"], [])

    def test_recursion_is_reported(self):
        idx = index({"stub.h": HEADER, "stub.cpp": DISPATCH, "helper.cpp": b"bool Helper(unsigned token) {return Helper(token);}"})
        self.assertTrue(any(r["reason"] == "depth_limit_or_recursion" for r in idx.trace_permissions(idx.entries()[0])["unresolved"]))

    def test_macro_common_variants(self):
        macros = macro_catalog({"macros.h": b"#define CHECK(x, r) do {if ((x) == nullptr) {return r;}} while(0)\n#define CHECK(x, r) do {if ((x) == nullptr) { Log(); return r;}} while(0)\n"})
        self.assertEqual(macros["CHECK"]["common_null_return_syntax"]["return_parameter"], "r")
        self.assertFalse(macros["CHECK"]["permission_guard"])
        self.assertEqual(macros["CHECK"]["full_effects"], "unknown")

    def test_conflicting_macro_variants_not_collapsed(self):
        macros = macro_catalog({"macros.h": b"#define CHECK(x, r) if ((x) == nullptr) {return r;}\n#define CHECK(x, r) DoNothing();\n"})
        self.assertIsNone(macros["CHECK"]["common_null_return_syntax"])

    def test_no_cross_repository_cache(self):
        a, b = index(), index({"stub.h": HEADER, "stub.cpp": DISPATCH})
        self.assertTrue(a.trace_permissions(a.entries()[0])["requirements"])
        self.assertEqual(b.trace_permissions(b.entries()[0])["requirements"], [])

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            RepositoryIndex({"../bad.cpp": b""}, "synthetic/demo", "d"*40)
        with self.assertRaises(ValueError):
            index().trace_permissions(index().entries()[0], max_depth=100)

    def test_callback_target_recorded_but_execution_not_claimed(self):
        source = DISPATCH.replace(b"return Helper(token);", b"std::bind(&Worker::Run, this, token); return 0;")
        helper = b"bool Worker::Run(unsigned token) { return Helper(token); }"+HELPER
        idx = index({"stub.h": HEADER, "stub.cpp": source, "helper.cpp": helper})
        result = idx.trace_permissions(idx.entries()[0])
        self.assertTrue(any(e["resolution"] == "bound_callback_syntax_only" for e in result["call_edges"]))
        self.assertTrue(any(e["reason"] == "callback_execution_and_identity_context_unknown" for e in result["unresolved"]))

    def test_virtual_override_is_only_possible(self):
        header = HEADER+b"class Service : public Demo { public: int Sensitive() override; };"
        source = DISPATCH.replace(b"return Helper(token);", b"return Sensitive();")
        idx = index({"stub.h": header, "stub.cpp": source, "helper.cpp": b"int Service::Sensitive() {return 0;}"})
        result = idx.trace_permissions(idx.entries()[0])
        self.assertTrue(any(e["resolution"] == "possible_virtual_override_not_definite" for e in result["call_edges"]))

    def test_negative_helper_denial_structure(self):
        source = DISPATCH.replace(b"return Helper(token);", b"if (!Helper(token)) return -1; return 0;")
        idx = index({"stub.h": HEADER, "stub.cpp": source, "helper.cpp": HELPER})
        relationships = idx.trace_permissions(idx.entries()[0])["guard_relationships"]
        self.assertTrue(relationships[0]["consequence_terminates_syntax"])

    def test_helper_denial_fallthrough_structure(self):
        source = DISPATCH.replace(b"return Helper(token);", b"if (!Helper(token)) { int ignored = 0; } return 0;")
        idx = index({"stub.h": HEADER, "stub.cpp": source, "helper.cpp": HELPER})
        relationships = idx.trace_permissions(idx.entries()[0])["guard_relationships"]
        self.assertFalse(relationships[0]["consequence_terminates_syntax"])

    def test_token_info_fetch_without_apl_guard_not_permission_constraint(self):
        helper = b"bool Helper(unsigned token, unsigned required) { HapTokenInfo info; AccessTokenKit::GetHapTokenInfo(token, info); return true; }"
        source = DISPATCH.replace(b"Helper(token)", b"Helper(token, 7)")
        idx = index({"stub.h": HEADER, "stub.cpp": source, "helper.cpp": helper})
        self.assertEqual(idx.trace_permissions(idx.entries()[0])["requirements"], [])

    def test_else_branch_role_is_not_positive_condition(self):
        source = DISPATCH.replace(b"return Helper(token);", b"if (flag) return 0; else return Helper(token);")
        idx = index({"stub.h": HEADER, "stub.cpp": source, "helper.cpp": HELPER})
        conditions = idx.trace_permissions(idx.entries()[0])["requirements"][0]["conditions"]
        self.assertEqual(conditions[0]["role"], "alternative")
        self.assertEqual(conditions[0]["feasibility"], "unknown")
