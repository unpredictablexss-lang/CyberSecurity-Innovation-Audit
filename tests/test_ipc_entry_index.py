"""Direct unit tests for the source-derived IPC entry/dispatch index.

Unlike ``test_ipc_detector.py`` these do not build a detector or a git tool.
``EntryIndex`` reads exactly four attributes off each unit -- ``path``,
``language``, ``text`` and ``parse_status`` -- so a tiny local stand-in is
enough; C++ sources are fed inline (or read from the perf corpus in the one
corpus-anchored regression).

Every assertion is on concrete fields of the returned records. Where the
module's observable behaviour is deliberately conservative (a dispatcher found
by signature without a stub base, a container delegation that is recorded but
not rooted) the test name states the intent rather than implying a verdict.
"""
import os
from pathlib import Path
import unittest

from src.ohscanner.detectors.interface.entry_index import (
    EntryIndex,
    DECLARATION_SHAPE,
    SOURCE_DISPATCH,
    SOURCE_DISPATCH_CASE_CALL,
    UNRESOLVED_HANDLER,
)

CORPUS = Path("/home/audit/openharmony-audit/perf-corpus/communication_ipc")


class _Unit:
    """Minimal ``SourceUnit`` stand-in: only the four attrs the index reads."""

    def __init__(self, path, text, language="cpp", parse_status="complete"):
        self.path = path
        self.text = text
        self.language = language
        self.parse_status = parse_status


def unit(path, text):
    return _Unit(path, text)


def build(*units):
    return EntryIndex(list(units))


def kinds(entries):
    return sorted(e.kind for e in entries)


# --------------------------------------------------------------------- sources

SWITCH_ENUM = r"""
enum class Code : uint32_t { A = 10, B = 11 };
class IRemoteStub {};
class Foo : public IRemoteStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int Handler(MessageParcel &data, MessageParcel &reply);
};
int Foo::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    switch (code) {
        case Code::A:
            return Handler(data, reply);
        default:
            return -1;
    }
}
int Foo::Handler(MessageParcel &data, MessageParcel &reply) { return 0; }
"""

MEMBER_PTR_CTOR = r"""
#define CAST_UINT(x) (static_cast<uint32_t>(x))
enum class TableCode : uint32_t { A = 1, B = 2 };
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    Cls() { table_ = { {CAST_UINT(TableCode::A), &Cls::HandlerA},
                       {CAST_UINT(TableCode::B), &Cls::HandlerB} }; }
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        auto iter = table_.find(code);
        if (iter == table_.end()) return -1;
        return (this->*(iter->second))(this, data, reply, option);
    }
    std::map<uint32_t, Fn> table_;
    int HandlerA(MessageParcel &data, MessageParcel &reply) { return 0; }
    int HandlerB(MessageParcel &data, MessageParcel &reply) { return 0; }
};
"""

COPIED_ALIAS = r"""
#define CAST_UINT(x) (static_cast<uint32_t>(x))
enum class Code : uint32_t { A = 1 };
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    Cls() { table_ = { {CAST_UINT(Code::A), &Cls::HandlerA} }; }
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        auto iter = table_.find(code);
        if (iter == table_.end()) return -1;
        Fn fn = iter->second;
        if (fn != nullptr) { return (this->*fn)(data, reply); }
        return -1;
    }
    std::map<uint32_t, Fn> table_;
    int HandlerA(MessageParcel &data, MessageParcel &reply) { return 0; }
};
"""

CALLABLE_TABLE = r"""
#define CODE 0x10
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    Cls() { recFuncs_[CODE] = std::bind(&Cls::Handler, this, std::placeholders::_1); }
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        auto it = recFuncs_.find(code);
        if (it == recFuncs_.end()) return -1;
        auto fn = it->second;
        fn(data, reply);
        return 0;
    }
    std::map<uint32_t, std::function<int(MessageParcel&, MessageParcel&)>> recFuncs_;
    int Handler(MessageParcel &data, MessageParcel &reply) { return 0; }
};
"""

CASE_BODY_CALL = r"""
enum class Code : uint32_t { A = 1 };
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        switch (code) {
            case Code::A: { Err e; OnDone(e); break; }
            default: return -1;
        }
        return 0;
    }
    void OnDone(Err e) {}
};
"""

CROSS_STUB = r"""
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int Handler(MessageParcel &data, MessageParcel &reply);
};
int Cls::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
    switch (code) { case 5: return Handler(data, reply); }
    return -1;
}
"""

CROSS_SERVICE = r"""
int Cls::Handler(MessageParcel &data, MessageParcel &reply) { return 0; }
"""

CONDITIONAL = r"""
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        switch (code) {
#ifdef FOO
            case 1: return HandlerA(data, reply);
#endif
#ifndef BAR
            case 2: return HandlerB(data, reply);
#endif
            default: return -1;
        }
    }
    int HandlerA(MessageParcel &data, MessageParcel &reply) { return 0; }
    int HandlerB(MessageParcel &data, MessageParcel &reply) { return 0; }
};
"""

MAP_NEVER_DISPATCHED = r"""
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    Cls() { table_ = { {1, &Cls::HandlerA} }; }
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        auto iter = table_.find(code);
        if (iter == table_.end()) return -1;
        return 0;
    }
    std::map<uint32_t, Fn> table_;
    int HandlerA(MessageParcel &data, MessageParcel &reply) { return 0; }
};
"""

SIGNATURE_ONLY = r"""
class Bare {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; }
};
class NotDispatch {
public:
    int OnRemoteRequest(std::string name, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; }
};
"""

OVERLOADED = r"""
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    Cls() { table_ = { {1, &Cls::Handler} }; }
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        auto iter = table_.find(code);
        if (iter == table_.end()) return -1;
        return (this->*(iter->second))(this, data, reply, option);
    }
    std::map<uint32_t, Fn> table_;
    int Handler(MessageParcel &data, MessageParcel &reply) { return 0; }
    int Handler(int x) { return x; }
};
"""

UNKNOWN_MACRO = r"""
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        switch (code) {
            case SOME_UNKNOWN_MACRO:
                return Handler(data, reply);
            default: return -1;
        }
    }
    int Handler(MessageParcel &data, MessageParcel &reply) { return 0; }
};
"""

DELEGATE_STMT = r"""
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        switch (code) {
            case 1: { IPCObjectStub::OnRemoteRequest(code, data, reply, option); break; }
            default: return -1;
        }
        return 0;
    }
};
"""

DELEGATE_RETURN = r"""
class IRemoteStub {};
class Cls : public IRemoteStub {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
        switch (code) {
            case 1: return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            default: return -1;
        }
    }
};
"""

RECEIVER_ALIAS = r"""
#define SVC DelayedSingleton<Demand>::GetInstance()
"""


class EntryIndexTests(unittest.TestCase):
    # -- 1. switch/return dispatcher with an enum transaction -----------------
    def test_switch_case_return_binds_handler_and_resolves_enum(self):
        index = build(unit("foo.cpp", SWITCH_ENUM))
        entries = [e for e in index.entries if e.kind == "switch_case_return"]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertTrue(entry.dispatcher.endswith("Foo::OnRemoteRequest"))
        self.assertTrue(entry.handler.endswith("Foo::Handler"))
        self.assertEqual(entry.evidence, SOURCE_DISPATCH)
        self.assertTrue(entry.handler_bound)
        self.assertEqual(entry.transaction_raw, "Code::A")
        self.assertEqual(entry.transaction_value, "10")
        self.assertEqual(entry.transaction_resolution, "enum")
        self.assertEqual(entry.transaction_reason, "")
        # and the binding is admitted as a root
        self.assertIn(("Foo", "Handler"), [(o, n) for o, n, _a in index.root_bindings()])

    # -- 2. constructor-initialised member-pointer table ----------------------
    def test_constructor_member_pointer_table_binds_handlers(self):
        index = build(unit("cls.cpp", MEMBER_PTR_CTOR))
        entries = sorted((e for e in index.entries if e.kind == "map_member_ptr"),
                         key=lambda e: e.transaction_value)
        self.assertEqual(len(entries), 2)
        handlers = sorted(e.handler for e in entries)
        self.assertEqual(handlers, ["HandlerA", "HandlerB"])
        for entry in entries:
            self.assertEqual(entry.evidence, SOURCE_DISPATCH)
            self.assertTrue(entry.handler_bound)
            self.assertEqual(entry.transaction_resolution, "enum")
        self.assertEqual([e.transaction_value for e in entries], ["1", "2"])

    # -- 3. copied alias form from communication_ipc --------------------------
    def test_copied_alias_member_pointer_form_is_bound(self):
        index = build(unit("cls.cpp", COPIED_ALIAS))
        entries = list(index.entries)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.kind, "map_member_ptr")
        self.assertEqual(entry.evidence, SOURCE_DISPATCH)
        self.assertTrue(entry.handler_bound)
        self.assertTrue(entry.handler.endswith("HandlerA"))

    # -- 4. callable (std::bind) table ----------------------------------------
    def test_map_callable_bind_form(self):
        index = build(unit("cls.cpp", CALLABLE_TABLE))
        entries = list(index.entries)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.kind, "map_callable")
        self.assertEqual(entry.evidence, SOURCE_DISPATCH)
        self.assertTrue(entry.handler_bound)
        self.assertTrue(entry.handler.endswith("Handler"))
        self.assertEqual(entry.transaction_raw, "CODE")
        self.assertEqual(entry.transaction_resolution, "dynamic")
        self.assertEqual(entry.transaction_reason, "not_a_constant")

    # -- 5. same-class handler call inside a case body ------------------------
    def test_switch_case_call_same_class_business_handler(self):
        index = build(unit("cls.cpp", CASE_BODY_CALL))
        entries = list(index.entries)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.kind, "switch_case_call")
        self.assertEqual(entry.evidence, SOURCE_DISPATCH_CASE_CALL)
        self.assertTrue(entry.handler_bound)
        self.assertTrue(entry.handler.endswith("OnDone"))
        self.assertEqual(entry.transaction_resolution, "enum")
        self.assertEqual(entry.transaction_value, "1")

    # -- 6. cross-file handler definition -------------------------------------
    def test_cross_file_handler_binding(self):
        units = sorted((unit("a_stub.cpp", CROSS_STUB),
                        unit("b_service.cpp", CROSS_SERVICE)),
                       key=lambda u: u.path)
        self.assertEqual([u.path for u in units], ["a_stub.cpp", "b_service.cpp"])
        index = build(*units)
        entries = list(index.entries)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertTrue(entry.dispatcher.endswith("Cls::OnRemoteRequest"))
        self.assertTrue(entry.handler.endswith("Cls::Handler"))
        self.assertTrue(entry.handler_bound)
        self.assertEqual(entry.evidence, SOURCE_DISPATCH)

    # -- 7. preprocessor conditionals (ifdef vs ifndef) -----------------------
    def test_conditional_records_directive_word(self):
        index = build(unit("cls.cpp", CONDITIONAL))
        by_code = {e.transaction_value: e for e in index.entries}
        self.assertEqual(set(by_code), {"1", "2"})
        ifdef_entry, ifndef_entry = by_code["1"], by_code["2"]
        self.assertEqual(ifdef_entry.conditional, "ifdef FOO")
        self.assertEqual(ifndef_entry.conditional, "ifndef BAR")
        # the directive word is read back, not assumed from the node type
        self.assertNotEqual(ifndef_entry.conditional, "ifdef BAR")
        self.assertEqual(ifndef_entry.conditional.split()[0], "ifndef")

    # -- 8. negative: map defined but never dispatched ------------------------
    def test_map_defined_but_never_dispatched_is_unresolved(self):
        index = build(unit("cls.cpp", MAP_NEVER_DISPATCHED))
        entries = list(index.entries)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.evidence, UNRESOLVED_HANDLER)
        self.assertEqual(entry.transaction_reason, "map_found_but_never_dispatched")
        self.assertEqual(entry.kind, "map_member_ptr")
        self.assertFalse(entry.handler_bound)
        self.assertEqual(entry.handler, "")
        self.assertEqual(entry.transaction_resolution, "unresolved")
        self.assertEqual([e for e in index.entries if e.handler_bound], [])

    # -- 9. negative: signature discovery has no stub requirement -------------
    def test_dispatcher_discovered_by_signature_even_without_stub_base(self):
        """Dispatchers are found by signature, not by base class.

        A class carrying an ``OnRemoteRequest(uint32_t, MessageParcel&,
        MessageParcel&, MessageOption&)`` method is reported even when it does
        not derive from ``IRemoteStub``/``IPCObjectStub``; it is simply not
        marked as a stub container (``container_ok`` is False).
        """
        index = build(unit("cls.cpp", SIGNATURE_ONLY))
        bare = [d for d in index.dispatchers if d.owner == "Bare"]
        self.assertEqual(len(bare), 1)
        self.assertEqual(bare[0].name, "OnRemoteRequest")
        self.assertFalse(bare[0].container_ok)
        self.assertFalse(bare[0].owner_is_stub)

    def test_method_with_non_code_first_param_is_not_a_dispatcher(self):
        index = build(unit("cls.cpp", SIGNATURE_ONLY))
        self.assertEqual([d for d in index.dispatchers if d.owner == "NotDispatch"], [])
        # only the signature-matching class is reported
        self.assertEqual(sorted(d.owner for d in index.dispatchers), ["Bare"])

    # -- 10. negative: overloaded handler is ambiguous ------------------------
    def test_overloaded_handler_is_not_bound(self):
        index = build(unit("cls.cpp", OVERLOADED))
        entries = list(index.entries)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertFalse(entry.handler_bound)
        self.assertTrue(entry.ambiguity)
        self.assertEqual(entry.ambiguity[0], "overload")
        self.assertEqual(list(index.root_bindings()), [])

    # -- 11. negative: unknown macro transaction is kept ----------------------
    def test_unknown_macro_transaction_still_emitted(self):
        index = build(unit("cls.cpp", UNKNOWN_MACRO))
        entries = list(index.entries)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.transaction_raw, "SOME_UNKNOWN_MACRO")
        self.assertIn(entry.transaction_resolution, ("dynamic", "unresolved"))
        self.assertTrue(entry.transaction_reason)
        self.assertEqual(entry.transaction_value, "unknown")
        # the binding is still resolved even though the code is not
        self.assertTrue(entry.handler_bound)
        self.assertEqual(entry.evidence, SOURCE_DISPATCH)

    # -- 12. negative: container delegation is recorded, never rooted ---------
    def test_delegation_to_container_is_not_rooted(self):
        cases = (
            ("statement", DELEGATE_STMT, "delegation", DECLARATION_SHAPE),
            ("return", DELEGATE_RETURN, "switch_case_return", SOURCE_DISPATCH),
        )
        for form, src, expected_kind, expected_evidence in cases:
            with self.subTest(form=form):
                index = build(unit("cls.cpp", src))
                entries = list(index.entries)
                self.assertEqual(len(entries), 1)
                entry = entries[0]
                self.assertEqual(entry.kind, expected_kind)
                self.assertEqual(entry.evidence, expected_evidence)
                self.assertFalse(entry.handler_bound)
                self.assertTrue(entry.handler.endswith("IPCObjectStub::OnRemoteRequest"))
                self.assertEqual(entry.ambiguity, ("delegation_to_container",))
                self.assertEqual(list(index.root_bindings()), [])

    # -- 13. resolve_receiver -------------------------------------------------
    def test_resolve_receiver_unknown_and_spoofed_return_none(self):
        index = build(unit("r.cpp", RECEIVER_ALIAS))
        self.assertIsNone(index.resolve_receiver("mystery->Method"))
        self.assertIsNone(index.resolve_receiver("IPCSkeleton::GetCallingTokenID()->Method"))
        self.assertIsNone(index.resolve_receiver("Fake::GetCallingTokenID()->GetTokenType"))
        # an inline singleton expression is source-backed without any macro
        self.assertEqual(
            index.resolve_receiver("DelayedSingleton<Demand>::GetInstance()->Method"),
            "Demand::Method")

    def test_object_macro_singleton_alias_resolves(self):
        # Regression for `_ALIAS_PATTERNS`: they used to anchor on `^::?`, which is
        # a *mandatory* colon, so an ordinary `#define SVC DelayedSingleton<T>::GetInstance()`
        # was never registered and `SVC->Method` stayed unresolved.

        index = build(unit("r.cpp", RECEIVER_ALIAS))
        self.assertIn("SVC", index.aliases)
        self.assertEqual(index.resolve_receiver("SVC->Method"), "Demand::Method")

    # -- 14. counts -----------------------------------------------------------
    def test_counts_keys_and_totals(self):
        index = build(unit("foo.cpp", SWITCH_ENUM), unit("cls.cpp", MEMBER_PTR_CTOR))
        counts = index.counts()
        expected_keys = {
            "classes", "stub_classes", "dispatchers", "dispatchers_by_signature",
            "dispatchers_with_guard", "entries", "entries_by_evidence",
            "entries_by_kind", "bound_handlers", "root_bindings", "aliases",
            "unresolved_transactions", "limitations",
        }
        self.assertEqual(set(counts), expected_keys)
        self.assertEqual(counts["entries"], len(index.entries))
        self.assertEqual(sum(counts["entries_by_evidence"].values()), counts["entries"])
        self.assertEqual(sum(counts["entries_by_kind"].values()), counts["entries"])
        self.assertEqual(counts["entries_by_kind"], {"map_member_ptr": 2, "switch_case_return": 1})
        self.assertEqual(counts["bound_handlers"], 3)

    # -- 15. determinism ------------------------------------------------------
    def test_repeated_index_build_is_identical(self):
        make_units = lambda: (unit("foo.cpp", SWITCH_ENUM),
                              unit("cls.cpp", MEMBER_PTR_CTOR))
        first = build(*make_units())
        second = build(*make_units())
        self.assertEqual(first.entries, second.entries)
        self.assertEqual(first.dispatchers, second.dispatchers)

    # -- 16. corpus-anchored regression ---------------------------------------
    @unittest.skipUnless(os.path.isdir(CORPUS), "perf-corpus/communication_ipc not present")
    def test_corpus_ipc_object_stub_send_request_dispatch(self):
        header = CORPUS / "interfaces/innerkits/ipc_core/include/ipc_object_stub.h"
        source = CORPUS / "ipc/native/src/core/framework/source/ipc_object_stub.cpp"
        units = sorted(
            (unit(str(header.relative_to(CORPUS)), header.read_text()),
             unit(str(source.relative_to(CORPUS)), source.read_text())),
            key=lambda u: u.path)
        index = build(*units)
        hits = [e for e in index.entries
                if e.dispatcher.endswith("IPCObjectStub::SendRequest")
                and e.handler.endswith("DBinderGetPidUid")]
        self.assertEqual(len(hits), 1)
        entry = hits[0]
        self.assertIn("GET_PID_UID", entry.transaction_raw)
        self.assertIn("ifndef CONFIG_IPC_SINGLE", entry.conditional)
        self.assertEqual(entry.evidence, SOURCE_DISPATCH)
        self.assertTrue(entry.handler_bound)


if __name__ == "__main__":
    unittest.main()
