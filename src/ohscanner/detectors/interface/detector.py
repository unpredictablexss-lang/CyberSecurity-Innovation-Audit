"""Contract-compatible first-party IPC candidate detector."""
from typing import Tuple
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .analysis import Interpreter
from .families import cwes, merge_policy
from .models import IMPACT_DESCRIPTION, MODEL_VERSION, reviewed_consequence
from .tlv_fixed_width import find_fixed_width_tlv_overreads
from .network_session_allowlist import (
    find_auth_session_allowlist_candidates,
    has_exact_registered_session_resolution,
)
from .auth_transport_status import find_permission_denial_transport_success


# Exact path components are review cues, not proof that a file is excluded from
# a product build. Some OpenHarmony tests and fuzzers deliberately compile
# production sources, so these candidates must remain visible and carry an
# explicit build-membership obligation instead of being silently dropped.
_TEST_SOURCE_SEGMENTS = frozenset({
    "test", "tests", "unittest", "unittests", "fuzz", "fuzztest",
    "fuzztests", "fuzzer", "fuzzers", "mock", "mocks", "rdbmock",
})


def _test_source_path(path):
    normalized = path.replace(chr(92), "/").lower()
    return bool(_TEST_SOURCE_SEGMENTS.intersection(
        segment for segment in normalized.split("/") if segment))

# Which family reports which mechanism CWE. Read from the family modules rather
# than repeated here, so a family's id, its rules and its CWE land together and a
# new family cannot be emitted without declaring the CWE it reports.
_CWE = cwes()
assert set(_CWE) == {"AUTH-01", "AUTH-02", "AUTH-03", "AUTH-04", "AUTH-05", "AUTH-06", "AUTH-07",
                     "DATA-01", "DATA-02", "DATA-03", "DATA-04", "DATA-05", "CAP-01"}, sorted(_CWE)

_BASE_OBLIGATIONS = (
    EvidenceObligation("entry_reachability","Verify actual caller reachability and product build/macro conditions."),
    EvidenceObligation("callee_and_policy","Verify overload/receiver binding, required permission and any upstream guard."),
    EvidenceObligation("security_impact","Independently review attacker control, trust boundary and concrete effect."),
)
_DISPATCH_OBLIGATION = EvidenceObligation(
    "dispatch_binding",
    "Handler was admitted as an entry from a source-derived dispatch binding. Verify dispatcher-level "
    "guards (e.g. IsCallerValid/IsPermissionGranted), their dominance over this transaction code, and the "
    "overload/receiver binding.")
_DESCRIPTOR_OBLIGATIONS = {
    "mismatch": EvidenceObligation(
        "descriptor_identity_mismatch",
        "A descriptor comparison is present but targets an interface other than the one this class "
        "states it implements. Verify which interface this transaction actually carries and whether the "
        "caller the candidate assumes can present that descriptor."),
    "unresolved": EvidenceObligation(
        "descriptor_identity_unresolved",
        "A descriptor comparison is present but the source does not state which interface this class "
        "implements, so neither a working guard nor a mismatch is established. Verify the interface and "
        "the descriptor its caller writes before treating the comparison as a guard."),
}
_CONSEQUENCE_OBLIGATION = EvidenceObligation(
    "consequence",
    "Establish what the modeled path can actually expose: which data, capability or state the caller "
    "reaches, and to whom. A modeled read of a sensitive API does not by itself show that anything was "
    "returned to an unauthorized caller. The candidate CWE is the mechanism; the consequence CWE stated "
    "in the message is a possibility, not a demonstrated effect.")


def _finding_message(o):
    """Mechanism first, then the possible consequence, then the path.

    The consequence is stated with the call that drove it so the classification
    can be reviewed rather than trusted. Both CWE numbers appear: the mechanism
    CWE on the finding, the consequence CWE here.
    """
    message = (o.family + " candidate: " + o.message + " Entry=" + o.root_key[1]
               + " [entry-source=" + o.root_key[0] + "]")
    if _test_source_path(o.root_key[0]):
        message += " [entry-source-review-cue=test/fuzz/mock path; product-build membership is unverified]"
    if o.entry_grade == "dispatch" and o.dispatch_note:
        message += " [" + o.dispatch_note + "]"
    if o.impact and o.impact != "unknown":
        # The CWE is only appended when the catalogue can justify one; an impact
        # whose CWE depends on what the path reaches is named without a number.
        label = o.impact + ((" " + o.impact_cwe) if o.impact_cwe else "")
        message += ("; possible consequence (not established): " + IMPACT_DESCRIPTION[o.impact]
                    + " [" + label + "]")
        if o.impact_basis:
            message += " driven by modelled call " + o.impact_basis
    return message + "; path=" + repr(o.trace)


class IpcInterfaceDetector:
    detector_id = "ohscanner.interface.ipc"
    # 0.9.3 was used by the archived campaign implementation; skip it here so
    # this source-verified macro-flow change cannot collide with that identity.
    version = "0.12.6"
    # The interpretation model, recorded so a persisted candidate can name the
    # rule set it came from, not only the code version. Read by the audit driver
    # through getattr; it is not part of the shared Detector protocol.
    model_version = MODEL_VERSION
    # The interpretation this detector applies, independent of any scope variant.
    interpretation_id = "ohscanner.interface.ipc"
    supported_languages = ("c", "cpp")
    required_facts = ()
    ast_scope = "per_file"

    def __init__(self, policy=None):
        # The reviewed policy is the catalogue's defaults plus the families'
        # additions; a caller-supplied policy is merged rather than replaced, so a
        # narrowed harness (`IpcPolicy(max_paths=2)`) still runs under the facts
        # the families were reviewed for. See families.merge_policy.
        self.policy = merge_policy(policy)

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        ast = context.shared_facts.get("ast", {})
        # Only this detector's declared languages are in scope. A .ts/.js/.ets
        # declaration file, or a language with no frontend, is outside the
        # detector rather than a reason to abandon the whole component.
        applicable = tuple(u for u in units if u.language in self.supported_languages)
        if not applicable or any(u.parse_status in ("failed","not_run") or u.path not in ast
                                 for u in applicable):
            return DetectorRun(self.detector_id,self.version,"blocked",limitations=(
                "Shared AST outline is required for every supported unit; missing/failed coverage is unknown. "
                "Unsupported languages are outside this detector's declared scope.",))
        analysis = Interpreter(applicable,self.policy,context.request)
        observations, extra = analysis.run()
        findings = tuple(DetectorFinding(
            file=o.file,line=o.line,symbol=o.symbol,rule_id=o.rule,
            message=_finding_message(o),
            evidence_type="syntax",candidate_cwe=_CWE[o.family],
            # Contract v2 §3: mechanism CWE above, consequence here. Both are
            # optional and neither overwrites the other; the message keeps the
            # same content for readers. `reviewed_consequence` drops the
            # catalogue's "unknown" to None so an unclassified consequence never
            # travels as a value that looks classified.
            consequence_impact=reviewed_consequence(o.impact),
            consequence_cwe=o.impact_cwe or None,
            evidence_obligations=_BASE_OBLIGATIONS
                +((_DISPATCH_OBLIGATION,) if o.entry_grade=="dispatch" else ())
                +((EvidenceObligation(
                    "entry_build_membership",
                    "The modeled entry source path contains a test/fuzz/mock segment. This is only a path cue; "
                    "verify whether the entry is included in the pinned product build before treating it as a "
                    "product-reachable interface.",
                ),) if _test_source_path(o.root_key[0]) else ())
                +((_DESCRIPTOR_OBLIGATIONS[o.descriptor_identity],) if o.descriptor_identity else ())
                +((_CONSEQUENCE_OBLIGATION,) if o.impact and o.impact!="unknown" else ()),
            ) for o in observations)
        resource_findings = []
        for fn, line, container in analysis.unbounded_observer_registrations():
            resource_findings.append(DetectorFinding(
                file=fn.file,
                line=line,
                symbol=fn.qualified,
                rule_id="ipc.resource.unbounded-observer-registration",
                message=("Observer-growth candidate: the component contains an IPC On*Observer "
                         "entry calling SubscribeObserver and a same-owner AddObserver helper "
                         "inserting " + container + " without the reviewed aggregate observer-cap "
                         "shape. This lightweight rule does not prove the cross-class/virtual call "
                         "edge, complete insertion accounting, caller reachability, or product-level "
                         "denial of service."),
                evidence_type="syntax",
                candidate_cwe="CWE-400",
                evidence_obligations=(
                    EvidenceObligation(
                        "call_path_binding",
                        "Bind the On*Observer entry, SubscribeObserver implementation and AddObserver "
                        "sink through interface/virtual dispatch in the pinned component.",
                    ),
                    EvidenceObligation(
                        "entry_reachability",
                        "Verify the pinned product build registers this IPC entry and an untrusted "
                        "caller can reach it with distinct observer objects.",
                    ),
                    EvidenceObligation(
                        "resource_bound",
                        "Review all insertion paths and cross-type aggregate accounting; this rule "
                        "recognizes only a local limit comparison followed by an early exit.",
                    ),
                    EvidenceObligation(
                        "product_impact",
                        "Measure resource growth and service availability in a supported product "
                        "configuration before assigning denial-of-service impact.",
                    ),
                ),
            ))
        permission_findings = []
        for fn, line, grant_name, path_note in analysis.privileged_permission_grants():
            permission_findings.append(DetectorFinding(
                file=fn.file,
                line=line,
                symbol=fn.qualified,
                rule_id="ipc.auth.privileged-app-bypass",
                message=("Authorization-policy candidate: default-app/IME predicate " + grant_name
                         + " contributes to the VerifyPermission grant. "
                         + (("Source-derived path within the scanned scope: " + path_note + ". "
                             "Product build reachability and other overrides remain unverified. ")
                            if path_note else
                            "No unique source-derived entry-to-implementation path was established. ")
                         + "Review whether this alternate grant exceeds the documented permission policy."),
                evidence_type="syntax",
                candidate_cwe="CWE-862",
                evidence_obligations=(
                    EvidenceObligation(
                        "call_path_binding",
                        (("The pinned scan resolves this entry through one source-derived implementation "
                          "to this verifier; verify product registration, dispatch and any overrides "
                          "outside the scanned scope.") if path_note else
                         "Bind the OnGetPasteData entry to this GetPasteData/VerifyPermission implementation "
                         "through the pinned interface and virtual-dispatch hierarchy."),
                    ),
                    EvidenceObligation(
                        "grant_policy",
                        "Verify the privileged-app exception against the permission policy and "
                        "fixed-version security patch; a named exception is not automatically safe.",
                    ),
                    EvidenceObligation(
                        "entry_reachability",
                        "Verify the pinned product build and caller identities that can reach the "
                        "GetPasteData transaction.",
                    ),
                    EvidenceObligation(
                        "disclosure_impact",
                        "Confirm whether an unauthorized caller can retrieve protected pasteboard "
                        "data in the product configuration.",
                    ),
                ),
            ))
        findings = findings + tuple(resource_findings) + tuple(permission_findings)
        # A narrowly reviewed SoftBus network-auth callback is not a Binder
        # OnRemoteRequest root. Keep this source-only check separate and attach
        # explicit reachability/policy obligations to its candidate.
        network_auth_findings = []
        exact_registered_session_resolution = has_exact_registered_session_resolution(
            unit.text for unit in applicable
            if unit.parse_status not in ("failed", "not_run")
        )
        for unit in applicable:
            if unit.parse_status in ("failed", "not_run"):
                continue
            for line, symbol, check_kind in find_auth_session_allowlist_candidates(unit.text):
                message = ("AUTH-06 candidate: a decoded peer AppInfo reaches auth-channel state "
                           "update and success notification without a source-recognized exact "
                           "sessionName whitelist rejection. Network reachability and policy effect "
                           "remain unknown.")
                consequence = "unauthorized_effect"
                if check_kind == "prefix":
                    if exact_registered_session_resolution:
                        message = ("AUTH-06 candidate: the callback applies a prefix-only sessionName "
                                   "allowlist before auth-channel state changes. A downstream exact "
                                   "session-registry lookup proves that the name is registered, but "
                                   "does not prove it is an exact allowlist member or that its "
                                   "registration policy authorizes this peer. Suffix-bearing names "
                                   "and product policy remain unknown.")
                    else:
                        message = ("AUTH-06 candidate: the callback rejects names outside its "
                                   "sessionName allowlist, but the recognized strncmp comparison "
                                   "only checks an allowlist-length prefix. Whether suffix-bearing "
                                   "names are valid and whether this changes downstream authorization "
                                   "remain unknown.")
                    consequence = "unknown"
                network_auth_findings.append(DetectorFinding(
                    file=unit.path,
                    line=line,
                    symbol=symbol,
                    rule_id="ipc.network.auth-session-whitelist",
                    message=message,
                    evidence_type="syntax",
                    candidate_cwe="CWE-862",
                    consequence_impact=consequence,
                    evidence_obligations=(
                        EvidenceObligation("network_entry_binding",
                                           "Bind this callback to the authenticated transport, peer and enabled product module."),
                        EvidenceObligation("session_name_policy",
                                           "Verify the approved session-name set and exact identity comparison semantics."),
                        EvidenceObligation("authorization_effect",
                                           "Verify whether a non-approved peer identity can create state or trigger a privileged callback."),
                        EvidenceObligation("security_impact",
                                           "Establish attacker reachability, required pairing/trust prerequisites and concrete impact."),
                    ),
                ))
        findings = findings + tuple(network_auth_findings)
        # Separate transaction status from reply-payload status. A successful
        # transport return after an authorization rejection is a candidate only;
        # client-side consumption determines whether it weakens the denial.
        transport_status_findings = []
        for unit in applicable:
            if unit.language != "cpp" or unit.parse_status in ("failed", "not_run"):
                continue
            for line, symbol, predicate, status in find_permission_denial_transport_success(unit.text):
                transport_status_findings.append(DetectorFinding(
                    file=unit.path,
                    line=line,
                    symbol=symbol,
                    rule_id="ipc.auth.denial-transport-success",
                    message=("AUTH-07 candidate: a failed " + predicate
                             + " guard writes an error to the reply but returns transport success "
                             + status + ". This status mismatch does not by itself prove authorization "
                             "bypass; inspect the proxy, Binder wrapper and reply-consumption path."),
                    evidence_type="syntax",
                    candidate_cwe="CWE-863",
                    consequence_impact=None,
                    evidence_obligations=(
                        EvidenceObligation("transport_reply_semantics",
                                           "Determine whether this Binder status is consumed separately from the reply payload and whether success changes caller behavior."),
                        EvidenceObligation("permission_failure_path",
                                           "Verify the predicate's authorization policy and that the branch is the actual denial path."),
                        EvidenceObligation("client_binding",
                                           "Bind the transaction to the pinned proxy or caller that consumes the transport result and reply."),
                        EvidenceObligation("security_impact",
                                           "Establish whether the mismatch permits protected data or effects despite denial."),
                    ),
                ))
        findings = findings + tuple(transport_status_findings)
        # TLV fixed-width serializers are reusable parser helpers, not IPC roots.
        # Keep this exact non-entry pass separate; do not imply IPC reachability.
        tlv_findings = []
        for unit in applicable:
            if unit.language != "cpp" or unit.parse_status in ("failed", "not_run"):
                continue
            for line, symbol in find_fixed_width_tlv_overreads(unit.text):
                tlv_findings.append(DetectorFinding(
                    file=unit.path,
                    line=line,
                    symbol=symbol,
                    rule_id="ipc.tlv.fixed-width-length",
                    message=("DATA-05 candidate: a TLV header length bounds available bytes, "
                             "but a fixed-width memcpy_s still reads sizeof(T) without first "
                             "requiring head.len == sizeof(T). Entry reachability, the exact "
                             "serialized input source, and product impact are not established."),
                    evidence_type="syntax",
                    candidate_cwe="CWE-125",
                    consequence_impact="out_of_bounds_read",
                    consequence_cwe="CWE-125",
                    evidence_obligations=(
                        EvidenceObligation("serialized_input_binding",
                                           "Verify the TLV header and backing byte vector derive from the same untrusted serialized input."),
                        EvidenceObligation("source_extent",
                                           "Confirm a short declared value can leave fewer than sizeof(T) physical bytes at cursor_ on the reached path."),
                        EvidenceObligation("entry_reachability",
                                           "Bind this reusable parser helper to a product IPC/service entry and attacker-controlled data."),
                        EvidenceObligation("security_impact",
                                           "Determine whether adjacent bytes are disclosed, only misparsed, or safely rejected by surrounding code."),
                    ),
                ))
        findings = findings + tuple(tlv_findings)
        status = "blocked" if any(u.parse_status != "complete" for u in applicable) else "completed"
        return DetectorRun(self.detector_id,self.version,status,tuple(u.path for u in applicable),findings,
            ("Model="+MODEL_VERSION+"; first-party bounded structured syntax interpretation, no external scanner execution.",
             "Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.",
             "No compiler CFG, arbitrary virtual dispatch, alias analysis or full-program authorization proof. "
             "Macros are expanded only from the scan's own sources and only when unambiguous; the catalogue is "
             "never an #include resolution, and what the expander refused is counted in the macro-expansion "
             "limitation rather than assumed away.",
             "Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.",
             "Interface-descriptor identity is read from the class's own base clause: a comparison is counted "
             "as this transaction's guard only when the source names the interface the class implements. A "
             "comparison against another interface, or one whose identity the analysed sources do not state, "
             "is reported with that reason instead of counting as a guard or as a proven mismatch.",
             "Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.",
             "IPC roots require a source-indexed class dispatcher with code, request Parcel and reply Parcel; "
             "explicit service/transport roots and Stub inner helpers are separate allowlisted entry kinds. "
             "Test/fuzz/mock path roots are excluded from product candidate analysis and counted in limitations. "
             "Entry discovery is not reachability: dispatcher-level guards and macro-conditional reachability "
             "remain obligations, not conclusions.",
             "Entry-coverage measurements are published in the interface research report, not in this result.")+extra)


class IpcInterfaceCompleteAstDetector(IpcInterfaceDetector):
    """The same interpretation, restricted by the shared runner to complete AST.

    ``IpcInterfaceDetector`` walks partial and complete parses alike, so one
    partial file in a real component makes the whole run ``blocked``. The shared
    runner then records neither scope counters nor evidence obligations for that
    run: ``runner.py`` reports ``scope_files``/``scope_loc`` as 0 unless the
    status is ``completed``, and the coverage sidecar lists per-candidate
    obligations only for a completed run. The candidates are still emitted, so a
    blocked run hands the reviewer a finding list with the proof obligations
    stripped from it -- the one thing the evidence gate needs.

    Declaring ``ast`` as a required fact makes the runner select only units whose
    parse is complete and record the rest as ``unexamined`` with an explicit
    ``incomplete_ast:<status>`` reason. The run then completes over a scope it
    can name, with real counters and recorded obligations.

    This is a scope restriction, not a recall claim. Candidates visible only in
    partial trees are not claimed here; an audit runs both scopes and reports
    which pass saw each candidate. Neither pass promotes anything: every
    diagnostic stays ``candidate`` with its obligations attached.
    """
    detector_id = "ohscanner.interface.ipc.complete-ast"
    required_facts = ("ast",)
    # Same interpretation as the base detector, applied under a narrower scope.
    # Declared explicitly so a candidate found by both passes keeps ONE identity
    # instead of splitting into two rows over a variant id.
    interpretation_id = "ohscanner.interface.ipc"
