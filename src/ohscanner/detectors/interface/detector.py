"""Contract-compatible first-party IPC candidate detector (six families)."""
from typing import Tuple
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .analysis import Interpreter
from .fd_backing import detect_fd_backing_findings
from .families import cwes, merge_policy
from .models import IMPACT_DESCRIPTION, MODEL_VERSION, reviewed_consequence

# Which family reports which mechanism CWE. Read from the family modules rather
# than repeated here, so a family's id, its rules and its CWE land together and a
# new family cannot be emitted without declaring the CWE it reports.
_CWE = cwes()
assert set(_CWE) == {"AUTH-01", "AUTH-02", "AUTH-03", "AUTH-04", "AUTH-05",
                     "DATA-01", "DATA-02", "DATA-03", "DATA-04", "CAP-01"}, sorted(_CWE)

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
    message = o.family + " candidate: " + o.message + " Entry=" + o.root_key[1]
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
    version = "0.9.3"
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
        fd_findings, fd_limitations = detect_fd_backing_findings(applicable)
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
                +((_DESCRIPTOR_OBLIGATIONS[o.descriptor_identity],) if o.descriptor_identity else ())
                +((_CONSEQUENCE_OBLIGATION,) if o.impact and o.impact!="unknown" else ()),
            ) for o in observations) + fd_findings
        status = "blocked" if any(u.parse_status != "complete" for u in applicable) else "completed"
        return DetectorRun(self.detector_id,self.version,status,tuple(u.path for u in applicable),findings,
            ("Model="+MODEL_VERSION+"; first-party bounded structured syntax interpretation, no external scanner execution.",
             "Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.",
             *fd_limitations,
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
             "Entry roots come from the name allowlist plus source-derived dispatch bindings (function-pointer tables, "
             "switch/if code dispatch, and source-declared virtual overrides). Entry discovery is not reachability: "
             "dispatcher-level guards and macro-conditional reachability remain obligations, not conclusions.",
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
