"""Contract-compatible first-party IPC candidate detector (six families)."""
from typing import Tuple
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .analysis import Interpreter
from .models import IMPACT_DESCRIPTION, IpcPolicy, MODEL_VERSION

_CWE = {"AUTH-01":"CWE-441", "AUTH-02":"CWE-862", "AUTH-03":"CWE-863", "AUTH-04":"CWE-863", "DATA-01":"CWE-20", "CAP-01":"CWE-926"}

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
    version = "0.2.0"
    supported_languages = ("c", "cpp")
    required_facts = ()
    ast_scope = "per_file"

    def __init__(self, policy=None):
        self.policy = policy or IpcPolicy()

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
        analysis = Interpreter(applicable,self.policy)
        observations, extra = analysis.run()
        findings = tuple(DetectorFinding(
            file=o.file,line=o.line,symbol=o.symbol,rule_id=o.rule,
            message=_finding_message(o),
            evidence_type="syntax",candidate_cwe=_CWE[o.family],
            evidence_obligations=_BASE_OBLIGATIONS
                +((_DISPATCH_OBLIGATION,) if o.entry_grade=="dispatch" else ())
                +((_CONSEQUENCE_OBLIGATION,) if o.impact and o.impact!="unknown" else ()),
            ) for o in observations)
        status = "blocked" if any(u.parse_status != "complete" for u in applicable) else "completed"
        return DetectorRun(self.detector_id,self.version,status,tuple(u.path for u in applicable),findings,
            ("Model="+MODEL_VERSION+"; first-party bounded structured syntax interpretation, no external scanner execution.",
             "Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.",
             "No compiler CFG, macro expansion, arbitrary virtual dispatch, alias analysis or full-program authorization proof.",
             "Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.",
             "Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.",
             "Entry roots come from the name allowlist plus source-derived dispatch bindings (function-pointer tables, "
             "switch/if code dispatch, and source-declared virtual overrides). Entry discovery is not reachability: "
             "dispatcher-level guards and macro-conditional reachability remain obligations, not conclusions.",
             "Entry-coverage measurements are published in the interface research report, not in this result.")+extra)
