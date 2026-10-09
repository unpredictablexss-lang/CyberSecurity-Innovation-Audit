"""Contract-compatible first-party IPC candidate detector (six families)."""
from typing import Tuple
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit
from .analysis import Interpreter
from .models import IpcPolicy, MODEL_VERSION

_CWE = {"AUTH-01":"CWE-441", "AUTH-02":"CWE-862", "AUTH-03":"CWE-863", "AUTH-04":"CWE-863", "DATA-01":"CWE-20", "CAP-01":"CWE-926"}

class IpcInterfaceDetector:
    detector_id = "ohscanner.interface.ipc"
    version = "0.1.0"
    supported_languages = ("c", "cpp")
    required_facts = ()
    ast_scope = "per_file"

    def __init__(self, policy=None):
        self.policy = policy or IpcPolicy()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        ast = context.shared_facts.get("ast", {})
        if any(u.parse_status in ("failed","not_run") or u.path not in ast for u in units):
            return DetectorRun(self.detector_id,self.version,"blocked",limitations=("Shared AST outline is required; missing/failed coverage is unknown.",))
        analysis = Interpreter(units,self.policy)
        observations, extra = analysis.run()
        findings = tuple(DetectorFinding(
            file=o.file,line=o.line,symbol=o.symbol,rule_id=o.rule,
            message=o.family+" candidate: "+o.message+" Entry="+o.root_key[1]+"; path="+repr(o.trace),
            evidence_type="syntax",candidate_cwe=_CWE[o.family],
            evidence_obligations=(
                EvidenceObligation("entry_reachability","Verify actual caller reachability and product build/macro conditions."),
                EvidenceObligation("callee_and_policy","Verify overload/receiver binding, required permission and any upstream guard."),
                EvidenceObligation("security_impact","Independently review attacker control, trust boundary and concrete effect."),
            )) for o in observations)
        status = "blocked" if any(u.parse_status != "complete" for u in units) else "completed"
        return DetectorRun(self.detector_id,self.version,status,tuple(u.path for u in units),findings,
            ("Model="+MODEL_VERSION+"; first-party bounded structured syntax interpretation, no external scanner execution.",
             "Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.",
             "No compiler CFG, macro expansion, arbitrary virtual dispatch, alias analysis or full-program authorization proof.",
             "Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.",
             "Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.",
             "Entry methods plus Stub *Inner handlers with first MessageParcel as request; handler upstream exposure remains unknown.")+extra)
