"""Family-specific proof-of-concept generation and local dynamic execution.

This module is the only place in the project that compiles and runs OpenHarmony
component code. It is deliberately separate from the detectors: per
`docs/contracts/ohscanner_detector_contract_v1.md`, a detector's production
execution path must not execute the target or invoke external scanners, and
promotion of a finding is carried by this module plus review records rather than
happening quietly inside a detector run.

Scope and standing limits (AGENTS.md): a PoC may build and run a local, isolated
copy of a component and may use sanitizers. It must not touch live or remote
services. Nothing here turns "the code did X" into "an attacker can do X":
reachability stays an obligation until it is separately evidenced.

The evidence ladder used here is
`static_candidate < static_confirmed < dynamic_reproduced < stable_reproduced`,
and the PoC lifecycle is
`not_generated -> generated -> build_success -> run_success -> trigger_success
-> stable_reproduced`
(`docs/architecture_2026.md` section 8.4, per `docs/evaluation_criteria.md` section 6).
"""
from .reachability import ReachabilityEvidence, Relation, verify as verify_reachability  # noqa: F401
from .records import PocResult, render_markdown  # noqa: F401
from .runner import run_poc  # noqa: F401
from .states import EVIDENCE_LEVELS, POC_STATES, REPLAY_LABELS, ladder_state, replay_label  # noqa: F401
