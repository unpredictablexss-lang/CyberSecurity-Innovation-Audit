"""PoC lifecycle states, stability-replay labels and the evidence ladder.

Two vocabularies exist in the project documentation and they are not the same
ladder, so both are named here explicitly rather than being conflated:

* the six-state lifecycle from `docs/architecture_2026.md` section 8.4 (also
  listed in `docs/evaluation_criteria.md` section 6);
* the evidence ladder from `docs/strategy/competition_deliverables_plan.md`
  section 2.3, which adds `dynamic_reproduced`.

A PoC never claims a level its recorded evidence does not support.
"""

POC_STATES = (
    "not_generated",
    "generated",
    "build_success",
    "run_success",
    "trigger_success",
    "stable_reproduced",
)

REPLAY_LABELS = ("no_trigger", "flaky", "trigger_success", "stable_reproduced")

EVIDENCE_LEVELS = (
    "static_candidate",
    "static_confirmed",
    "dynamic_reproduced",
    "stable_reproduced",
)

# PoC state -> the strongest evidence level that state actually justifies.
_STATE_TO_EVIDENCE = {
    "not_generated": "static_candidate",
    "generated": "static_candidate",
    "build_success": "static_candidate",
    "run_success": "static_candidate",
    "trigger_success": "dynamic_reproduced",
    "stable_reproduced": "stable_reproduced",
}


def ladder_state(*, generated, built, ran, triggered, stable):
    """Where on the lifecycle ladder the run actually stopped.

    A step that did not happen leaves the state at the previous rung; a failed
    step is never reported as the rung above it.
    """
    if not generated:
        return "not_generated"
    if not built:
        return "generated"
    if not ran:
        return "build_success"
    if not triggered:
        return "run_success"
    return "stable_reproduced" if stable else "trigger_success"


def replay_label(attempts):
    """Label a stability replay from a sequence of per-attempt booleans."""
    attempts = tuple(bool(item) for item in attempts)
    if not attempts or not any(attempts):
        return "no_trigger"
    if all(attempts):
        return "stable_reproduced" if len(attempts) > 1 else "trigger_success"
    return "flaky"


def evidence_for(state):
    """The evidence level justified by a lifecycle state."""
    return _STATE_TO_EVIDENCE[state]
