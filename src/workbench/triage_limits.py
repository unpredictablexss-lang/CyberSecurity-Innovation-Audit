"""Explicit limits for user-authorized automatic candidate triage."""

DEFAULT_AGENT_OUTPUT_TOKENS = 5000

MAX_TRIAGE_CANDIDATES_PER_ENDPOINT = 10_000
MAX_AUTOMATIC_TRIAGE_ENDPOINTS = 8
MAX_AUTHORIZED_TRIAGE_QUEUE_ITEMS = (
    MAX_TRIAGE_CANDIDATES_PER_ENDPOINT * MAX_AUTOMATIC_TRIAGE_ENDPOINTS
)
R1_CANDIDATE_SELECTION_POLICY = "evidence_route_then_severity_then_fixed_candidate_id_v2"
R1_OVERFLOW_POLICY = "fail_closed_without_model_queue_and_require_smaller_batches"
