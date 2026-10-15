"""Executable conformance rules for A-CCR-04.

This module is proposal/test support only. It does not implement or modify the
public OHScanner Detector contract, runner, IR, catalog, or report schema.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


CONTRACT_PATH = Path(__file__).with_name("contract.json")
CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
STATUS_VALUES = tuple(CONTRACT["status_values"])
METHODS = tuple(item["name"] for item in CONTRACT["methods"])
LIMIT_FIELDS = tuple(CONTRACT["budget"]["limit_fields"])


class ContractViolation(ValueError):
    """Raised when a proposed ReadOnlyFactView response violates A-CCR-04."""


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractViolation(f"{name} must be an object")
    return value


def _required(value: Mapping[str, Any], fields: tuple[str, ...], name: str) -> None:
    missing = set(fields) - set(value)
    if missing:
        raise ContractViolation(
            f"{name} missing fields: " + ", ".join(sorted(missing))
        )


def _integer(value: Any, name: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractViolation(f"{name} must be an integer >= {minimum}")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractViolation(f"{name} must be non-empty text")
    return value


def _proof_refs(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise ContractViolation("proof_ref must be an array")
    result = []
    fields = tuple(CONTRACT["proof_ref"]["required_fields"])
    for index, item in enumerate(value):
        record = _mapping(item, f"proof_ref[{index}]")
        _required(record, fields, f"proof_ref[{index}]")
        _text(record["evidence_id"], f"proof_ref[{index}].evidence_id")
        if record["kind"] not in CONTRACT["proof_ref"]["kinds"]:
            raise ContractViolation(f"proof_ref[{index}].kind is unsupported")
        if record["authority"] not in CONTRACT["proof_ref"]["authorities"]:
            raise ContractViolation(f"proof_ref[{index}].authority is unsupported")
        _text(record["object_sha256"], f"proof_ref[{index}].object_sha256")
        if not isinstance(record["verified"], bool):
            raise ContractViolation(f"proof_ref[{index}].verified must be boolean")
        result.append(record)
    return result


def _scope(value: Any) -> Mapping[str, Any]:
    scope = _mapping(value, "analysis_scope")
    _required(scope, tuple(CONTRACT["analysis_scope"]["required_fields"]), "analysis_scope")
    for field in ("repository", "commit", "git_tree", "snapshot_sha256", "profile_id"):
        _text(scope[field], f"analysis_scope.{field}")
    if not isinstance(scope["files"], list):
        raise ContractViolation("analysis_scope.files must be an array")
    for index, item in enumerate(scope["files"]):
        record = _mapping(item, f"analysis_scope.files[{index}]")
        _required(record, tuple(CONTRACT["analysis_scope"]["file_fields"]),
                  f"analysis_scope.files[{index}]")
        for field in CONTRACT["analysis_scope"]["file_fields"]:
            _text(record[field], f"analysis_scope.files[{index}].{field}")
    if not isinstance(scope["functions"], list):
        raise ContractViolation("analysis_scope.functions must be an array")
    detector = _mapping(scope["detector"], "analysis_scope.detector")
    _required(detector, ("detector_id", "version"), "analysis_scope.detector")
    _text(detector["detector_id"], "analysis_scope.detector.detector_id")
    _text(detector["version"], "analysis_scope.detector.version")
    _text(scope["build_context_id"], "analysis_scope.build_context_id")
    return scope


def _budget(value: Any, *, allow_invalid_request: bool = False) -> Mapping[str, Any]:
    budget = _mapping(value, "budget")
    _required(budget, tuple(CONTRACT["budget"]["required_fields"]), "budget")
    requested = _mapping(budget["requested"], "budget.requested")
    used = _mapping(budget["used"], "budget.used")
    _required(requested, LIMIT_FIELDS, "budget.requested")
    _required(used, LIMIT_FIELDS, "budget.used")
    for field in LIMIT_FIELDS:
        if allow_invalid_request:
            if isinstance(requested[field], bool) or not isinstance(requested[field], int):
                raise ContractViolation(
                    f"budget.requested.{field} must remain an integer in failure evidence"
                )
        else:
            _integer(requested[field], f"budget.requested.{field}", minimum=1)
        actual = _integer(used[field], f"budget.used.{field}", minimum=0)
        if not allow_invalid_request and actual > requested[field]:
            raise ContractViolation(
                f"budget.used.{field} exceeds budget.requested.{field}"
            )
    if not isinstance(budget["exhausted"], list):
        raise ContractViolation("budget.exhausted must be an array")
    unsupported = set(budget["exhausted"]) - set(LIMIT_FIELDS)
    if unsupported:
        raise ContractViolation(
            "budget.exhausted has unsupported fields: "
            + ", ".join(sorted(unsupported))
        )
    if budget["reason"] is not None:
        _text(budget["reason"], "budget.reason")
    return budget


def validate_response(method: str, payload: Any) -> Mapping[str, Any]:
    """Validate one proposed response and return it unchanged."""
    if method not in METHODS:
        raise ContractViolation(f"unsupported method: {method}")
    response = _mapping(payload, "response")
    _required(response, tuple(CONTRACT["response_envelope"]["required_fields"]), "response")
    if response["schema_version"] != CONTRACT["schema_version"]:
        raise ContractViolation("unsupported response schema_version")
    if response["change_request_id"] != CONTRACT["change_request_id"]:
        raise ContractViolation("change_request_id mismatch")
    if response["method"] != method:
        raise ContractViolation("response method mismatch")
    _text(response["request_id"], "request_id")
    status = response["status"]
    if status not in STATUS_VALUES:
        raise ContractViolation("unsupported status")

    refs = _proof_refs(response["proof_ref"])
    _scope(response["analysis_scope"])
    failure = response["failure_reason"]
    invalid_budget_failure = (
        status == "failed"
        and isinstance(failure, Mapping)
        and failure.get("code") == "invalid_budget"
    )
    budget = _budget(response["budget"], allow_invalid_request=invalid_budget_failure)

    if not isinstance(response["limitations"], list):
        raise ContractViolation("limitations must be an array")
    for index, item in enumerate(response["limitations"]):
        _text(item, f"limitations[{index}]")

    failure = response["failure_reason"]
    unknown = response.get("unknown_reason")
    if status == "failed":
        record = _mapping(failure, "failure_reason")
        _required(record, tuple(CONTRACT["failure_reason"]["required_fields"]), "failure_reason")
        if record["code"] not in CONTRACT["failure_reason"]["codes"]:
            raise ContractViolation("unsupported failure_reason.code")
        _text(record["message"], "failure_reason.message")
        if not isinstance(record["retryable"], bool):
            raise ContractViolation("failure_reason.retryable must be boolean")
        if response["facts"] is not None:
            raise ContractViolation("failed responses cannot carry facts")
        if unknown is not None:
            raise ContractViolation("failed responses cannot carry unknown_reason")
    else:
        if failure is not None:
            raise ContractViolation("failure_reason must be null unless status=failed")
        if status == "unknown":
            record = _mapping(unknown, "unknown_reason")
            _required(record, tuple(CONTRACT["unknown_reason"]["required_fields"]), "unknown_reason")
            if record["code"] not in CONTRACT["unknown_reason"]["codes"]:
                raise ContractViolation("unsupported unknown_reason.code")
            _text(record["message"], "unknown_reason.message")
            if not isinstance(record["missing_facts"], list):
                raise ContractViolation("unknown_reason.missing_facts must be an array")
            for index, item in enumerate(record["missing_facts"]):
                _text(item, f"unknown_reason.missing_facts[{index}]")
            if response["facts"] is not None:
                raise ContractViolation("unknown responses cannot carry guessed facts")
        else:
            if unknown is not None:
                raise ContractViolation("unknown_reason is only valid for unknown")
            if response["facts"] is None:
                raise ContractViolation(f"{status} responses must carry facts")
            if not refs:
                raise ContractViolation(f"{status} responses require proof_ref")
            if status == "proven" and not all(item["verified"] for item in refs):
                raise ContractViolation("proven proof_ref entries must be verified")

    if budget["exhausted"] and status != "unknown":
        raise ContractViolation("budget exhaustion must return unknown")
    if budget["exhausted"]:
        record = _mapping(unknown, "unknown_reason")
        if record["code"] != "budget_exhausted":
            raise ContractViolation("budget exhaustion requires budget_exhausted")
        if response["facts"] is not None:
            raise ContractViolation("budget exhaustion cannot expose partial facts")
    return response


def validate_budget_payload(payload: Any) -> Mapping[str, Any]:
    """Validate a standalone budget object for focused budget tests."""
    return _budget(payload)
