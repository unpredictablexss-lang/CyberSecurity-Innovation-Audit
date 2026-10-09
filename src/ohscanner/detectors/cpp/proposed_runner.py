"""Minimal failure-isolation helper for proposed detector experiments.

This is not the owner-provided OHScanner registry or runner. It only proves the
local requirement that one detector crash/timeout produces one failure record
while another detector can still return its own run.
"""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Callable, Sequence, Tuple

from .proposed_contract import ProposedDetectorRun


@dataclass(frozen=True)
class DetectorJob:
    detector_id: str
    version: str
    invoke: Callable[[], ProposedDetectorRun]


def _failure_run(job: DetectorJob, failure_kind: str, elapsed: float, detail: str) -> ProposedDetectorRun:
    return ProposedDetectorRun(
        detector_id=job.detector_id,
        version=job.version,
        status="failed",
        diagnostics=(),
        analyzed_files=(),
        coverage=(),
        limitations=(
            "Detector-local execution failed; this failure does not imply safe or benchmark miss.",
            detail,
        ),
        elapsed_seconds=elapsed,
        scope_files=0,
        scope_loc=0,
        failure_kind=failure_kind,
    )


def run_detector_jobs(
    jobs: Sequence[DetectorJob],
    timeout_seconds: float,
) -> Tuple[ProposedDetectorRun, ...]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be > 0")

    results = []
    ordered_jobs = sorted(jobs, key=lambda job: job.detector_id)
    for job in ordered_jobs:
        started = time.perf_counter()
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"detector-{job.detector_id}")
        future: Future[ProposedDetectorRun] = executor.submit(job.invoke)
        try:
            result = future.result(timeout=timeout_seconds)
            if not isinstance(result, ProposedDetectorRun):
                results.append(
                    _failure_run(
                        job,
                        "invalid_result",
                        time.perf_counter() - started,
                        "Detector returned a value that is not ProposedDetectorRun.",
                    )
                )
            elif result.detector_id != job.detector_id:
                results.append(
                    _failure_run(
                        job,
                        "identity_mismatch",
                        time.perf_counter() - started,
                        "Detector result identity does not match its job identity.",
                    )
                )
            else:
                results.append(result)
        except (TimeoutError, FutureTimeoutError):
            results.append(
                _failure_run(
                    job,
                    "timeout",
                    time.perf_counter() - started,
                    f"Detector exceeded its {timeout_seconds:.6f}s local budget.",
                )
            )
        except Exception as exc:
            results.append(
                _failure_run(
                    job,
                    "exception",
                    time.perf_counter() - started,
                    f"{type(exc).__name__}: {exc}",
                )
            )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
    return tuple(results)
