#!/usr/bin/env bash
set -u
cd "/mnt/e/网安/CyberSecurity-Innovation-Audit" || exit 125

run_step() {
  name="$1"
  shift
  printf '__A_NULL_START__ %s\n' "$name"
  "$@"
  code=$?
  printf '__A_NULL_END__ %s exit_code=%s\n' "$name" "$code"
}

run_step fixture_integrity .venv-web/bin/python research/tests/a_null_01/verify_fixtures.py --check
run_step targeted_null_detector .venv-web/bin/python -m unittest tests.detectors.test_cpp_null_dereference_detector -v
run_step combined_cpp_detectors .venv-web/bin/python -m unittest tests.detectors.test_cpp_lifetime_detector tests.detectors.test_cpp_shared_ptr_race_detector tests.detectors.test_cpp_null_dereference_detector -v
run_step project_wide .venv-web/bin/python -m unittest discover -s tests -q
