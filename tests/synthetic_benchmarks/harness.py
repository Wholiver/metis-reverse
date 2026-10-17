#!/usr/bin/env python3
"""
Metis Reverse - Synthetic Benchmarks Test Harness

Compiles benchmark targets, runs test vectors, verifies ground truth execution,
and provides differential testing comparison functions between original stripped
binaries and reconstructed code.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

BENCHMARKS_ROOT = Path(__file__).parent.resolve()
PROJECT_ROOT = BENCHMARKS_ROOT.parent.parent.resolve()

TARGETS = ["c_service", "go_pipeline", "js_obfuscated"]


def compile_target(target: str) -> bool:
    """Compile a specific benchmark target using its Makefile / build script."""
    target_dir = BENCHMARKS_ROOT / target
    if not target_dir.exists():
        raise FileNotFoundError(f"Benchmark target directory not found: {target_dir}")

    cmd = ["make", "-C", str(target_dir)]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"[ERROR] Failed to build {target}: {proc.stderr}", file=sys.stderr)
        return False
    return True


def compile_all() -> bool:
    """Compile all benchmark targets."""
    all_ok = True
    for target in TARGETS:
        ok = compile_target(target)
        if not ok:
            all_ok = False
    return all_ok


def get_target_executables(target: str) -> dict[str, list[str]]:
    """Return command invocations for unstripped and stripped variants."""
    target_dir = BENCHMARKS_ROOT / target
    if target == "c_service":
        return {
            "unstripped": [str(target_dir / "bin" / "c_service_unstripped")],
            "stripped": [str(target_dir / "bin" / "c_service_stripped")],
        }
    elif target == "go_pipeline":
        return {
            "unstripped": [str(target_dir / "bin" / "go_pipeline_unstripped")],
            "stripped": [str(target_dir / "bin" / "go_pipeline_stripped")],
        }
    elif target == "js_obfuscated":
        return {
            "unstripped": ["node", str(target_dir / "dist" / "bundle.clean.js")],
            "stripped": ["node", str(target_dir / "dist" / "bundle.min.js")],
        }
    else:
        raise ValueError(f"Unknown target: {target}")


def load_test_vectors(target: str) -> list[dict[str, Any]]:
    """Load test vectors from JSON specification."""
    vectors_file = BENCHMARKS_ROOT / target / "test_vectors.json"
    if not vectors_file.exists():
        raise FileNotFoundError(f"Vectors file not found: {vectors_file}")
    with open(vectors_file, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("test_vectors", [])


def run_single_vector(
    cmd_prefix: list[str],
    vector: dict[str, Any],
    timeout_sec: float = 5.0,
) -> tuple[int, str, str]:
    """Execute a single test vector against an executable command."""
    cli_args = vector.get("cli_args", [])
    stdin_data = vector.get("stdin_data", "")
    env_vars = vector.get("env_vars", {})

    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    full_cmd = cmd_prefix + cli_args
    proc = subprocess.run(
        full_cmd,
        check=False,
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_differential_comparison(
    original_cmd: list[str],
    reconstructed_cmd: list[str],
    vectors: list[dict[str, Any]],
    sanitize_pattern: str | None = None,
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    """
    Run black-box differential testing between original binary and reconstructed binary.
    Enforces exact exit code match and byte-for-byte or sanitized stdout/stderr equivalence.
    """
    results: list[dict[str, Any]] = []
    passed_count = 0

    for vec in vectors:
        vid = vec.get("vector_id", "unknown")
        orig_rc, orig_out, orig_err = run_single_vector(original_cmd, vec, timeout_sec)
        rec_rc, rec_out, rec_err = run_single_vector(reconstructed_cmd, vec, timeout_sec)

        if sanitize_pattern:
            orig_out = re.sub(sanitize_pattern, "<MASKED>", orig_out)
            rec_out = re.sub(sanitize_pattern, "<MASKED>", rec_out)
            orig_err = re.sub(sanitize_pattern, "<MASKED>", orig_err)
            rec_err = re.sub(sanitize_pattern, "<MASKED>", rec_err)

        rc_match = orig_rc == rec_rc
        out_match = orig_out == rec_out
        err_match = orig_err == rec_err
        passed = rc_match and out_match and err_match

        if passed:
            passed_count += 1

        results.append(
            {
                "vector_id": vid,
                "passed": passed,
                "original_exit_code": orig_rc,
                "reconstructed_exit_code": rec_rc,
                "exit_code_matched": rc_match,
                "stdout_matched": out_match,
                "stderr_matched": err_match,
                "stdout_diff": None if out_match else f"Orig: {orig_out[:200]} vs Rec: {rec_out[:200]}",
                "stderr_diff": None if err_match else f"Orig: {orig_err[:200]} vs Rec: {rec_err[:200]}",
            }
        )

    total = len(vectors)
    pct = (passed_count / total * 100.0) if total > 0 else 0.0

    return {
        "total_vectors": total,
        "passed_vectors": passed_count,
        "equivalence_percentage": pct,
        "all_passed": passed_count == total,
        "results": results,
    }


def verify_ground_truth(target: str, variant: str = "stripped") -> dict[str, Any]:
    """Verify that a target's unstripped or stripped binary matches its test vectors."""
    executables = get_target_executables(target)
    cmd = executables[variant]
    vectors = load_test_vectors(target)

    results = []
    passed_count = 0

    for vec in vectors:
        vid = vec["vector_id"]
        exp_rc = vec["expected_exit_code"]
        exp_out = vec["expected_stdout"]
        exp_err = vec["expected_stderr"]

        rc, out, err = run_single_vector(cmd, vec)

        rc_match = rc == exp_rc
        out_match = out == exp_out
        err_match = err == exp_err
        passed = rc_match and out_match and err_match

        if passed:
            passed_count += 1

        results.append(
            {
                "vector_id": vid,
                "passed": passed,
                "exit_code": rc,
                "expected_exit_code": exp_rc,
                "stdout_match": out_match,
                "stderr_match": err_match,
            }
        )

    total = len(vectors)
    return {
        "target": target,
        "variant": variant,
        "total": total,
        "passed": passed_count,
        "all_passed": passed_count == total,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Metis Reverse Synthetic Benchmarks Test Harness")
    parser.add_argument("--compile", action="store_true", help="Compile benchmark binaries")
    parser.add_argument("--verify", action="store_true", help="Verify ground truth execution")
    parser.add_argument("--target", choices=TARGETS + ["all"], default="all", help="Target benchmark")
    args = parser.parse_args()

    targets_to_run = TARGETS if args.target == "all" else [args.target]

    if args.compile:
        print("[HARNESS] Compiling benchmark targets...")
        for tgt in targets_to_run:
            ok = compile_target(tgt)
            if ok:
                print(f"  [✓] {tgt} compiled successfully")
            else:
                print(f"  [✗] {tgt} compilation failed")
                return 1

    if args.verify or (not args.compile and not args.verify):
        print("\n[HARNESS] Verifying ground truth execution against stripped binaries...")
        overall_ok = True
        for tgt in targets_to_run:
            res_stripped = verify_ground_truth(tgt, variant="stripped")
            res_unstripped = verify_ground_truth(tgt, variant="unstripped")

            status = "✓" if (res_stripped["all_passed"] and res_unstripped["all_passed"]) else "✗"
            print(
                f"  [{status}] {tgt}: "
                f"stripped {res_stripped['passed']}/{res_stripped['total']} passed, "
                f"unstripped {res_unstripped['passed']}/{res_unstripped['total']} passed"
            )

            if not (res_stripped["all_passed"] and res_unstripped["all_passed"]):
                overall_ok = False
                for r in res_stripped["results"]:
                    if not r["passed"]:
                        print(f"      Failure in stripped {r['vector_id']}: rc={r['exit_code']}(exp {r['expected_exit_code']}), out_match={r['stdout_match']}, err_match={r['stderr_match']}")

        if not overall_ok:
            print("\n[HARNESS] Ground truth verification FAILED")
            return 1
        print("\n[HARNESS] Ground truth verification 100% PASSED for all targets!")

    return 0


try:
    import pytest

    @pytest.mark.parametrize("target", TARGETS)
    def test_benchmark_stripped_ground_truth(target: str) -> None:
        """Verify stripped binary satisfies all test vectors."""
        res = verify_ground_truth(target, variant="stripped")
        assert res["all_passed"], f"Ground truth failed for {target} (stripped): {res}"

    @pytest.mark.parametrize("target", TARGETS)
    def test_benchmark_unstripped_ground_truth(target: str) -> None:
        """Verify unstripped binary satisfies all test vectors."""
        res = verify_ground_truth(target, variant="unstripped")
        assert res["all_passed"], f"Ground truth failed for {target} (unstripped): {res}"
except ImportError:
    pass


if __name__ == "__main__":
    sys.exit(main())
