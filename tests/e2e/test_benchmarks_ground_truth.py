"""
E2E Benchmark Ground Truth Verification Tests.

Verifies that all synthetic benchmarks (c_service, go_pipeline, js_obfuscated)
compile cleanly and execute with 100% ground-truth fidelity across all test vectors.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.synthetic_benchmarks.harness import (
    TARGETS,
    compile_target,
    get_target_executables,
    load_test_vectors,
    run_differential_comparison,
    verify_ground_truth,
)


@pytest.mark.parametrize("target", TARGETS)
def test_benchmark_compilation(target: str) -> None:
    """Verify each benchmark compiles successfully via its build system."""
    success = compile_target(target)
    assert success is True, f"Failed to compile benchmark target: {target}"


@pytest.mark.parametrize("target", TARGETS)
def test_ground_truth_execution_unstripped(target: str) -> None:
    """Verify all test vectors pass on unstripped reference binaries."""
    result = verify_ground_truth(target, variant="unstripped")
    assert result["all_passed"] is True, (
        f"Ground truth verification failed on unstripped {target}: "
        f"{result['passed']}/{result['total']} passed. Failures: {result['results']}"
    )


@pytest.mark.parametrize("target", TARGETS)
def test_ground_truth_execution_stripped(target: str) -> None:
    """Verify all test vectors pass on stripped/obfuscated target binaries."""
    result = verify_ground_truth(target, variant="stripped")
    assert result["all_passed"] is True, (
        f"Ground truth verification failed on stripped {target}: "
        f"{result['passed']}/{result['total']} passed. Failures: {result['results']}"
    )


@pytest.mark.parametrize("target", TARGETS)
def test_differential_equivalence_unstripped_vs_stripped(target: str) -> None:
    """Verify byte-for-byte behavioral equivalence between unstripped and stripped binaries."""
    executables = get_target_executables(target)
    vectors = load_test_vectors(target)

    report = run_differential_comparison(
        original_cmd=executables["unstripped"],
        reconstructed_cmd=executables["stripped"],
        vectors=vectors,
    )

    assert report["all_passed"] is True, (
        f"Differential mismatch between unstripped and stripped {target}: "
        f"{report['passed_vectors']}/{report['total_vectors']} passed ({report['equivalence_percentage']:.1f}%). "
        f"Diff details: {[r for r in report['results'] if not r['passed']]}"
    )
    assert report["equivalence_percentage"] == 100.0


def test_differential_comparison_detects_deliberate_divergence(
    c_service_unstripped_path: Path,
) -> None:
    """Verify differential harness correctly detects divergence when binaries differ."""
    # Test vector expecting exit code 0
    vector = {
        "vector_id": "DIVERGENCE_TEST",
        "cli_args": [],
        "stdin_data": "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "expected_exit_code": 0,
        "expected_stdout": "",
        "expected_stderr": "",
    }

    # Compare c_service against /bin/echo (which exits 0 but produces different stdout)
    report = run_differential_comparison(
        original_cmd=[str(c_service_unstripped_path)],
        reconstructed_cmd=["/bin/echo"],
        vectors=[vector],
    )

    assert report["all_passed"] is False
    assert report["results"][0]["stdout_matched"] is False
