"""
Pytest configuration and shared fixtures for Metis Reverse test suite.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = TESTS_DIR.parent.resolve()
SRC_DIR = PROJECT_ROOT / "src"

# Add src and tests to sys.path so imports work cleanly
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def benchmarks_dir() -> Path:
    return TESTS_DIR / "synthetic_benchmarks"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return TESTS_DIR / "fixtures"


@pytest.fixture(scope="session")
def c_service_stripped_path(benchmarks_dir: Path) -> Path:
    p = benchmarks_dir / "c_service" / "bin" / "c_service_stripped"
    assert p.exists(), f"Target binary not found: {p}. Run harness.py --compile first."
    return p


@pytest.fixture(scope="session")
def c_service_unstripped_path(benchmarks_dir: Path) -> Path:
    p = benchmarks_dir / "c_service" / "bin" / "c_service_unstripped"
    assert p.exists(), f"Target binary not found: {p}. Run harness.py --compile first."
    return p


@pytest.fixture(scope="session")
def c_service_vectors(benchmarks_dir: Path) -> list[dict]:
    vec_path = benchmarks_dir / "c_service" / "test_vectors.json"
    with open(vec_path, encoding="utf-8") as f:
        return json.load(f)["test_vectors"]


@pytest.fixture(scope="session")
def c_service_ground_truth_symbols(benchmarks_dir: Path) -> dict:
    sym_path = benchmarks_dir / "c_service" / "ground_truth_symbols.json"
    with open(sym_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def go_pipeline_stripped_path(benchmarks_dir: Path) -> Path:
    p = benchmarks_dir / "go_pipeline" / "bin" / "go_pipeline_stripped"
    assert p.exists(), f"Target binary not found: {p}. Run harness.py --compile first."
    return p


@pytest.fixture(scope="session")
def go_pipeline_unstripped_path(benchmarks_dir: Path) -> Path:
    p = benchmarks_dir / "go_pipeline" / "bin" / "go_pipeline_unstripped"
    assert p.exists(), f"Target binary not found: {p}. Run harness.py --compile first."
    return p


@pytest.fixture(scope="session")
def go_pipeline_vectors(benchmarks_dir: Path) -> list[dict]:
    vec_path = benchmarks_dir / "go_pipeline" / "test_vectors.json"
    with open(vec_path, encoding="utf-8") as f:
        return json.load(f)["test_vectors"]


@pytest.fixture(scope="session")
def go_pipeline_ground_truth_symbols(benchmarks_dir: Path) -> dict:
    sym_path = benchmarks_dir / "go_pipeline" / "ground_truth_symbols.json"
    with open(sym_path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def js_obfuscated_bundle_path(benchmarks_dir: Path) -> Path:
    p = benchmarks_dir / "js_obfuscated" / "dist" / "bundle.min.js"
    assert p.exists(), f"Obfuscated JS not found: {p}. Run harness.py --compile first."
    return p


@pytest.fixture(scope="session")
def js_clean_bundle_path(benchmarks_dir: Path) -> Path:
    p = benchmarks_dir / "js_obfuscated" / "dist" / "bundle.clean.js"
    assert p.exists(), f"Clean JS not found: {p}. Run harness.py --compile first."
    return p


@pytest.fixture(scope="session")
def js_vectors(benchmarks_dir: Path) -> list[dict]:
    vec_path = benchmarks_dir / "js_obfuscated" / "test_vectors.json"
    with open(vec_path, encoding="utf-8") as f:
        return json.load(f)["test_vectors"]


@pytest.fixture(scope="session")
def reconstructed_c_source(fixtures_dir: Path) -> str:
    src_file = fixtures_dir / "reconstructed_c_service.c"
    with open(src_file, encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="session")
def malformed_binary_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "malformed_binary.bin"
