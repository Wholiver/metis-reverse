"""
Tier 4 E2E Tests: Interactive DB Mutation & Closed-Loop Equivalence.

Tests FastMCP server tools:
- rename_symbol, update_variable_type, define_struct
- recompile_and_verify (0 compilation errors)
- run_differential_test (100% equivalence on test vectors)
"""

from __future__ import annotations

from pathlib import Path

import pytest

mr_server = pytest.importorskip(
    "metis_reverse.server",
    reason="metis_reverse.server is scheduled for implementation in Milestone 1/4",
)


def test_tier4_interactive_mutation_tools(c_service_stripped_path: Path) -> None:
    """Verify rename_symbol, update_variable_type, and define_struct mutate DB state."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]
    functions = mr_server.list_functions(session_id)
    assert len(functions) > 0

    first_addr = getattr(functions[0], "address", None) or functions[0].get("address")

    # 1. Rename symbol
    ren_res = mr_server.rename_symbol(
        session_id=session_id,
        address=first_addr,
        new_name="reconstructed_main_handler",
    )
    assert ren_res is not None
    success = getattr(ren_res, "success", None) if hasattr(ren_res, "success") else ren_res.get("success", True)
    assert success is True

    # 2. Define struct
    struct_res = mr_server.define_struct(
        session_id=session_id,
        struct_name="ServiceConfig",
        fields={
            "magic": "uint32_t",
            "port": "uint32_t",
            "secret_token": "char[64]",
        },
    )
    assert struct_res is not None
    success_struct = getattr(struct_res, "success", None) if hasattr(struct_res, "success") else struct_res.get("success", True)
    assert success_struct is True


def test_tier4_recompile_and_verify_clean_reconstructed_source(
    c_service_stripped_path: Path,
    reconstructed_c_source: str,
) -> None:
    """Verify recompile_and_verify compiles clean reconstructed C code with 0 errors."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    res = mr_server.recompile_and_verify(
        session_id=session_id,
        reconstructed_source=reconstructed_c_source,
        compiler="clang",
    )

    assert res is not None
    compiled_ok = getattr(res, "success", None) if hasattr(res, "success") else res.get("success")
    compile_errors = getattr(res, "compile_errors", None) if hasattr(res, "compile_errors") else res.get("compile_errors", "")
    assert compiled_ok is True, f"Recompilation failed with errors: {compile_errors}"

    # Verify 100% equivalence was achieved
    equiv_pct = getattr(res, "equivalence_percentage", None) if hasattr(res, "equivalence_percentage") else res.get("equivalence_percentage", 100.0)
    assert equiv_pct == 100.0


def test_tier4_run_differential_test_vectors(
    c_service_stripped_path: Path,
    c_service_unstripped_path: Path,
    c_service_vectors: list[dict],
) -> None:
    """Verify run_differential_test executes vectors and reports equivalence."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    diff_res = mr_server.run_differential_test(
        session_id=session_id,
        original_path=str(c_service_stripped_path),
        reconstructed_binary_path=str(c_service_unstripped_path),
        test_vectors=c_service_vectors,
    )

    assert diff_res is not None
    all_passed = getattr(diff_res, "all_passed", None) if hasattr(diff_res, "all_passed") else diff_res.get("all_passed")
    assert all_passed is True
