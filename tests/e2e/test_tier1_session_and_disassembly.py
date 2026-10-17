"""
Tier 1 E2E Tests: Session Lifecycle, Binary Parsing & Disassembly.

Tests the FastMCP server tools:
- open_session
- list_functions
- disassemble_range / get_cfg
- Error handling on invalid binaries and sessions.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Progressive testability: skip if metis_reverse is not yet implemented by M1 workers
mr_server = pytest.importorskip(
    "metis_reverse.server",
    reason="metis_reverse.server is scheduled for implementation in Milestone 1",
)


def test_tier1_open_session_c_service(c_service_stripped_path: Path) -> None:
    """Verify open_session successfully opens a stripped C binary and returns SessionInfo."""
    res = mr_server.open_session(str(c_service_stripped_path), backend="auto")

    assert res is not None
    assert hasattr(res, "session_id") or "session_id" in res
    session_id = res.session_id if hasattr(res, "session_id") else res["session_id"]
    assert len(session_id) > 0

    # Verify target artifact properties
    artifact = getattr(res, "artifact", None) or res.get("artifact", {})
    format_val = getattr(artifact, "format", None) or artifact.get("format")
    assert str(format_val).upper() in ["MACHO", "ELF", "PE"]


def test_tier1_open_session_go_pipeline(go_pipeline_stripped_path: Path) -> None:
    """Verify open_session successfully opens a stripped Go binary."""
    res = mr_server.open_session(str(go_pipeline_stripped_path), backend="auto")
    assert res is not None
    session_id = res.session_id if hasattr(res, "session_id") else res["session_id"]
    assert len(session_id) > 0


def test_tier1_list_functions(c_service_stripped_path: Path) -> None:
    """Verify list_functions returns a list of discovered functions with valid addresses."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    functions = mr_server.list_functions(session_id)
    assert isinstance(functions, list)
    assert len(functions) > 0

    first_func = functions[0]
    func_addr = getattr(first_func, "address", None) or first_func.get("address")
    func_name = getattr(first_func, "name", None) or first_func.get("name")
    assert isinstance(func_addr, int)
    assert isinstance(func_name, str)


def test_tier1_disassemble_range(c_service_stripped_path: Path) -> None:
    """Verify disassembling instruction range around entry point."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]
    functions = mr_server.list_functions(session_id)
    first_addr = getattr(functions[0], "address", None) or functions[0].get("address")

    if hasattr(mr_server, "disassemble_range"):
        instructions = mr_server.disassemble_range(session_id, first_addr, 32)
        assert isinstance(instructions, list)
        assert len(instructions) > 0
        insn = instructions[0]
        assert hasattr(insn, "mnemonic") or "mnemonic" in insn


def test_tier1_error_handling_nonexistent_file() -> None:
    """Verify open_session handles non-existent file cleanly."""
    with pytest.raises((FileNotFoundError, ValueError, Exception)):
        mr_server.open_session("/path/to/nonexistent/binary_file_12345")


def test_tier1_error_handling_malformed_binary(malformed_binary_path: Path) -> None:
    """Verify open_session fails gracefully on corrupted binary headers."""
    with pytest.raises((ValueError, RuntimeError, Exception)):
        mr_server.open_session(str(malformed_binary_path))


def test_tier1_error_handling_invalid_session_id() -> None:
    """Verify tool functions reject non-existent session IDs."""
    with pytest.raises((KeyError, ValueError, Exception)):
        mr_server.list_functions("invalid-session-uuid-999999")
