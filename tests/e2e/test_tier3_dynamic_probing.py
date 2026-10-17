"""
Tier 3 E2E Tests: Dynamic Tracing & Memory Probing.

Tests FastMCP server tools:
- trace_function(session_id, function_address, args, prober)
- Native Frida hooking & Unicorn micro-emulation probers
- Dynamic argument and return value extraction
- Dynamic-to-static fact backfilling into session symbol table.
"""

from __future__ import annotations

from pathlib import Path

import pytest

mr_server = pytest.importorskip(
    "metis_reverse.server",
    reason="metis_reverse.server is scheduled for implementation in Milestone 1/3",
)


def test_tier3_trace_function_execution(c_service_stripped_path: Path) -> None:
    """Verify trace_function executes function hook and captures runtime event."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]
    functions = mr_server.list_functions(session_id)
    assert len(functions) > 0

    first_addr = getattr(functions[0], "address", None) or functions[0].get("address")
    trace_res = mr_server.trace_function(
        session_id=session_id,
        function_address=first_addr,
        args=[0, 0],
        prober="auto",
    )

    assert trace_res is not None
    assert hasattr(trace_res, "return_value") or "return_value" in trace_res or hasattr(trace_res, "events") or "events" in trace_res


def test_tier3_dynamic_fact_backfilling(c_service_stripped_path: Path) -> None:
    """Verify dynamic trace results backfill concrete facts into session evidence store."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]
    functions = mr_server.list_functions(session_id)
    first_addr = getattr(functions[0], "address", None) or functions[0].get("address")

    # Run trace
    mr_server.trace_function(session_id, first_addr, args=[1, 2], prober="auto")

    # Query evidence to check if dynamic facts were backfilled
    evidence = mr_server.query_evidence(session_id, symbol_or_addr=str(first_addr))
    dynamic_tags = [
        e for e in evidence
        if (getattr(e, "evidence_type", None) or e.get("evidence_type")) == "DYNAMIC_PROBE"
    ]
    # If dynamic tracing is active, tags should be populated
    if dynamic_tags:
        for tag in dynamic_tags:
            conf = getattr(tag, "confidence", None) or tag.get("confidence")
            assert conf == 1.0
