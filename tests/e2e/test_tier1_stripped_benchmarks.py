"""
Tier 1 E2E Empirical Verification on Real Stripped Benchmarks.

Adversarial validation covering:
1. c_service_stripped & go_pipeline_stripped parsing via LIEF (__text, __stubs, arch, entry point).
2. Capstone linear sweep disassembly at entry point & stubs without TypeErrors.
3. Angr whole-binary CFG, function-level CFG, and C pseudocode decompilation.
4. Session lifecycle: resource purge, handle closure, and double-close idempotency.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

from metis_reverse.core.models import SectionPermission
from metis_reverse.core.session import global_session_manager

mr_server = pytest.importorskip(
    "metis_reverse.server",
    reason="metis_reverse.server required for Tier 1 tests",
)

# ============================================================================
# C Service Stripped Benchmark Tests
# ============================================================================

def test_c_service_stripped_lief_parsing(c_service_stripped_path: Path) -> None:
    """Verify LIEF parses Mach-O headers, sections, arch, and entry point for c_service_stripped."""
    res = mr_server.open_session(str(c_service_stripped_path), backend="tier1_native")
    sid = res.session_id
    try:
        assert res.format == "MACHO"
        assert res.architecture == "arm64"
        assert res.bitness == 64
        assert res.entry_point == "0x1000004b0"

        artifact = res.artifact
        assert artifact is not None
        sec_dict = {sec.name: sec for sec in artifact.sections}

        # Verify critical executable and stub sections
        assert "__text" in sec_dict, f"Missing __text in sections: {list(sec_dict.keys())}"
        assert "__stubs" in sec_dict, f"Missing __stubs in sections: {list(sec_dict.keys())}"

        text_sec = sec_dict["__text"]
        assert text_sec.virtual_address == 0x1000004b0
        assert SectionPermission.READ in text_sec.permissions
        assert SectionPermission.EXECUTE in text_sec.permissions

        stubs_sec = sec_dict["__stubs"]
        assert SectionPermission.READ in stubs_sec.permissions
        assert SectionPermission.EXECUTE in stubs_sec.permissions
    finally:
        mr_server.close_session(sid)


def test_c_service_stripped_capstone_disassembly(c_service_stripped_path: Path) -> None:
    """Verify Capstone disassembles at entry point and stubs without TypeErrors."""
    res = mr_server.open_session(str(c_service_stripped_path), backend="tier1_native")
    sid = res.session_id
    try:
        ep = int(res.entry_point, 16)
        insns = mr_server.disassemble_range(sid, ep, size=32)
        assert len(insns) == 8, f"Expected 8 ARM64 instructions in 32 bytes, got {len(insns)}"

        for ins in insns:
            assert isinstance(ins.address, int)
            assert isinstance(ins.mnemonic, str) and len(ins.mnemonic) > 0
            assert isinstance(ins.raw_bytes, (bytes, bytearray))
            assert len(ins.raw_bytes) == 4  # ARM64 fixed instruction size

        # Disassemble stubs section
        stubs_sec = [s for s in res.artifact.sections if s.name == "__stubs"][0]
        stub_insns = mr_server.disassemble_range(sid, stubs_sec.virtual_address, size=32)
        assert len(stub_insns) > 0
        assert stub_insns[0].mnemonic in ("adrp", "ldr", "nop")
    finally:
        mr_server.close_session(sid)


def test_c_service_stripped_angr_cfg_and_decompilation(c_service_stripped_path: Path) -> None:
    """Verify Angr generates CFG nodes and decompiles functions for c_service_stripped."""
    res = mr_server.open_session(str(c_service_stripped_path), backend="tier1_native")
    sid = res.session_id
    try:
        ep = int(res.entry_point, 16)

        # 1. Whole-binary CFG
        cfg_all = mr_server.get_cfg(sid)
        nodes = cfg_all.get("nodes", [])
        assert len(nodes) >= 100, f"Expected >= 100 CFG nodes, got {len(nodes)}"

        # 2. Function-specific CFG
        cfg_fn = mr_server.get_cfg(sid, function_address=ep)
        fn_nodes = cfg_fn.get("nodes", [])
        fn_edges = cfg_fn.get("edges", [])
        assert len(fn_nodes) > 0, "Expected function CFG to contain nodes"
        assert len(fn_edges) > 0, "Expected function CFG to contain edges"

        # 3. Decompilation
        dec = mr_server.decompile(sid, ep)
        assert dec is not None
        assert dec.language.upper() == "C"
        assert dec.source_code is not None and len(dec.source_code) > 0
        assert "_start" in dec.source_code or "sub_" in dec.source_code
    finally:
        mr_server.close_session(sid)


def test_c_service_stripped_lifecycle_and_resource_release(c_service_stripped_path: Path) -> None:
    """Verify session closure purges backend references, releases handles, and rejects post-close calls."""
    res = mr_server.open_session(str(c_service_stripped_path), backend="tier1_native")
    sid = res.session_id
    backend = global_session_manager.get_backend(sid)
    assert backend is not None

    # Load Angr to instantiate project & CFG
    ep = int(res.entry_point, 16)
    mr_server.decompile(sid, ep)
    assert backend._decompiler is not None
    assert backend._decompiler._project is not None

    # Close session
    close_res = mr_server.close_session(sid)
    assert close_res.closed is True
    assert sid not in global_session_manager._sessions
    assert sid not in global_session_manager._backends
    assert backend._decompiler is None
    assert backend._disassembler is None

    # Idempotent close
    close_again = mr_server.close_session(sid)
    assert close_again.closed is False

    # Tool calls must be rejected
    with pytest.raises(ToolError):
        mr_server.list_functions(sid)

    with pytest.raises(ToolError):
        mr_server.disassemble_range(sid, ep, 16)


# ============================================================================
# Go Pipeline Stripped Benchmark Tests
# ============================================================================

def test_go_pipeline_stripped_lief_parsing(go_pipeline_stripped_path: Path) -> None:
    """Verify LIEF parses Mach-O headers, sections, arch, and entry point for go_pipeline_stripped."""
    res = mr_server.open_session(str(go_pipeline_stripped_path), backend="tier1_native")
    sid = res.session_id
    try:
        assert res.format == "MACHO"
        assert res.architecture == "arm64"
        assert res.bitness == 64
        assert res.entry_point == "0x10007b550"

        artifact = res.artifact
        assert artifact is not None
        sec_names = [s.name for s in artifact.sections]

        assert "__text" in sec_names, f"Missing __text in Go sections: {sec_names}"
        # Go Darwin binaries use __symbol_stub1 for stub linkage
        assert "__symbol_stub1" in sec_names, f"Missing stub section in Go: {sec_names}"
        assert "__gopclntab" in sec_names, f"Missing __gopclntab in Go: {sec_names}"

        text_sec = [s for s in artifact.sections if s.name == "__text"][0]
        assert SectionPermission.READ in text_sec.permissions
        assert SectionPermission.EXECUTE in text_sec.permissions
    finally:
        mr_server.close_session(sid)


def test_go_pipeline_stripped_capstone_disassembly(go_pipeline_stripped_path: Path) -> None:
    """Verify Capstone disassembles Go entry point and stub section without TypeErrors."""
    res = mr_server.open_session(str(go_pipeline_stripped_path), backend="tier1_native")
    sid = res.session_id
    try:
        ep = int(res.entry_point, 16)
        insns = mr_server.disassemble_range(sid, ep, size=32)
        assert len(insns) == 8, f"Expected 8 ARM64 instructions, got {len(insns)}"
        assert insns[0].mnemonic == "b"  # Branch to runtime.rt0_go

        # Disassemble Go stub section
        stub_sec = [s for s in res.artifact.sections if s.name == "__symbol_stub1"][0]
        stub_insns = mr_server.disassemble_range(sid, stub_sec.virtual_address, size=32)
        assert len(stub_insns) > 0
        assert stub_insns[0].mnemonic in ("adrp", "ldr", "nop")
    finally:
        mr_server.close_session(sid)


def test_go_pipeline_stripped_angr_cfg_and_decompilation(go_pipeline_stripped_path: Path) -> None:
    """Verify Angr generates CFG nodes and decompiles entry routine for go_pipeline_stripped."""
    res = mr_server.open_session(str(go_pipeline_stripped_path), backend="tier1_native")
    sid = res.session_id
    try:
        ep = int(res.entry_point, 16)

        # 1. Whole-binary CFG
        cfg_all = mr_server.get_cfg(sid)
        nodes = cfg_all.get("nodes", [])
        assert len(nodes) >= 1000, f"Expected >= 1000 CFG nodes in Go binary, got {len(nodes)}"

        # 2. Decompilation of runtime entry point
        dec = mr_server.decompile(sid, ep)
        assert dec is not None
        assert dec.language.upper() == "C"
        assert dec.source_code is not None and len(dec.source_code) > 0
        assert "rt0" in dec.source_code or "sub_" in dec.source_code
    finally:
        mr_server.close_session(sid)


def test_go_pipeline_stripped_lifecycle_and_resource_release(go_pipeline_stripped_path: Path) -> None:
    """Verify session closure purges Go binary backend references."""
    res = mr_server.open_session(str(go_pipeline_stripped_path), backend="tier1_native")
    sid = res.session_id
    backend = global_session_manager.get_backend(sid)

    # Trigger CFG to allocate Angr memory
    mr_server.get_cfg(sid)

    # Close session
    close_res = mr_server.close_session(sid)
    assert close_res.closed is True
    assert sid not in global_session_manager._sessions
    assert sid not in global_session_manager._backends
    assert backend._decompiler is None
