#!/usr/bin/env python3
"""
Metis Reverse - Empirical Verification Script for Tier 1 Native Backend.
Validates processing of real stripped benchmarks:
- tests/synthetic_benchmarks/c_service/bin/c_service_stripped
- tests/synthetic_benchmarks/go_pipeline/bin/go_pipeline_stripped
"""

from __future__ import annotations

import gc
import os
import sys
from pathlib import Path

import psutil
from fastmcp.exceptions import ToolError

from metis_reverse.core.session import global_session_manager
from metis_reverse.server import (
    close_session,
    decompile,
    disassemble_range,
    get_cfg,
    open_session,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def test_target(target_name: str, rel_path: str, expected_ep: str, expected_stubs_name: str):
    print(f"\n{'='*70}")
    print(f"VERIFYING TARGET: {target_name} ({rel_path})")
    print(f"{'='*70}")

    bin_path = str(PROJECT_ROOT / rel_path)
    assert os.path.exists(bin_path), f"File not found: {bin_path}"

    proc = psutil.Process()
    gc.collect()
    mem_before = proc.memory_info().rss / (1024 * 1024)

    # 1. open_session: LIEF parsing
    print("\n[1] Testing open_session & LIEF binary parser...")
    session_info = open_session(bin_path, backend="tier1_native")
    sid = session_info.session_id
    print(f"  -> Session ID: {sid}")
    print(f"  -> Format: {session_info.format}")
    print(f"  -> Architecture: {session_info.architecture} ({session_info.bitness}-bit)")
    print(f"  -> Entry Point: {session_info.entry_point}")

    assert session_info.format == "MACHO", f"Expected MACHO, got {session_info.format}"
    assert session_info.architecture == "arm64", f"Expected arm64, got {session_info.architecture}"
    assert session_info.entry_point.lower() == expected_ep.lower(), f"Expected {expected_ep}, got {session_info.entry_point}"

    artifact = session_info.artifact
    assert artifact is not None, "TargetArtifact is None"
    sec_names = [s.name for s in artifact.sections]
    print(f"  -> Total Sections: {len(artifact.sections)}")
    print(f"  -> Sections: {sec_names}")

    assert "__text" in sec_names, f"Expected __text in sections: {sec_names}"
    assert expected_stubs_name in sec_names, f"Expected {expected_stubs_name} in sections: {sec_names}"

    text_sec = [s for s in artifact.sections if s.name == "__text"][0]
    stubs_sec = [s for s in artifact.sections if s.name == expected_stubs_name][0]
    perms_text = [p.name for p in text_sec.permissions]
    perms_stubs = [p.name for p in stubs_sec.permissions]
    print(f"  -> __text: VA=0x{text_sec.virtual_address:x}, Size=0x{text_sec.virtual_size:x}, Perms={perms_text}")
    print(f"  -> {expected_stubs_name}: VA=0x{stubs_sec.virtual_address:x}, Size=0x{stubs_sec.virtual_size:x}, Perms={perms_stubs}")
    assert "READ" in perms_text and "EXECUTE" in perms_text
    assert "READ" in perms_stubs and "EXECUTE" in perms_stubs

    # 2. disassemble_range: Capstone disassembly
    print("\n[2] Testing disassemble_range & Capstone disassembler...")
    ep_int = int(session_info.entry_point, 16)
    insns_ep = disassemble_range(sid, ep_int, size=32)
    print(f"  -> Disassembled {len(insns_ep)} instructions at entry point 0x{ep_int:x}:")
    for ins in insns_ep[:4]:
        print(f"     0x{ins.address:x}: {ins.mnemonic:8} {ins.operands}")
    assert len(insns_ep) > 0, "No instructions decoded at entry point"

    insns_stubs = disassemble_range(sid, stubs_sec.virtual_address, size=32)
    print(f"  -> Disassembled {len(insns_stubs)} instructions at stubs VA 0x{stubs_sec.virtual_address:x}:")
    for ins in insns_stubs[:4]:
        print(f"     0x{ins.address:x}: {ins.mnemonic:8} {ins.operands}")
    assert len(insns_stubs) > 0, "No instructions decoded at stubs VA"

    # 3. get_cfg & decompile: Angr CFG & Decompilation
    print("\n[3] Testing get_cfg and decompile via Angr engine...")
    cfg = get_cfg(sid)
    nodes = cfg.get("nodes", [])
    edges = cfg.get("edges", [])
    print(f"  -> Whole-binary CFG: {len(nodes)} nodes, {len(edges)} edges")
    assert len(nodes) > 0, "CFG returned 0 nodes"

    func_cfg = get_cfg(sid, function_address=ep_int)
    fn_nodes = func_cfg.get("nodes", [])
    fn_edges = func_cfg.get("edges", [])
    print(f"  -> Function CFG (0x{ep_int:x}): {len(fn_nodes)} nodes, {len(fn_edges)} edges")
    assert len(fn_nodes) > 0, "Function CFG returned 0 nodes"

    print(f"  -> Decompiling function at entry point 0x{ep_int:x}...")
    dec_result = decompile(sid, ep_int)
    print(f"  -> Decompilation success! Language: {dec_result.language}")
    print("  -> Source preview (first 5 lines):")
    for line in dec_result.source_code.strip().splitlines()[:5]:
        print(f"     | {line}")
    assert dec_result.source_code and len(dec_result.source_code) > 0

    # 4. close_session: Resource and file handle release
    print("\n[4] Testing close_session & resource cleanup...")
    backend = global_session_manager.get_backend(sid)
    assert backend is not None
    assert backend._decompiler is not None

    close_res = close_session(sid)
    print(f"  -> close_session returned: closed={close_res.closed}")
    assert close_res.closed is True
    assert sid not in global_session_manager._sessions
    assert sid not in global_session_manager._backends
    assert backend._decompiler is None
    assert backend._disassembler is None

    # Verify calls on closed session fail
    try:
        disassemble_range(sid, ep_int, 16)
        raise AssertionError("Should have raised ToolError on closed session")
    except ToolError:
        print("  -> Post-close disassemble_range correctly rejected with ToolError.")

    # Second close must return False
    close_res_2 = close_session(sid)
    assert close_res_2.closed is False
    print("  -> Idempotent second close_session correctly returned closed=False.")

    gc.collect()
    mem_after = proc.memory_info().rss / (1024 * 1024)
    print(f"  -> Memory: before={mem_before:.2f} MB, after session close & GC={mem_after:.2f} MB")
    print(f"  -> VERDICT for {target_name}: PASS")


def main():
    print("Metis Reverse - Empirical Challenger Verification Harness")
    print(f"Python: {sys.version}")

    # Target 1: C Service Stripped
    test_target(
        target_name="C Service (Stripped Mach-O)",
        rel_path="tests/synthetic_benchmarks/c_service/bin/c_service_stripped",
        expected_ep="0x1000004b0",
        expected_stubs_name="__stubs",
    )

    # Target 2: Go Pipeline Stripped
    test_target(
        target_name="Go Pipeline (Stripped Mach-O)",
        rel_path="tests/synthetic_benchmarks/go_pipeline/bin/go_pipeline_stripped",
        expected_ep="0x10007b550",
        expected_stubs_name="__symbol_stub1",
    )

    print("\n" + "="*70)
    print("ALL EMPIRICAL TESTS PASSED SUCCESSFULLY!")
    print("="*70)


if __name__ == "__main__":
    main()
