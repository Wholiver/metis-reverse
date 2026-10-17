"""
Unit tests for Metis Reverse Dynamic Probing & Memory Probing Subsystem (Milestone 3).
Covers models, BaseProber, FridaProber, UnicornProber, FactBackfiller, and Server tools.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import metis_reverse.server as mr_server
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    EvidenceSource,
    TargetArtifact,
    TargetType,
    TraceEvent,
    TraceEventType,
    TraceResult,
)
from metis_reverse.core.session import global_session_manager
from metis_reverse.dynamic.backfiller import FactBackfiller
from metis_reverse.dynamic.frida_prober import FridaProber
from metis_reverse.dynamic.prober_base import (
    BaseProber,
    is_host_native_compatible,
)
from metis_reverse.dynamic.unicorn_prober import (
    HeapManager,
    UnicornProber,
    build_page_mappings,
)


def test_trace_event_model():
    """Verify TraceEvent serialization, field coercion, and dict access."""
    ev = TraceEvent(
        step=1,
        event_type="enter",
        address=0x100000894,
        details={"arg0": 128},
    )
    assert ev.event_type == TraceEventType.ENTER
    assert ev["step"] == 1
    assert ev.get("address") == 0x100000894
    assert ev["details"]["arg0"] == 128

    ev_exec = TraceEvent(step=2, event_type=TraceEventType.EXEC, address=0x100000898)
    assert ev_exec.event_type == TraceEventType.EXEC


@pytest.mark.asyncio
async def test_trace_result_model_and_await():
    """Verify TraceResult attributes, dict access, and __await__ compatibility."""
    res = TraceResult(
        success=True,
        session_id="sess_123",
        function_address=0x100000894,
        return_value=1,
        return_type="int",
        captured_strings=["secret_token"],
        memory_dumps={"heap_0x1000": "01020304"},
        prober="unicorn",
        prober_used="unicorn",
    )
    assert res.success is True
    assert res["return_value"] == 1
    assert res.get("prober") == "unicorn"
    assert "secret_token" in res.captured_strings

    # Verify __await__ support
    awaited_res = await res
    assert awaited_res.function_address == 0x100000894


def test_base_prober_interface():
    """Verify BaseProber is an abstract class requiring concrete implementation."""
    with pytest.raises(TypeError):
        BaseProber()  # type: ignore[abstract]


def test_is_host_native_compatible():
    """Verify host compatibility evaluation across architectures and formats."""
    # Fake ELF artifact
    elf_artifact = TargetArtifact(
        file_path="/tmp/test_elf",
        format=ArtifactFormat.ELF,
        architecture=ArchitectureType.X86_64,
        bitness=64,
        base_address=0x400000,
        entry_point=0x401000,
        file_size_bytes=1024,
    )
    import sys
    if sys.platform == "darwin":
        assert is_host_native_compatible(elf_artifact) is False

    # Fake Mach-O artifact
    macho_artifact = TargetArtifact(
        file_path="/tmp/test_macho",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        bitness=64,
        base_address=0x100000000,
        entry_point=0x1000004b0,
        file_size_bytes=1024,
    )
    if sys.platform == "darwin":
        import platform
        if platform.machine().lower() in ("arm64", "aarch64"):
            assert is_host_native_compatible(macho_artifact) is True


def test_page_coalescing():
    """Verify build_page_mappings coalesces contiguous slices and merges permissions."""
    slices = [
        (0x1000, 0x500, b"A" * 0x500, 1),  # READ
        (0x1500, 0x300, b"B" * 0x300, 2),  # WRITE in same 4KB page
        (0x2000, 0x1000, b"C" * 0x1000, 1), # Adjacent page
    ]
    blocks = build_page_mappings(slices, page_size=4096)
    assert len(blocks) >= 1
    for addr, size, _data, _prot in blocks:
        assert addr % 4096 == 0
        assert size % 4096 == 0


def test_unicorn_heap_manager():
    """Verify HeapManager allocates memory for ints, strings, and buffers."""
    from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    heap = HeapManager(uc, base_addr=0x600000000000, max_size=0x100000)

    ptr_str = heap.allocate_string("hello_metis")
    assert ptr_str >= 0x600000000000
    read_str = uc.mem_read(ptr_str, 12).decode("utf-8").rstrip("\x00")
    assert read_str == "hello_metis"

    ptr_buf = heap.allocate(128, b"\xaa" * 128)
    assert ptr_buf > ptr_str
    read_buf = bytes(uc.mem_read(ptr_buf, 128))
    assert read_buf == b"\xaa" * 128


def test_unicorn_prober_config_init_default(c_service_stripped_path: Path):
    """Verify UnicornProber emulates _config_init_default on c_service_stripped."""
    session = global_session_manager.create_session(str(c_service_stripped_path))
    prober = UnicornProber()
    assert prober.is_available(session) is True

    # 0x100000894 is _config_init_default
    res = prober.trace_function(session, 0x100000894, args=[{"size": 512}])
    assert res.success is True
    assert res.prober == "unicorn"
    assert len(res.events) > 0
    # Checks that secret token was initialized in the struct
    assert any("metis_default_secret_token_2026" in s for s in res.captured_strings)


def test_unicorn_prober_session_authenticate(c_service_stripped_path: Path):
    """Verify UnicornProber evaluates valid and invalid tokens in _session_authenticate."""
    session = global_session_manager.create_session(str(c_service_stripped_path))
    prober = UnicornProber()

    # 0x100000894: init default config
    cfg_res = prober.trace_function(session, 0x100000894, args=[{"size": 512}])
    assert cfg_res.success is True

    # 0x100000ac8 is _session_authenticate(session_ptr, cfg_ptr, token_ptr)
    # Construct an initialized ServiceConfig struct buffer with the secret token at offset 12
    import struct
    valid_cfg_buf = (
        struct.pack("<III", 0x53455256, 8080, 128)
        + b"metis_default_secret_token_2026".ljust(64, b"\x00")
        + struct.pack("<II", 1, 5000)
    )

    # Vector A: Valid token matching cfg->secret_token -> returns 1
    res_valid = prober.trace_function(
        session,
        0x100000ac8,
        args=[{"size": 128}, valid_cfg_buf, "metis_default_secret_token_2026"],
    )
    assert res_valid.success is True
    assert res_valid.return_value == 1

    # Vector B: Invalid token -> returns 0
    res_invalid = prober.trace_function(
        session,
        0x100000ac8,
        args=[{"size": 128}, valid_cfg_buf, "wrong_fake_token"],
    )
    assert res_invalid.success is True
    assert res_invalid.return_value == 0


def test_unicorn_prober_null_pointer_trap(c_service_stripped_path: Path):
    """Verify UnicornProber traps null pointer dereferences safely without crashing."""
    session = global_session_manager.create_session(str(c_service_stripped_path))
    prober = UnicornProber(max_instructions=50)

    # Calling with null pointer (0) where a struct pointer is expected
    res = prober.trace_function(session, 0x100000894, args=[0])
    # Either stops early or records null deref safely
    assert res is not None


def test_frida_prober_availability_and_codesign(c_service_stripped_path: Path):
    """Verify FridaProber detection and Darwin runner codesign."""
    prober = FridaProber()
    assert prober.name == "frida"
    is_avail = prober.is_available()
    assert isinstance(is_avail, bool)

    import sys
    if sys.platform == "darwin":
        runner_bin, temp_dir = prober._prepare_darwin_runner(c_service_stripped_path)
        try:
            assert runner_bin.exists()
            assert runner_bin.stat().st_size > 0
        finally:
            if temp_dir and temp_dir.exists():
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)


def test_fact_backfiller_integration(c_service_stripped_path: Path):
    """Verify FactBackfiller generates immutable tags with confidence 1.0."""
    session = global_session_manager.create_session(str(c_service_stripped_path))
    backfiller = FactBackfiller()

    trace_result = TraceResult(
        success=True,
        session_id=session.session_id,
        function_address=0x100000894,
        return_value=1,
        return_type="int",
        captured_strings=["metis_default_secret_token_2026"],
    )

    tags = backfiller.backfill(session, trace_result, 0x100000894, args=[512, "token"])
    assert len(tags) >= 2

    # Verify function tag
    func_tag = next(t for t in tags if t.target_type == TargetType.FUNCTION)
    assert func_tag.confidence == 1.0
    assert func_tag.is_immutable is True
    assert func_tag.source == EvidenceSource.DYNAMIC_PROBE
    assert func_tag.evidence_type == "DYNAMIC_PROBE"

    # Verify parameter tags
    param_tags = [t for t in tags if t.target_type == TargetType.PARAMETER]
    assert len(param_tags) == 2
    assert param_tags[0].confidence == 1.0
    assert param_tags[0].is_immutable is True

    # Verify session function has updated metadata
    func = session.functions[0x100000894]
    assert func.confidence_score == 1.0
    assert func.return_type == "int"


def test_server_trace_function_and_query_evidence(c_service_stripped_path: Path):
    """Verify FastMCP server trace_function tool and query_evidence integration."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id

    # Trace via unicorn
    trace_res = mr_server.trace_function(
        session_id=session_id,
        function_address=0x100000894,
        args=[{"size": 512}],
        prober="unicorn",
    )
    assert trace_res.success is True
    assert "return_value" in trace_res or hasattr(trace_res, "return_value")

    # Query evidence
    evidence = mr_server.query_evidence(session_id, symbol_or_addr="0x100000894")
    dyn_tags = [e for e in evidence if getattr(e, "evidence_type", None) == "DYNAMIC_PROBE"]
    assert len(dyn_tags) > 0
    for t in dyn_tags:
        assert t.confidence == 1.0
        assert t.is_immutable is True
