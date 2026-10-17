"""
Challenger M3-R2-2: Deep Adversarial Stress & Verification Harness
==================================================================
Milestone 3: Dynamic Tracing & Memory Probing (Frida, Unicorn, Backfill, trace_function).

Target Verification Foci:
1. Auto-dispatch logic & Foreign Architecture Compatibility:
   - Host compatibility detection for MACHO, ELF, PE, WASM across ARM64 and x86_64.
   - Frida graceful fallback to Unicorn on foreign binaries.
   - Runtime crash/failure in Frida fallback to Unicorn.
   - Clean ToolError raising for unsupported architectures.
2. FastMCP tool `trace_function` parameter validation & boundary stress:
   - Invalid session IDs (missing, empty, non-existent).
   - Address normalization (int, hex string, uppercase, decimal string, negative, malformed).
   - Prober parameter sanitization (whitespace, case-insensitivity, unknown prober names).
   - Timeout and instruction limit halting behavior.
   - Adversarial argument types (None, empty, large buffers, extreme integers, dicts).
3. `FactBackfiller` and `EvidenceStore` Immutability:
   - Confidence 1.0 and is_immutable=True enforcement on function, parameter, and string tags.
   - Direct EvidenceStore add_tag and delete_tag blocking with ImmutableEvidenceError.
   - rename_symbol strictly blocked via int and hex string addresses.
   - Function metadata lock and synthesized stripped function protection.
4. Concurrency & Contention Stress:
   - High-concurrency tracing on identical function (20 threads).
   - Concurrent tracing across different functions (15 threads).
   - Race condition between trace_function backfill and rename_symbol mutation.
   - Rapid back-to-back repeated trace executions (no memory exhaustion or deadlocks).
"""

from __future__ import annotations

import concurrent.futures
import platform
import struct
import sys
import threading
from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

import metis_reverse.server as mr_server
from metis_reverse.core.evidence import EvidenceStore, ImmutableEvidenceError
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySection,
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    SectionPermission,
    TargetArtifact,
    TraceResult,
)
from metis_reverse.core.session import global_session_manager
from metis_reverse.dynamic.frida_prober import FridaProber
from metis_reverse.dynamic.prober_base import (
    ArchitectureCompatibilityError,
    is_host_native_compatible,
)

# ============================================================================
# Helpers
# ============================================================================

def make_test_artifact(
    file_path: str = "/tmp/fake_bin",
    fmt: str | ArtifactFormat = ArtifactFormat.ELF,
    arch: str | ArchitectureType = ArchitectureType.X86_64,
    bitness: int = 64,
) -> TargetArtifact:
    return TargetArtifact(
        file_path=file_path,
        format=fmt,
        architecture=arch,
        bitness=bitness,
        base_address=0x400000,
        entry_point=0x401000,
        file_size_bytes=4096,
        sections=[
            BinarySection(
                name=".text",
                virtual_address=0x401000,
                virtual_size=0x1000,
                raw_offset=0x1000,
                raw_size=0x1000,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
            ),
            BinarySection(
                name=".data",
                virtual_address=0x402000,
                virtual_size=0x1000,
                raw_offset=0x2000,
                raw_size=0x1000,
                permissions=[SectionPermission.READ, SectionPermission.WRITE],
            ),
        ],
    )


def make_test_session(artifact: TargetArtifact, session_id: str = "r2_2_test_sess") -> BinarySession:
    store = EvidenceStore()
    sess = BinarySession(
        session_id=session_id,
        artifact=artifact,
        backend_type="mock",
        evidence_store=store,
    )
    return sess


# ============================================================================
# Focus 1: Auto-Dispatch Logic & Foreign Architecture Compatibility
# ============================================================================

class TestR22AutoDispatchAndCompatibility:
    """Adversarial challenge for auto-dispatch and cross-architecture handling."""

    def test_exhaustive_host_native_compatibility_matrix(self):
        """Verify compatibility matrix correctly categorizes native vs foreign formats and architectures."""
        host_os = sys.platform
        host_machine = platform.machine().lower()

        # 1. Native match on macOS ARM64
        if host_os == "darwin" and host_machine in ("arm64", "aarch64"):
            macho_arm64 = make_test_artifact(fmt=ArtifactFormat.MACHO, arch=ArchitectureType.ARM64)
            assert is_host_native_compatible(macho_arm64) is True

            # Mach-O x86_64 on Apple Silicon should be False (native execution without Rosetta)
            macho_x86 = make_test_artifact(fmt=ArtifactFormat.MACHO, arch=ArchitectureType.X86_64)
            assert is_host_native_compatible(macho_x86) is False

            # Foreign OS formats should all be False
            elf_arm64 = make_test_artifact(fmt=ArtifactFormat.ELF, arch=ArchitectureType.ARM64)
            elf_x86 = make_test_artifact(fmt=ArtifactFormat.ELF, arch=ArchitectureType.X86_64)
            pe_x86 = make_test_artifact(fmt=ArtifactFormat.PE, arch=ArchitectureType.X86_64)
            wasm_art = make_test_artifact(fmt=ArtifactFormat.WASM, arch=ArchitectureType.WASM)
            raw_art = make_test_artifact(fmt=ArtifactFormat.RAW, arch=ArchitectureType.ARM64)

            assert is_host_native_compatible(elf_arm64) is False
            assert is_host_native_compatible(elf_x86) is False
            assert is_host_native_compatible(pe_x86) is False
            assert is_host_native_compatible(wasm_art) is False
            assert is_host_native_compatible(raw_art) is False

        # Arbitrary / Unknown strings
        unknown_art = make_test_artifact(fmt="UNKNOWN_FORMAT", arch="UNKNOWN_ARCH")
        assert is_host_native_compatible(unknown_art) is False

    def test_frida_rejects_incompatible_binary_with_typed_exception(self):
        """Verify FridaProber explicitly raises ArchitectureCompatibilityError when forced to run foreign binary."""
        prober = FridaProber()
        foreign_sess = make_test_session(make_test_artifact(fmt=ArtifactFormat.ELF, arch=ArchitectureType.X86_64))

        if sys.platform == "darwin":
            compat, reason = prober.check_compatibility(foreign_sess)
            assert compat is False
            assert "cannot natively execute" in reason

            with pytest.raises(ArchitectureCompatibilityError) as exc_info:
                prober.trace_function(foreign_sess, 0x401000)
            assert "cannot trace artifact" in str(exc_info.value).lower()

    def test_auto_dispatch_gracefully_selects_unicorn_for_elf_and_pe(self, monkeypatch):
        """Verify trace_function(prober='auto') routes foreign ELF/PE binaries straight to Unicorn."""
        elf_sess = make_test_session(
            make_test_artifact(fmt=ArtifactFormat.ELF, arch=ArchitectureType.X86_64),
            session_id="r2_2_elf_sess",
        )
        global_session_manager._sessions["r2_2_elf_sess"] = elf_sess

        dispatched = []

        class MockUnicornProber:
            name = "unicorn"
            def trace_function(self, session, func_addr, **kwargs):
                dispatched.append("unicorn")
                return TraceResult(
                    success=True,
                    session_id=session.session_id,
                    function_address=func_addr,
                    prober="unicorn",
                    prober_used="unicorn",
                    return_value=123,
                )

        monkeypatch.setattr("metis_reverse.dynamic.unicorn_prober.UnicornProber", MockUnicornProber)

        res = mr_server.trace_function(
            session_id="r2_2_elf_sess",
            function_address=0x401000,
            prober="auto",
        )
        assert res.success is True
        assert res.return_value == 123
        assert "unicorn" in dispatched

    def test_auto_dispatch_runtime_recovery_when_frida_crashes(self, monkeypatch, c_service_stripped_path: Path):
        """Verify auto mode seamlessly catches runtime Frida crashes and completes via Unicorn fallback."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        # Mock Frida as available, but throwing a runtime crash during execution
        class CrashingFrida:
            name = "frida"
            def is_available(self, session=None):
                return True
            def trace_function(self, *args, **kwargs):
                raise RuntimeError("Process crashed during Frida Interceptor injection")

        monkeypatch.setattr("metis_reverse.dynamic.frida_prober.FridaProber", CrashingFrida)

        # In auto mode, the runtime exception must trigger fallback to UnicornProber
        res = mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="auto",
        )
        assert res.success is True
        assert res.prober_used == "unicorn" or res.prober == "unicorn"
        assert res.return_value is not None or len(res.captured_strings) > 0

    def test_unsupported_architecture_returns_tool_error(self):
        """Verify that attempting to trace an architecture unsupported by Unicorn (e.g. MIPS) raises ToolError."""
        mips_sess = make_test_session(
            make_test_artifact(arch=ArchitectureType.MIPS),
            session_id="r2_2_mips_sess",
        )
        global_session_manager._sessions["r2_2_mips_sess"] = mips_sess

        with pytest.raises(ToolError) as exc_info:
            mr_server.trace_function(
                session_id="r2_2_mips_sess",
                function_address=0x401000,
                prober="auto",
            )
        assert "unsupported architecture" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()


# ============================================================================
# Focus 2: FastMCP `trace_function` Parameter Validation & Edge Cases
# ============================================================================

class TestR22TraceFunctionBoundaries:
    """Stress-test input validation and extreme boundary cases for trace_function."""

    def test_nonexistent_or_malformed_session_ids(self):
        """Verify non-existent, empty, or whitespace session IDs cleanly raise ToolError."""
        with pytest.raises(ToolError) as exc_info:
            mr_server.trace_function(session_id="invalid_uuid_0000", function_address=0x1000)
        assert "not found" in str(exc_info.value).lower()

        with pytest.raises(ToolError):
            mr_server.trace_function(session_id="", function_address=0x1000)

        with pytest.raises(ToolError):
            mr_server.trace_function(session_id="   ", function_address=0x1000)

    @pytest.mark.parametrize(
        "addr_input, expected_int",
        [
            (0x100000894, 0x100000894),
            ("0x100000894", 0x100000894),
            ("0X100000894", 0x100000894),
            ("  0x100000894  ", 0x100000894),
            ("4294969492", 0x100000894),  # decimal string representation
        ],
    )
    def test_address_normalization_formats(self, addr_input, expected_int, c_service_stripped_path: Path):
        """Verify parse_int_address correctly parses all valid hex, int, and string formats."""
        session = mr_server.open_session(str(c_service_stripped_path))
        res = mr_server.trace_function(
            session_id=session.session_id,
            function_address=addr_input,
            args=[{"size": 512}],
            prober="unicorn",
        )
        assert res.success is True
        assert res.function_address == expected_int

    @pytest.mark.parametrize(
        "bad_addr",
        [
            -1,
            -0x1000,
            "-0x100",
            "not_hex_or_dec",
            "0xGGGG",
            "",
            "   ",
            None,
            [0x1000],
            {"addr": 0x1000},
        ],
    )
    def test_invalid_address_formats_raise_tool_error(self, bad_addr, c_service_stripped_path: Path):
        """Verify negative, unparseable, and type-mismatched addresses raise ToolError."""
        session = mr_server.open_session(str(c_service_stripped_path))
        with pytest.raises(ToolError):
            mr_server.trace_function(
                session_id=session.session_id,
                function_address=bad_addr,
                prober="unicorn",
            )

    @pytest.mark.parametrize(
        "prober_val",
        [
            "auto",
            "AUTO",
            "  aUtO  ",
            "unicorn",
            "UNICORN",
            "  UnIcOrN  ",
        ],
    )
    def test_prober_case_and_whitespace_insensitivity(self, prober_val, c_service_stripped_path: Path):
        """Verify prober selection is resilient to whitespace and mixed casing."""
        session = mr_server.open_session(str(c_service_stripped_path))
        res = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober=prober_val,
        )
        assert res.success is True

    @pytest.mark.parametrize(
        "invalid_prober",
        [
            "qiling",
            "gdb",
            "lldb",
            "bochs",
            "radare2",
            "none",
            "12345",
        ],
    )
    def test_invalid_prober_raises_tool_error(self, invalid_prober, c_service_stripped_path: Path):
        """Verify unsupported prober names raise ToolError detailing supported backends."""
        session = mr_server.open_session(str(c_service_stripped_path))
        with pytest.raises(ToolError) as exc_info:
            mr_server.trace_function(
                session_id=session.session_id,
                function_address=0x100000894,
                prober=invalid_prober,
            )
        assert "unknown prober type" in str(exc_info.value).lower()
        assert "supported" in str(exc_info.value).lower()

    def test_instruction_limit_trapping(self, c_service_stripped_path: Path):
        """Verify max_instructions limit prevents runaway execution and returns failure cleanly."""
        session = mr_server.open_session(str(c_service_stripped_path))

        # Restrict execution to 1 instruction
        res = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
            max_instructions=1,
        )
        assert res.success is False
        assert res.instructions_executed <= 1
        assert "limit reached" in (res.error or "").lower()

    def test_adversarial_arguments_marshaling(self, c_service_stripped_path: Path):
        """Verify prober marshaling handles varied adversarial argument types without crashing."""
        session = mr_server.open_session(str(c_service_stripped_path))

        # 1. None args
        res1 = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=None,
            prober="unicorn",
            max_instructions=20,
        )
        assert res1 is not None

        # 2. Empty string
        res2 = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[""],
            prober="unicorn",
            max_instructions=20,
        )
        assert res2 is not None

        # 3. Very long string (2048 chars)
        long_str = "A" * 2048
        res3 = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[long_str],
            prober="unicorn",
            max_instructions=20,
        )
        assert res3 is not None

        # 4. Binary buffer with embedded nulls and high bytes
        raw_bin = b"\x00\xff\xfe\x01\x00\xaa\xbb"
        res4 = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[raw_bin],
            prober="unicorn",
            max_instructions=20,
        )
        assert res4 is not None

        # 5. Extreme integers (negative, max uint32, max uint64)
        res5 = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[-100, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF],
            prober="unicorn",
            max_instructions=20,
        )
        assert res5 is not None


# ============================================================================
# Focus 3: FactBackfiller & EvidenceStore Immutability
# ============================================================================

class TestR22BackfillerImmutability:
    """Stress-test immutability locks created by dynamic execution tracing."""

    def test_backfill_creates_immutable_tags_with_confidence_one(self, c_service_stripped_path: Path):
        """Verify FactBackfiller generates tags with confidence 1.0, is_immutable=True, and correct sources."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        res = mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )
        assert res.success is True

        evidence = mr_server.query_evidence(sess_id, symbol_or_addr="0x100000894")
        dyn_tags = [t for t in evidence if getattr(t, "evidence_type", None) == "DYNAMIC_PROBE"]
        assert len(dyn_tags) >= 1

        for tag in dyn_tags:
            assert tag.confidence == 1.0
            assert tag.is_immutable is True
            assert tag.source == EvidenceSource.DYNAMIC_PROBE
            assert "0x100000894" in tag.target_id or "0x100000894" in (tag.raw_anchor or "")

    def test_direct_evidence_store_tampering_blocked(self, c_service_stripped_path: Path):
        """Verify that direct EvidenceStore modifications (add_tag overwrite / delete_tag) raise ImmutableEvidenceError."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        res = mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )
        assert res.success is True

        raw_session = global_session_manager.get_session(sess_id)
        dyn_tag = next(t for t in raw_session.evidence_tags.values() if t.evidence_type == "DYNAMIC_PROBE")

        # Attack A: Attempt to overwrite the immutable tag
        malicious_tag = EvidenceTag(
            tag_id=dyn_tag.tag_id,
            target_type=dyn_tag.target_type,
            target_id=dyn_tag.target_id,
            suggested_name="adversary_overwrite",
            confidence=0.01,
            is_immutable=False,
            raw_anchor="fake",
            explanation="tampered",
        )
        with pytest.raises(ImmutableEvidenceError) as exc_info:
            raw_session.evidence_store.add_tag(malicious_tag)
        assert "cannot overwrite immutable evidence tag" in str(exc_info.value).lower()

        # Attack B: Attempt to delete the immutable tag
        with pytest.raises(ImmutableEvidenceError) as exc_info:
            raw_session.evidence_store.delete_tag(dyn_tag.tag_id)
        assert "cannot delete immutable evidence tag" in str(exc_info.value).lower()

    def test_rename_symbol_strictly_prohibited_after_tracing(self, c_service_stripped_path: Path):
        """Verify rename_symbol tool is completely blocked for any function that has been dynamically traced."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        # Trace function to lock it
        mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )

        # Attempt 1: Rename via integer address
        with pytest.raises(ToolError) as exc_int:
            mr_server.rename_symbol(
                session_id=sess_id,
                address=0x100000894,
                new_name="tampered_init_name",
            )
        assert "locked by immutable evidence" in str(exc_int.value).lower()

        # Attempt 2: Rename via hex string
        with pytest.raises(ToolError) as exc_hex:
            mr_server.rename_symbol(
                session_id=sess_id,
                address="0x100000894",
                new_name="tampered_init_name_hex",
            )
        assert "locked by immutable evidence" in str(exc_hex.value).lower()

        # Attempt 3: Rename via clean decimal address
        with pytest.raises(ToolError) as exc_dec:
            mr_server.rename_symbol(
                session_id=sess_id,
                address=str(0x100000894),
                new_name="tampered_init_name_dec",
            )
        assert "locked by immutable evidence" in str(exc_dec.value).lower()


# ============================================================================
# Focus 4: Concurrency & Contention Stress
# ============================================================================

class TestR22ConcurrencyStress:
    """Stress-test high concurrency, race conditions, and session integrity."""

    def test_high_concurrency_same_function_same_session(self, c_service_stripped_path: Path):
        """Verify 20 concurrent threads tracing the identical function on the same session execute cleanly."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        results = []
        errors = []

        def worker(wid: int):
            try:
                res = mr_server.trace_function(
                    session_id=sess_id,
                    function_address=0x100000894,
                    args=[{"size": 512}],
                    prober="unicorn",
                )
                results.append((wid, res))
            except Exception as e:
                errors.append((wid, e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors encountered: {errors}"
        assert len(results) == 20
        for _wid, res in results:
            assert res.success is True
            assert any("metis_default_secret_token_2026" in s for s in res.captured_strings)

    def test_concurrent_multi_function_tracing(self, c_service_stripped_path: Path):
        """Verify concurrent execution across multiple distinct functions on the same session."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        cfg_buf = (
            struct.pack("<III", 0x53455256, 8080, 128)
            + b"metis_default_secret_token_2026".ljust(64, b"\x00")
            + struct.pack("<II", 1, 5000)
        )

        results = {}
        errors = []

        def worker(wid: int, mode: str):
            try:
                if mode == "init":
                    res = mr_server.trace_function(
                        session_id=sess_id,
                        function_address=0x100000894,
                        args=[{"size": 512}],
                        prober="unicorn",
                    )
                    results[wid] = (mode, res.success, res.captured_strings)
                elif mode == "auth_ok":
                    res = mr_server.trace_function(
                        session_id=sess_id,
                        function_address=0x100000ac8,
                        args=[{"size": 128}, cfg_buf, "metis_default_secret_token_2026"],
                        prober="unicorn",
                    )
                    results[wid] = (mode, res.success, res.return_value)
                elif mode == "auth_fail":
                    res = mr_server.trace_function(
                        session_id=sess_id,
                        function_address=0x100000ac8,
                        args=[{"size": 128}, cfg_buf, "invalid_attacker_token"],
                        prober="unicorn",
                    )
                    results[wid] = (mode, res.success, res.return_value)
            except Exception as e:
                errors.append((wid, mode, e))

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(15):
                mode = "init" if i % 3 == 0 else ("auth_ok" if i % 3 == 1 else "auth_fail")
                futures.append(executor.submit(worker, i, mode))
            concurrent.futures.wait(futures)

        assert len(errors) == 0, f"Concurrent multi-function errors: {errors}"
        assert len(results) == 15
        for _wid, (mode, success, val) in results.items():
            assert success is True
            if mode == "auth_ok":
                assert val == 1
            elif mode == "auth_fail":
                assert val == 0

    def test_concurrent_trace_and_mutation_race(self, c_service_stripped_path: Path):
        """Stress race condition where tracing and renaming contend concurrently on the same function."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        # Trace once first so function is firmly locked
        mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )

        trace_count = [0]
        blocked_rename_count = [0]
        leak_errors = []

        def trace_runner():
            for _ in range(8):
                try:
                    res = mr_server.trace_function(
                        session_id=sess_id,
                        function_address=0x100000894,
                        args=[{"size": 512}],
                        prober="unicorn",
                    )
                    if res.success:
                        trace_count[0] += 1
                except Exception as e:
                    leak_errors.append(("trace", e))

        def rename_runner():
            for _ in range(8):
                try:
                    mr_server.rename_symbol(
                        session_id=sess_id,
                        address=0x100000894,
                        new_name="race_condition_hacked_name",
                    )
                    leak_errors.append(("rename", "Renaming was NOT blocked!"))
                except ToolError:
                    blocked_rename_count[0] += 1
                except Exception as e:
                    leak_errors.append(("rename", e))

        t1 = threading.Thread(target=trace_runner)
        t2 = threading.Thread(target=rename_runner)
        t3 = threading.Thread(target=trace_runner)
        t4 = threading.Thread(target=rename_runner)

        for t in (t1, t2, t3, t4):
            t.start()
        for t in (t1, t2, t3, t4):
            t.join()

        assert len(leak_errors) == 0, f"Race errors: {leak_errors}"
        assert trace_count[0] > 0
        assert blocked_rename_count[0] == 16  # 2 threads * 8 attempts = 16 blocked renames
