"""
Adversarial Stress Test Suite for Milestone 3 Dynamic Tracing & Memory Probing
=============================================================================
Targets:
1. Auto-dispatch logic & foreign binary architecture compatibility (ELF/PE/MIPS/ARM on macOS).
2. FastMCP tool `trace_function`: invalid session IDs, invalid addresses, invalid prober names, timeout handling, adversarial arguments.
3. `FactBackfiller` and `EvidenceStore` immutability: verify that after tracing, attempting to overwrite backfilled tags or rename symbols via `rename_symbol` is strictly blocked.
4. Concurrent tracing: multiple threads tracing functions simultaneously on the same session without races, deadlocks, or corruption.
"""

from __future__ import annotations

import concurrent.futures
import struct
import sys
import threading
from pathlib import Path

import pytest

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

try:
    from fastmcp.exceptions import ToolError
except ImportError:
    from metis_reverse.server import ToolError  # type: ignore


# ============================================================================
# Helpers & Fixtures
# ============================================================================

def make_foreign_artifact(
    file_path: str = "/tmp/fake_foreign_bin",
    fmt: ArtifactFormat = ArtifactFormat.ELF,
    arch: ArchitectureType = ArchitectureType.X86_64,
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


def make_test_session(artifact: TargetArtifact, session_id: str = "test_adv_sess") -> BinarySession:
    store = EvidenceStore()
    sess = BinarySession(
        session_id=session_id,
        artifact=artifact,
        backend_type="mock",
        evidence_store=store,
    )
    return sess


# ============================================================================
# Group 1: Auto-Dispatch & Foreign Binary Architecture Compatibility
# ============================================================================

class TestAutoDispatchAndArchitectureCompatibility:
    """Stress-test auto-dispatch logic and foreign architecture compatibility."""

    def test_is_host_native_compatible_matrix(self):
        """Verify host compatibility returns False for all foreign formats/architectures."""
        # Linux ELF on macOS should be incompatible
        elf_x86 = make_foreign_artifact(fmt=ArtifactFormat.ELF, arch=ArchitectureType.X86_64)
        elf_arm = make_foreign_artifact(fmt=ArtifactFormat.ELF, arch=ArchitectureType.ARM64)
        pe_x86 = make_foreign_artifact(fmt=ArtifactFormat.PE, arch=ArchitectureType.X86_64)

        if sys.platform == "darwin":
            assert is_host_native_compatible(elf_x86) is False
            assert is_host_native_compatible(elf_arm) is False
            assert is_host_native_compatible(pe_x86) is False

        # Unknown architecture or format
        unknown_art = make_foreign_artifact(fmt="UNKNOWN", arch=ArchitectureType.UNKNOWN)
        assert is_host_native_compatible(unknown_art) is False

    def test_frida_rejects_incompatible_architecture(self):
        """Verify FridaProber explicitly raises ArchitectureCompatibilityError on foreign binaries."""
        sess = make_test_session(make_foreign_artifact(fmt=ArtifactFormat.ELF, arch=ArchitectureType.X86_64))
        prober = FridaProber()

        if sys.platform == "darwin":
            compat, reason = prober.check_compatibility(sess)
            assert compat is False
            assert "cannot natively execute" in reason.lower()

            with pytest.raises(ArchitectureCompatibilityError) as exc_info:
                prober.trace_function(sess, 0x401000)
            assert "cannot trace artifact" in str(exc_info.value).lower()

    def test_auto_dispatch_selects_unicorn_for_foreign_binary(self, monkeypatch):
        """Verify trace_function with prober='auto' falls back to Unicorn for foreign binaries."""
        sess = make_test_session(make_foreign_artifact(fmt=ArtifactFormat.ELF, arch=ArchitectureType.X86_64), session_id="foreign_sess")
        global_session_manager._sessions["foreign_sess"] = sess

        called_prober = []

        class MockUnicorn:
            name = "unicorn"
            def trace_function(self, session, func_addr, **kwargs):
                called_prober.append("unicorn")
                return TraceResult(
                    success=True,
                    session_id=session.session_id,
                    function_address=func_addr,
                    prober="unicorn",
                    prober_used="unicorn",
                    return_value=42,
                )

        monkeypatch.setattr("metis_reverse.dynamic.unicorn_prober.UnicornProber", MockUnicorn)

        res = mr_server.trace_function(
            session_id="foreign_sess",
            function_address=0x401000,
            prober="auto",
        )
        assert "unicorn" in called_prober
        assert res.success is True
        assert res.return_value == 42

    def test_auto_dispatch_graceful_fallback_when_frida_fails_at_runtime(self, monkeypatch, c_service_stripped_path: Path):
        """Verify auto mode seamlessly recovers via Unicorn if Frida crashes or fails at runtime."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        # Simulate Frida available but failing during execution
        class FailingFrida:
            name = "frida"
            def is_available(self, session=None):
                return True
            def trace_function(self, *args, **kwargs):
                raise RuntimeError("Simulated Frida attachment/injection failure")

        monkeypatch.setattr("metis_reverse.dynamic.frida_prober.FridaProber", FailingFrida)

        # In auto mode, it should catch the Frida failure and fallback to Unicorn
        res = mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="auto",
        )
        assert res.success is True
        assert res.prober_used == "unicorn" or res.prober == "unicorn"

    def test_unsupported_architecture_raises_tool_error(self):
        """Verify unsupported architectures cleanly raise ToolError rather than crashing."""
        sess = make_test_session(make_foreign_artifact(arch=ArchitectureType.UNKNOWN), session_id="unsupported_arch_sess")
        global_session_manager._sessions["unsupported_arch_sess"] = sess

        with pytest.raises(ToolError) as exc_info:
            mr_server.trace_function(
                session_id="unsupported_arch_sess",
                function_address=0x401000,
                prober="auto",
            )
        assert "unsupported architecture" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()


# ============================================================================
# Group 2: FastMCP trace_function Error & Boundary Input Stress-Testing
# ============================================================================

class TestTraceFunctionInputBoundaries:
    """Stress-test trace_function parameter validation and boundary error paths."""

    def test_invalid_session_id(self):
        """Verify non-existent or empty session IDs raise ToolError."""
        with pytest.raises(ToolError) as exc_info:
            mr_server.trace_function(
                session_id="session_that_does_not_exist_999",
                function_address=0x100000894,
            )
        assert "not found" in str(exc_info.value).lower()

        with pytest.raises(ToolError):
            mr_server.trace_function(
                session_id="",
                function_address=0x100000894,
            )

    @pytest.mark.parametrize(
        "bad_addr",
        [
            -1,
            -0x1000,
            "not_an_address",
            "0xZZZZ",
            "",
            None,
            [],
            {},
        ],
    )
    def test_invalid_address_formats(self, bad_addr, c_service_stripped_path: Path):
        """Verify negative, malformed, and non-int/hex addresses raise ToolError."""
        session = mr_server.open_session(str(c_service_stripped_path))
        with pytest.raises(ToolError):
            mr_server.trace_function(
                session_id=session.session_id,
                function_address=bad_addr,
            )

    def test_unmapped_or_zero_address_handled_safely(self, c_service_stripped_path: Path):
        """Verify executing at 0x0 or unmapped addresses returns failure or ToolError without crashing."""
        session = mr_server.open_session(str(c_service_stripped_path))

        # Tracing at 0x0
        try:
            res_zero = mr_server.trace_function(
                session_id=session.session_id,
                function_address=0x0,
                prober="unicorn",
                max_instructions=20,
            )
            assert res_zero.success is False
        except ToolError:
            pass  # Raising ToolError is also acceptable and clean

        # Tracing at giant unmapped address
        try:
            res_unmapped = mr_server.trace_function(
                session_id=session.session_id,
                function_address=0xDEADBEEF0000,
                prober="unicorn",
                max_instructions=20,
            )
            assert res_unmapped.success is False
        except ToolError:
            pass

    @pytest.mark.parametrize(
        "invalid_prober",
        [
            "qiling",
            "ida_prober",
            "gdb",
            "invalid_choice",
        ],
    )
    def test_invalid_prober_name_raises_tool_error(self, invalid_prober, c_service_stripped_path: Path):
        """Verify invalid prober backend choices raise ToolError."""
        session = mr_server.open_session(str(c_service_stripped_path))
        with pytest.raises(ToolError) as exc_info:
            mr_server.trace_function(
                session_id=session.session_id,
                function_address=0x100000894,
                prober=invalid_prober,
            )
        assert "unknown prober type" in str(exc_info.value).lower()

    def test_prober_case_insensitivity_and_whitespace(self, c_service_stripped_path: Path):
        """Verify prober names accept variations like '  UNICORN  ' or 'AuTo'."""
        session = mr_server.open_session(str(c_service_stripped_path))
        res = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="  UNICORN  ",
        )
        assert res.success is True
        assert res.prober_used == "unicorn"

    def test_timeout_and_instruction_limit_trapping(self, c_service_stripped_path: Path):
        """Verify execution stops cleanly when instruction count or timeout is exceeded."""
        session = mr_server.open_session(str(c_service_stripped_path))

        # Restrict max_instructions to 2 (config_init requires ~20 instructions)
        res = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
            max_instructions=2,
            timeout_seconds=0.1,
        )
        assert res.success is False
        assert "limit reached" in (res.error or "").lower() or res.instructions_executed <= 2

    def test_adversarial_arguments_handling(self, c_service_stripped_path: Path):
        """Verify handling of None args, empty args, large byte buffers, and extreme integers."""
        session = mr_server.open_session(str(c_service_stripped_path))

        # None args
        res_none = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=None,
            prober="unicorn",
            max_instructions=50,
        )
        assert res_none is not None

        # Giant byte buffer (16 KB)
        large_buf = b"\x41" * 16384
        res_large = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[large_buf],
            prober="unicorn",
            max_instructions=50,
        )
        assert res_large is not None

        # Extreme integers: negative, 32-bit max, 64-bit max
        res_ints = mr_server.trace_function(
            session_id=session.session_id,
            function_address=0x100000894,
            args=[-999, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF],
            prober="unicorn",
            max_instructions=50,
        )
        assert res_ints is not None


# ============================================================================
# Group 3: FactBackfiller & EvidenceStore Immutability Enforcement
# ============================================================================

class TestBackfillingAndImmutabilityEnforcement:
    """Stress-test immutability locking after dynamic fact backfilling."""

    def test_backfilled_tags_are_strictly_immutable(self, c_service_stripped_path: Path):
        """Verify tags created by FactBackfiller have confidence 1.0 and is_immutable=True."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        # Trace function to trigger backfill
        res = mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )
        assert res.success is True

        # Query backfilled tags
        evidence = mr_server.query_evidence(sess_id, symbol_or_addr="0x100000894")
        dyn_tags = [e for e in evidence if getattr(e, "evidence_type", None) == "DYNAMIC_PROBE"]
        assert len(dyn_tags) >= 1

        for tag in dyn_tags:
            assert tag.confidence == 1.0
            assert tag.is_immutable is True
            assert tag.source == EvidenceSource.DYNAMIC_PROBE

    def test_evidence_store_blocks_overwriting_backfilled_tag(self, c_service_stripped_path: Path):
        """Verify EvidenceStore.add_tag raises ImmutableEvidenceError when attempting to overwrite."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        res = mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )
        assert res.success is True

        # Retrieve one of the backfilled tags
        raw_session = global_session_manager.get_session(sess_id)
        dyn_tag = next(t for t in raw_session.evidence_tags.values() if t.evidence_type == "DYNAMIC_PROBE")

        # Attempt to overwrite existing tag with new content
        corrupted_tag = EvidenceTag(
            tag_id=dyn_tag.tag_id,
            target_type=dyn_tag.target_type,
            target_id=dyn_tag.target_id,
            suggested_name="fake_corrupted_name",
            confidence=0.1,
            is_immutable=False,
            raw_anchor="hacked_anchor",
            explanation="attempted overwrite",
        )

        with pytest.raises(ImmutableEvidenceError) as exc_info:
            raw_session.evidence_store.add_tag(corrupted_tag)
        assert "cannot overwrite immutable evidence tag" in str(exc_info.value).lower()

    def test_evidence_store_blocks_deleting_backfilled_tag(self, c_service_stripped_path: Path):
        """Verify EvidenceStore.delete_tag raises ImmutableEvidenceError on backfilled tags."""
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

        with pytest.raises(ImmutableEvidenceError) as exc_info:
            raw_session.evidence_store.delete_tag(dyn_tag.tag_id)
        assert "cannot delete immutable evidence tag" in str(exc_info.value).lower()

    def test_rename_symbol_strictly_blocked_by_int_address(self, c_service_stripped_path: Path):
        """Verify rename_symbol fails with ToolError after function has been traced."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        # 1. Trace function to lock it
        res = mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )
        assert res.success is True

        # 2. Attempt rename by int address
        with pytest.raises(ToolError) as exc_info:
            mr_server.rename_symbol(
                session_id=sess_id,
                address=0x100000894,
                new_name="adversary_hacked_init",
            )
        assert "locked by immutable evidence" in str(exc_info.value).lower()
        assert "renaming forbidden" in str(exc_info.value).lower()

    def test_rename_symbol_strictly_blocked_by_hex_string_address(self, c_service_stripped_path: Path):
        """Verify rename_symbol fails with ToolError when address is provided as hex string."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )

        with pytest.raises(ToolError) as exc_info:
            mr_server.rename_symbol(
                session_id=sess_id,
                address="0x100000894",
                new_name="adversary_hacked_init_hex",
            )
        assert "locked by immutable evidence" in str(exc_info.value).lower()

    def test_rename_symbol_strictly_blocked_for_synthesized_stripped_function(self, c_service_stripped_path: Path):
        """Verify rename_symbol fails on functions dynamically synthesized in stripped binaries."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        # Trace _session_authenticate (0x100000ac8)
        mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000ac8,
            args=[{"size": 128}, b"\x00" * 128, "token"],
            prober="unicorn",
        )

        # Attempt to rename it
        with pytest.raises(ToolError) as exc_info:
            mr_server.rename_symbol(
                session_id=sess_id,
                address=0x100000ac8,
                new_name="adversary_auth_func",
            )
        assert "locked by immutable evidence" in str(exc_info.value).lower()


# ============================================================================
# Group 4: High Concurrency Stress-Testing
# ============================================================================

class TestConcurrentTracing:
    """Stress-test concurrent trace execution and fact backfilling."""

    def test_concurrent_tracing_same_function_same_session(self, c_service_stripped_path: Path):
        """Verify 10 threads tracing the same function on the same session execute safely."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        errors = []
        results = []

        def worker_trace(worker_id: int):
            try:
                res = mr_server.trace_function(
                    session_id=sess_id,
                    function_address=0x100000894,
                    args=[{"size": 512}],
                    prober="unicorn",
                )
                results.append((worker_id, res))
            except Exception as e:
                errors.append((worker_id, e))

        threads = [threading.Thread(target=worker_trace, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Concurrent workers encountered errors: {errors}"
        assert len(results) == 10
        for _wid, res in results:
            assert res.success is True
            assert any("metis_default_secret_token_2026" in s for s in res.captured_strings)

        # Verify EvidenceStore consistency
        raw_sess = global_session_manager.get_session(sess_id)
        dyn_tags = [t for t in raw_sess.evidence_tags.values() if t.evidence_type == "DYNAMIC_PROBE"]
        assert len(dyn_tags) >= 1

    def test_concurrent_tracing_different_functions(self, c_service_stripped_path: Path):
        """Verify threads tracing different functions concurrently complete with expected return values."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        valid_cfg_buf = (
            struct.pack("<III", 0x53455256, 8080, 128)
            + b"metis_default_secret_token_2026".ljust(64, b"\x00")
            + struct.pack("<II", 1, 5000)
        )

        results = {}
        errors = []

        def trace_task(task_type: str, task_id: int):
            try:
                if task_type == "init":
                    res = mr_server.trace_function(
                        session_id=sess_id,
                        function_address=0x100000894,
                        args=[{"size": 512}],
                        prober="unicorn",
                    )
                    results[task_id] = (task_type, res.success, res.captured_strings)
                elif task_type == "auth_valid":
                    res = mr_server.trace_function(
                        session_id=sess_id,
                        function_address=0x100000ac8,
                        args=[{"size": 128}, valid_cfg_buf, "metis_default_secret_token_2026"],
                        prober="unicorn",
                    )
                    results[task_id] = (task_type, res.success, res.return_value)
                elif task_type == "auth_invalid":
                    res = mr_server.trace_function(
                        session_id=sess_id,
                        function_address=0x100000ac8,
                        args=[{"size": 128}, valid_cfg_buf, "wrong_attacker_token"],
                        prober="unicorn",
                    )
                    results[task_id] = (task_type, res.success, res.return_value)
            except Exception as e:
                errors.append((task_id, task_type, e))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for i in range(12):
                t_type = "init" if i % 3 == 0 else ("auth_valid" if i % 3 == 1 else "auth_invalid")
                futures.append(executor.submit(trace_task, t_type, i))
            concurrent.futures.wait(futures)

        assert len(errors) == 0, f"Concurrent tasks had errors: {errors}"
        assert len(results) == 12

        for _i, (t_type, success, val) in results.items():
            assert success is True
            if t_type == "auth_valid":
                assert val == 1
            elif t_type == "auth_invalid":
                assert val == 0
            elif t_type == "init":
                assert any("metis_default_secret_token_2026" in s for s in val)

    def test_concurrent_read_write_stress(self, c_service_stripped_path: Path):
        """Stress test simultaneous tracing, evidence querying, and blocked mutation attempts."""
        session = mr_server.open_session(str(c_service_stripped_path))
        sess_id = session.session_id

        # First trace 0x100000894 once so it is locked
        mr_server.trace_function(
            session_id=sess_id,
            function_address=0x100000894,
            args=[{"size": 512}],
            prober="unicorn",
        )

        trace_successes = [0]
        query_successes = [0]
        rename_blocked = [0]
        unexpected_errors = []

        def worker_trace():
            for _ in range(5):
                try:
                    res = mr_server.trace_function(
                        session_id=sess_id,
                        function_address=0x100000894,
                        args=[{"size": 512}],
                        prober="unicorn",
                    )
                    if res.success:
                        trace_successes[0] += 1
                except Exception as e:
                    unexpected_errors.append(("trace", e))

        def worker_query():
            for _ in range(10):
                try:
                    ev = mr_server.query_evidence(sess_id, "0x100000894")
                    if len(ev) > 0:
                        query_successes[0] += 1
                except Exception as e:
                    unexpected_errors.append(("query", e))

        def worker_rename():
            for _ in range(5):
                try:
                    mr_server.rename_symbol(sess_id, 0x100000894, "adversary_race_rename")
                    unexpected_errors.append(("rename", "Renaming should have been blocked!"))
                except ToolError:
                    rename_blocked[0] += 1
                except Exception as e:
                    unexpected_errors.append(("rename", e))

        threads = [
            threading.Thread(target=worker_trace),
            threading.Thread(target=worker_trace),
            threading.Thread(target=worker_query),
            threading.Thread(target=worker_query),
            threading.Thread(target=worker_rename),
            threading.Thread(target=worker_rename),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(unexpected_errors) == 0, f"Unexpected errors during concurrent stress: {unexpected_errors}"
        assert trace_successes[0] > 0
        assert query_successes[0] > 0
        assert rename_blocked[0] == 10  # 2 threads * 5 iterations each
