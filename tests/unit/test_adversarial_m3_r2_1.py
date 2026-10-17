"""
Challenger M3-R2-1: Adversarial Stress Test Suite for Milestone 3 (Dynamic Tracing & Memory Probing).
====================================================================================================
Focus: UnicornProber In-Memory Micro-Emulation Engine:
1. Page coalescing with weird, overlapping, zero-sized, and misaligned sections.
2. Deterministic sentinel return trapping at 0xDEAD0000 across ARM64, x86_64, and x86_32.
3. Null pointer dereference trapping (< 0x1000) for reads, writes, and struct offset accesses.
4. Unmapped memory auto-allocation (> 0x1000), scratch page limits, disabled auto_alloc, and cross-page access.
5. Infinite loop protection via instruction count limits and wall-clock timeout.
6. Libc hooks (strcmp, strncmp, strlen, memcmp, strncpy, strcpy, memcpy, memset, atoi) under valid, empty, and NULL inputs.
7. HeapManager allocation alignment and heap exhaustion bounds.
8. Real stripped binary (_config_init_default and _session_authenticate) micro-emulation on c_service_stripped.
"""

from __future__ import annotations

import struct
import tempfile
import time
from pathlib import Path

import pytest
from unicorn import (
    UC_ARCH_ARM64,
    UC_MODE_ARM,
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
)

from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySection,
    BinarySession,
    SectionPermission,
    TargetArtifact,
)
from metis_reverse.core.session import global_session_manager
from metis_reverse.dynamic.unicorn_prober import (
    SENTINEL_RETURN_ADDRESS,
    ARM64Adapter,
    HeapManager,
    UnicornProber,
    X86_32Adapter,
    X86_64Adapter,
    build_page_mappings,
)

# ============================================================================
# 1. Page Coalescing Stress Tests
# ============================================================================

class TestPageCoalescing:
    """Stress-test page coalescing with weird, overlapping, and zero-sized sections."""

    def test_empty_and_zero_and_negative_sizes(self):
        """Verify empty lists, zero sizes, and negative sizes are safely ignored."""
        assert build_page_mappings([]) == []
        slices = [
            (0x1000, 0, b"", UC_PROT_READ),
            (0x2000, -100, b"DATA", UC_PROT_WRITE),
            (0x3000, 0, b"ABC", UC_PROT_EXEC),
        ]
        assert build_page_mappings(slices) == []

    def test_overlapping_sections_permission_merge_and_content_overlay(self):
        """Verify overlapping sections merge permissions and later bytes overlay properly."""
        slices = [
            (0x1000, 0x100, b"\xaa" * 0x100, UC_PROT_READ),
            (0x1050, 0x100, b"\xbb" * 0x100, UC_PROT_WRITE),
        ]
        blocks = build_page_mappings(slices, page_size=4096)
        assert len(blocks) == 1
        addr, size, content, prot = blocks[0]
        assert addr == 0x1000
        assert size == 4096
        assert prot == (UC_PROT_READ | UC_PROT_WRITE)
        assert content[0:0x50] == b"\xaa" * 0x50
        assert content[0x50:0x150] == b"\xbb" * 0x100
        assert content[0x150:4096] == b"\x00" * (4096 - 0x150)

    def test_contiguous_pages_permission_coalescing(self):
        """Verify contiguous pages with same permission coalesce; different permissions stay split."""
        # Page 1 & 2 have same permission -> coalesced into 8192 bytes
        # Page 3 has different permission -> separate 4096 bytes block
        slices = [
            (0x1000, 4096, b"\x11" * 4096, UC_PROT_READ | UC_PROT_EXEC),
            (0x2000, 4096, b"\x22" * 4096, UC_PROT_READ | UC_PROT_EXEC),
            (0x3000, 4096, b"\x33" * 4096, UC_PROT_READ | UC_PROT_WRITE),
        ]
        blocks = build_page_mappings(slices, page_size=4096)
        assert len(blocks) == 2
        assert blocks[0][0] == 0x1000
        assert blocks[0][1] == 8192
        assert blocks[0][3] == (UC_PROT_READ | UC_PROT_EXEC)

        assert blocks[1][0] == 0x3000
        assert blocks[1][1] == 4096
        assert blocks[1][3] == (UC_PROT_READ | UC_PROT_WRITE)

    def test_virtual_size_exceeding_content_is_zero_padded(self):
        """Verify BSS sections where virtual size exceeds raw bytes are zero-padded."""
        slices = [
            (0x5000, 8192, b"\xfe" * 64, UC_PROT_READ | UC_PROT_WRITE),
        ]
        blocks = build_page_mappings(slices, page_size=4096)
        assert len(blocks) == 1
        addr, size, content, prot = blocks[0]
        assert addr == 0x5000
        assert size == 8192
        assert content[:64] == b"\xfe" * 64
        assert content[64:] == b"\x00" * (8192 - 64)

    def test_unaligned_arbitrary_offsets_and_sizes(self):
        """Verify unaligned addresses coalesce into clean 4KB aligned blocks."""
        slices = [
            (0x1003, 5, b"HELLO", UC_PROT_READ),
            (0x1FF0, 32, b"WORLD_SPANNING_PAGE_BOUNDARY!!!", UC_PROT_READ),
        ]
        blocks = build_page_mappings(slices, page_size=4096)
        # Spans across page 0x1000 and page 0x2000
        assert len(blocks) == 1  # Same permission -> coalesced to 8192
        addr, size, content, prot = blocks[0]
        assert addr == 0x1000
        assert size == 8192
        assert content[3:8] == b"HELLO"
        assert content[0xFF0:0xFF0 + 31] == b"WORLD_SPANNING_PAGE_BOUNDARY!!!"


# ============================================================================
# 2. Sentinel Return Trapping Tests
# ============================================================================

class TestSentinelReturnTrapping:
    """Stress-test deterministic sentinel return trapping across CPU architectures."""

    def test_sentinel_return_arm64_basic(self):
        """Verify ARM64 halts cleanly at 0xDEAD0000 with return value in X0."""
        adapter = ARM64Adapter()
        uc = adapter.create_engine()
        uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
        uc.mem_map(0x7FFF0000, 0x10000, UC_PROT_ALL)

        # mov x0, #42 ; ret
        # d2800540 d65f03c0
        code = struct.pack("<II", 0xD2800540, 0xD65F03C0)
        uc.mem_write(0x10000, code)

        adapter.setup_frame(uc, 0x7FFF8000, SENTINEL_RETURN_ADDRESS, [])
        adapter.set_pc(uc, 0x10000)

        uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
        assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
        assert adapter.read_return_value(uc) == 42

    def test_sentinel_return_arm64_stack_arguments(self):
        """Verify ARM64 passes > 8 arguments via stack correctly (ldr x8, [sp])."""
        adapter = ARM64Adapter()
        uc = adapter.create_engine()
        uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
        uc.mem_map(0x7FFF0000, 0x10000, UC_PROT_ALL)

        # 10 arguments passed: x0..x7, 9th on stack [sp], 10th at [sp+8]
        # ldr x8, [sp] (0xf94003e8) ; add x0, x0, x8 (0x8b080000) ; ret (0xd65f03c0)
        code = struct.pack("<III", 0xF94003E8, 0x8B080000, 0xD65F03C0)
        uc.mem_write(0x10000, code)

        args = [5, 2, 3, 4, 5, 6, 7, 8, 95, 200]
        adapter.setup_frame(uc, 0x7FFF8000, SENTINEL_RETURN_ADDRESS, args)
        adapter.set_pc(uc, 0x10000)

        uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
        assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
        assert adapter.read_return_value(uc) == 100  # 5 + 95

    def test_sentinel_return_x86_64_basic(self):
        """Verify x86_64 halts cleanly at 0xDEAD0000 with return value in RAX."""
        adapter = X86_64Adapter()
        uc = adapter.create_engine()
        uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
        uc.mem_map(0x7FFF0000, 0x10000, UC_PROT_ALL)

        # mov rax, 77 ; ret
        code = b"\x48\xc7\xc0\x4d\x00\x00\x00\xc3"
        uc.mem_write(0x10000, code)

        adapter.setup_frame(uc, 0x7FFF8000, SENTINEL_RETURN_ADDRESS, [])
        adapter.set_pc(uc, 0x10000)

        uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
        assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
        assert adapter.read_return_value(uc) == 77

    def test_sentinel_return_x86_64_stack_arguments(self):
        """Verify x86_64 passes > 6 arguments via stack correctly ([rsp + 8])."""
        adapter = X86_64Adapter()
        uc = adapter.create_engine()
        uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
        uc.mem_map(0x7FFF0000, 0x10000, UC_PROT_ALL)

        # 7th arg is at [rsp + 8] because [rsp] has return sentinel
        # mov rax, [rsp + 8] ; add rax, rdi ; ret
        # 48 8b 44 24 08 48 01 f8 c3
        code = b"\x48\x8b\x44\x24\x08\x48\x01\xf8\xc3"
        uc.mem_write(0x10000, code)

        args = [20, 2, 3, 4, 5, 6, 80]
        adapter.setup_frame(uc, 0x7FFF8000, SENTINEL_RETURN_ADDRESS, args)
        adapter.set_pc(uc, 0x10000)

        uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
        assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
        assert adapter.read_return_value(uc) == 100  # 20 + 80

    def test_sentinel_return_x86_32_cdecl(self):
        """Verify x86 32-bit cdecl halts cleanly at 0xDEAD0000."""
        adapter = X86_32Adapter()
        uc = adapter.create_engine()
        uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
        uc.mem_map(0x70000000, 0x10000, UC_PROT_ALL)

        # mov eax, [esp + 4] ; add eax, [esp + 8] ; ret
        # 8b 44 24 04 03 44 24 08 c3
        code = b"\x8b\x44\x24\x04\x03\x44\x24\x08\xc3"
        uc.mem_write(0x10000, code)

        adapter.setup_frame(uc, 0x70008000, SENTINEL_RETURN_ADDRESS, [25, 75])
        adapter.set_pc(uc, 0x10000)

        uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
        assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
        assert adapter.read_return_value(uc) == 100


# ============================================================================
# 3. Null Pointer Dereference Trapping Tests (< 0x1000)
# ============================================================================

class TestNullPointerTrapping:
    """Stress-test null pointer dereference traps without crashing process."""

    def _make_mock_session(self, code: bytes, arch: ArchitectureType = ArchitectureType.ARM64) -> tuple[BinarySession, str]:
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(code + b"\x00" * 4096)
            temp_path = f.name

        artifact = TargetArtifact(
            file_path=temp_path,
            format=ArtifactFormat.MACHO if arch == ArchitectureType.ARM64 else ArtifactFormat.ELF,
            architecture=arch,
            bitness=64,
            file_size_bytes=len(code) + 4096,
            sections=[
                BinarySection(
                    name=".text",
                    virtual_address=0x10000,
                    virtual_size=0x1000,
                    raw_offset=0,
                    raw_size=len(code),
                    permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                )
            ],
        )
        session = BinarySession(
            session_id=f"sess_null_{arch.value}",
            artifact=artifact,
            backend_type="mock",
        )
        return session, temp_path

    def test_null_pointer_read_zero_arm64(self):
        """Verify ldr x1, [x0] when x0=0 triggers clean null deref error."""
        code = struct.pack("<I", 0xF9400001)  # ldr x1, [x0]
        session, path = self._make_mock_session(code, ArchitectureType.ARM64)
        try:
            prober = UnicornProber()
            res = prober.trace_function(session, 0x10000, args=[0])
            assert res.success is False
            assert res.error is not None
            assert "Null pointer dereference at 0x0" in res.error
        finally:
            Path(path).unlink(missing_ok=True)

    def test_null_pointer_struct_field_offset_arm64(self):
        """Verify ptr->field access at 0x80 (< 0x1000) traps as null deref."""
        # ldr x1, [x0, #0x80] -> 0xf9404001
        code = struct.pack("<I", 0xF9404001)
        session, path = self._make_mock_session(code, ArchitectureType.ARM64)
        try:
            prober = UnicornProber()
            res = prober.trace_function(session, 0x10000, args=[0])
            assert res.success is False
            assert "Null pointer dereference at 0x80" in res.error
        finally:
            Path(path).unlink(missing_ok=True)

    def test_null_pointer_write_x86_64(self):
        """Verify mov [rdi], rax when rdi=0 triggers clean null deref error on x86_64."""
        code = b"\x48\x89\x07"  # mov [rdi], rax
        session, path = self._make_mock_session(code, ArchitectureType.X86_64)
        try:
            prober = UnicornProber()
            res = prober.trace_function(session, 0x10000, args=[0])
            assert res.success is False
            assert "Null pointer dereference at 0x0" in res.error
        finally:
            Path(path).unlink(missing_ok=True)


# ============================================================================
# 4. Unmapped Memory Auto-Allocation Tests
# ============================================================================

class TestUnmappedMemoryAutoAllocation:
    """Stress-test auto-allocation of unmapped benign memory (> 0x1000)."""

    def test_unmapped_read_write_auto_alloc_success(self):
        """Verify unmapped write and subsequent read at 0x60000 succeeds via auto-alloc."""
        # str x1, [x0] (x0=0x60000, x1=0x1234) ; ldr x0, [x0] ; ret
        code = struct.pack("<III", 0xF9000001, 0xF9400000, 0xD65F03C0)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(code + b"\x00" * 4096)
            path = f.name

        artifact = TargetArtifact(
            file_path=path,
            format=ArtifactFormat.MACHO,
            architecture=ArchitectureType.ARM64,
            bitness=64,
            file_size_bytes=len(code) + 4096,
            sections=[
                BinarySection(
                    name=".text",
                    virtual_address=0x10000,
                    virtual_size=0x1000,
                    raw_offset=0,
                    raw_size=len(code),
                    permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                )
            ],
        )
        session = BinarySession(session_id="sess_auto_alloc", artifact=artifact, backend_type="mock")
        try:
            prober = UnicornProber(auto_alloc_unmapped=True)
            res = prober.trace_function(session, 0x10000, args=[0x60000, 0x1234])
            assert res.success is True
            assert res.return_value == 0x1234
        finally:
            Path(path).unlink(missing_ok=True)

    def test_unmapped_auto_alloc_disabled(self):
        """Verify auto_alloc_unmapped=False halts on unmapped access."""
        code = struct.pack("<II", 0xF9000001, 0xD65F03C0)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(code + b"\x00" * 4096)
            path = f.name

        artifact = TargetArtifact(
            file_path=path,
            format=ArtifactFormat.MACHO,
            architecture=ArchitectureType.ARM64,
            bitness=64,
            file_size_bytes=len(code) + 4096,
            sections=[
                BinarySection(
                    name=".text",
                    virtual_address=0x10000,
                    virtual_size=0x1000,
                    raw_offset=0,
                    raw_size=len(code),
                    permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                )
            ],
        )
        session = BinarySession(session_id="sess_auto_off", artifact=artifact, backend_type="mock")
        try:
            prober = UnicornProber(auto_alloc_unmapped=False)
            res = prober.trace_function(session, 0x10000, args=[0x60000, 0x1234])
            assert res.success is False
            assert "Unmapped memory access at 0x60000" in res.error
        finally:
            Path(path).unlink(missing_ok=True)

    def test_unmapped_scratch_page_exhaustion(self):
        """Verify max_scratch_pages limit halts when exhausted."""
        # Access 3 distinct unmapped pages: 0x30000, 0x40000, 0x50000
        # str x1, [x0] ; str x1, [x2] ; str x1, [x3] ; ret
        # f9000001 f9000041 f9000061 d65f03c0
        code = struct.pack("<IIII", 0xF9000001, 0xF9000041, 0xF9000061, 0xD65F03C0)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(code + b"\x00" * 4096)
            path = f.name

        artifact = TargetArtifact(
            file_path=path,
            format=ArtifactFormat.MACHO,
            architecture=ArchitectureType.ARM64,
            bitness=64,
            file_size_bytes=len(code) + 4096,
            sections=[
                BinarySection(
                    name=".text",
                    virtual_address=0x10000,
                    virtual_size=0x1000,
                    raw_offset=0,
                    raw_size=len(code),
                    permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                )
            ],
        )
        session = BinarySession(session_id="sess_limit", artifact=artifact, backend_type="mock")
        try:
            prober = UnicornProber(auto_alloc_unmapped=True, max_scratch_pages=2)
            # Limit is 2 pages; 3rd page (0x50000) will fault
            res = prober.trace_function(session, 0x10000, args=[0x30000, 1, 0x40000, 0x50000])
            assert res.success is False
            assert "Unmapped memory access at 0x50000" in res.error
        finally:
            Path(path).unlink(missing_ok=True)


# ============================================================================
# 5. Infinite Loop Protection & Timeout Tests
# ============================================================================

class TestInfiniteLoopProtection:
    """Stress-test instruction limits and wall-clock timeout protection."""

    def test_infinite_loop_max_instructions(self):
        """Verify infinite loop (b .) halts exactly at max_instructions limit."""
        # ARM64: b . (0x14000000)
        code = struct.pack("<I", 0x14000000)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(code + b"\x00" * 4096)
            path = f.name

        artifact = TargetArtifact(
            file_path=path,
            format=ArtifactFormat.MACHO,
            architecture=ArchitectureType.ARM64,
            bitness=64,
            file_size_bytes=len(code) + 4096,
            sections=[
                BinarySection(
                    name=".text",
                    virtual_address=0x10000,
                    virtual_size=0x1000,
                    raw_offset=0,
                    raw_size=len(code),
                    permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                )
            ],
        )
        session = BinarySession(session_id="sess_loop", artifact=artifact, backend_type="mock")
        try:
            prober = UnicornProber()
            res = prober.trace_function(session, 0x10000, args=[], max_instructions=50)
            assert res.success is False
            assert res.instructions_executed == 50
            assert "limit reached" in (res.error or "")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_finite_loop_under_instruction_limit_succeeds(self):
        """Verify finite loop running 10 iterations finishes cleanly with success=True."""
        # 0x10000: subs x0, x0, #1  (0xf1000400)
        # 0x10004: b.ne 0x10000      (0x54ffffe1)
        # 0x10008: ret              (0xd65f03c0)
        code = struct.pack("<III", 0xF1000400, 0x54FFFFE1, 0xD65F03C0)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(code + b"\x00" * 4096)
            path = f.name

        artifact = TargetArtifact(
            file_path=path,
            format=ArtifactFormat.MACHO,
            architecture=ArchitectureType.ARM64,
            bitness=64,
            file_size_bytes=len(code) + 4096,
            sections=[
                BinarySection(
                    name=".text",
                    virtual_address=0x10000,
                    virtual_size=0x1000,
                    raw_offset=0,
                    raw_size=len(code),
                    permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                )
            ],
        )
        session = BinarySession(session_id="sess_finite", artifact=artifact, backend_type="mock")
        try:
            prober = UnicornProber()
            res = prober.trace_function(session, 0x10000, args=[10], max_instructions=200)
            assert res.success is True
            assert res.return_value == 0
            assert res.instructions_executed > 10
        finally:
            Path(path).unlink(missing_ok=True)

    def test_wall_clock_timeout_stops_execution(self):
        """Verify timeout_seconds stops long-running execution."""
        code = struct.pack("<I", 0x14000000)  # b .
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(code + b"\x00" * 4096)
            path = f.name

        artifact = TargetArtifact(
            file_path=path,
            format=ArtifactFormat.MACHO,
            architecture=ArchitectureType.ARM64,
            bitness=64,
            file_size_bytes=len(code) + 4096,
            sections=[
                BinarySection(
                    name=".text",
                    virtual_address=0x10000,
                    virtual_size=0x1000,
                    raw_offset=0,
                    raw_size=len(code),
                    permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                )
            ],
        )
        session = BinarySession(session_id="sess_timeout", artifact=artifact, backend_type="mock")
        try:
            prober = UnicornProber()
            t0 = time.time()
            res = prober.trace_function(session, 0x10000, timeout_seconds=0.1, max_instructions=10000000)
            elapsed = time.time() - t0
            assert res.success is False
            assert elapsed < 1.0  # Finished promptly via timeout
            assert "limit reached" in (res.error or "")
        finally:
            Path(path).unlink(missing_ok=True)


# ============================================================================
# 6. Libc Hooks Stress Tests
# ============================================================================

class TestLibcHooks:
    """Stress-test in-memory libc hooks with valid, boundary, and hostile inputs."""

    @pytest.fixture(autouse=True)
    def setup_engine(self):
        self.prober = UnicornProber()
        self.adapter = ARM64Adapter()
        self.uc = self.adapter.create_engine()
        self.heap = HeapManager(self.uc, base_addr=0x600000000000)

    def test_strcmp_comprehensive(self):
        """Verify strcmp under identical, divergent, empty, and NULL strings."""
        p1 = self.heap.allocate_string("alpha")
        p2 = self.heap.allocate_string("alpha")
        p3 = self.heap.allocate_string("beta")
        p_empty = self.heap.allocate_string("")

        # Identical -> 0
        self.uc.reg_write(UC_ARM64_REG_X0, p1)
        self.uc.reg_write(UC_ARM64_REG_X1, p2)
        self.prober._handle_libc_stub(self.uc, "strcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

        # "alpha" vs "beta" -> -1
        self.uc.reg_write(UC_ARM64_REG_X0, p1)
        self.uc.reg_write(UC_ARM64_REG_X1, p3)
        self.prober._handle_libc_stub(self.uc, "strcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == -1

        # "beta" vs "alpha" -> 1
        self.uc.reg_write(UC_ARM64_REG_X0, p3)
        self.uc.reg_write(UC_ARM64_REG_X1, p1)
        self.prober._handle_libc_stub(self.uc, "strcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 1

        # Empty vs Empty -> 0
        self.uc.reg_write(UC_ARM64_REG_X0, p_empty)
        self.uc.reg_write(UC_ARM64_REG_X1, p_empty)
        self.prober._handle_libc_stub(self.uc, "strcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

        # NULL pointer -> safe return without exception
        self.uc.reg_write(UC_ARM64_REG_X0, 0)
        self.uc.reg_write(UC_ARM64_REG_X1, p1)
        self.prober._handle_libc_stub(self.uc, "strcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == -1

    def test_strncmp_comprehensive(self):
        """Verify strncmp with prefix match, prefix mismatch, n=0, and lengths."""
        p1 = self.heap.allocate_string("secret_key_1")
        p2 = self.heap.allocate_string("secret_key_2")

        # Prefix n=10 ("secret_key") matches -> 0
        self.uc.reg_write(UC_ARM64_REG_X0, p1)
        self.uc.reg_write(UC_ARM64_REG_X1, p2)
        self.uc.reg_write(UC_ARM64_REG_X2, 10)
        self.prober._handle_libc_stub(self.uc, "strncmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

        # Full length n=12 mismatches -> -1
        self.uc.reg_write(UC_ARM64_REG_X2, 12)
        self.prober._handle_libc_stub(self.uc, "strncmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == -1

        # n=0 always returns 0
        self.uc.reg_write(UC_ARM64_REG_X2, 0)
        self.prober._handle_libc_stub(self.uc, "strncmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

    def test_strlen_comprehensive(self):
        """Verify strlen with standard, empty, and NULL strings."""
        p = self.heap.allocate_string("abcdefgh")
        p_empty = self.heap.allocate_string("")

        self.uc.reg_write(UC_ARM64_REG_X0, p)
        self.prober._handle_libc_stub(self.uc, "strlen", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 8

        self.uc.reg_write(UC_ARM64_REG_X0, p_empty)
        self.prober._handle_libc_stub(self.uc, "strlen", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

        self.uc.reg_write(UC_ARM64_REG_X0, 0)
        self.prober._handle_libc_stub(self.uc, "strlen", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

    def test_memcmp_comprehensive(self):
        """Verify memcmp with embedded nulls, binary payloads, and n=0."""
        b1 = b"\x00\x01\x02\x00\x03"
        b2 = b"\x00\x01\x02\x00\x03"
        b3 = b"\x00\x01\x02\x00\x04"

        p1 = self.heap.allocate(len(b1), b1)
        p2 = self.heap.allocate(len(b2), b2)
        p3 = self.heap.allocate(len(b3), b3)

        self.uc.reg_write(UC_ARM64_REG_X0, p1)
        self.uc.reg_write(UC_ARM64_REG_X1, p2)
        self.uc.reg_write(UC_ARM64_REG_X2, len(b1))
        self.prober._handle_libc_stub(self.uc, "memcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

        # Reset X0 (since set_ret overwrote X0 with return value 0)
        self.uc.reg_write(UC_ARM64_REG_X0, p1)
        self.uc.reg_write(UC_ARM64_REG_X1, p3)
        self.uc.reg_write(UC_ARM64_REG_X2, len(b1))
        self.prober._handle_libc_stub(self.uc, "memcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == -1

        # n=0 returns 0
        self.uc.reg_write(UC_ARM64_REG_X0, p1)
        self.uc.reg_write(UC_ARM64_REG_X1, p3)
        self.uc.reg_write(UC_ARM64_REG_X2, 0)
        self.prober._handle_libc_stub(self.uc, "memcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

        # Note: memcmp with NULL/unmapped returns 0 due to try..except fallback
        self.uc.reg_write(UC_ARM64_REG_X0, 0)
        self.uc.reg_write(UC_ARM64_REG_X1, p3)
        self.uc.reg_write(UC_ARM64_REG_X2, len(b1))
        self.prober._handle_libc_stub(self.uc, "memcmp", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0

    def test_strncpy_and_strcpy(self):
        """Verify strncpy and strcpy buffer copying and null padding."""
        src = self.heap.allocate_string("sample_string")
        dst = self.heap.allocate(32)

        # strncpy 6 bytes
        self.uc.reg_write(UC_ARM64_REG_X0, dst)
        self.uc.reg_write(UC_ARM64_REG_X1, src)
        self.uc.reg_write(UC_ARM64_REG_X2, 6)
        self.prober._handle_libc_stub(self.uc, "strncpy", self.adapter)
        assert bytes(self.uc.mem_read(dst, 6)) == b"sample"

        # strcpy full string
        dst2 = self.heap.allocate(32)
        self.uc.reg_write(UC_ARM64_REG_X0, dst2)
        self.uc.reg_write(UC_ARM64_REG_X1, src)
        self.prober._handle_libc_stub(self.uc, "strcpy", self.adapter)
        assert bytes(self.uc.mem_read(dst2, 14)) == b"sample_string\x00"

    def test_memcpy_and_memset(self):
        """Verify memcpy raw buffer copy and memset pattern filling."""
        src = self.heap.allocate(8, b"\xca\xfe\xba\xbe\x01\x02\x03\x04")
        dst = self.heap.allocate(8)

        self.uc.reg_write(UC_ARM64_REG_X0, dst)
        self.uc.reg_write(UC_ARM64_REG_X1, src)
        self.uc.reg_write(UC_ARM64_REG_X2, 8)
        self.prober._handle_libc_stub(self.uc, "memcpy", self.adapter)
        assert bytes(self.uc.mem_read(dst, 8)) == b"\xca\xfe\xba\xbe\x01\x02\x03\x04"

        # memset 4 bytes to 0x55
        self.uc.reg_write(UC_ARM64_REG_X1, 0x55)
        self.uc.reg_write(UC_ARM64_REG_X2, 4)
        self.prober._handle_libc_stub(self.uc, "memset", self.adapter)
        assert bytes(self.uc.mem_read(dst, 4)) == b"\x55\x55\x55\x55"
        assert bytes(self.uc.mem_read(dst + 4, 4)) == b"\x01\x02\x03\x04"

    def test_atoi_cases(self):
        """Verify atoi with integers, negative numbers, whitespace, and garbage."""
        cases = [
            ("98765", 98765),
            ("-4321", -4321),
            ("0", 0),
            ("  100  ", 100),
            ("invalid_text", 0),
            ("", 0),
        ]
        for s_val, expected in cases:
            p = self.heap.allocate_string(s_val)
            self.uc.reg_write(UC_ARM64_REG_X0, p)
            self.prober._handle_libc_stub(self.uc, "atoi", self.adapter)
            assert self.adapter.read_return_value(self.uc) == expected

        # NULL pointer
        self.uc.reg_write(UC_ARM64_REG_X0, 0)
        self.prober._handle_libc_stub(self.uc, "atoi", self.adapter)
        assert self.adapter.read_return_value(self.uc) == 0


# ============================================================================
# 7. HeapManager Bounds & Alignment Tests
# ============================================================================

class TestHeapManager:
    """Stress-test HeapManager alignment and bounds checking."""

    def test_heap_manager_alignment(self):
        """Verify allocations are 16-byte aligned."""
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        heap = HeapManager(uc, base_addr=0x600000000000, max_size=0x100000)

        p1 = heap.allocate(7)
        p2 = heap.allocate(11)
        p3 = heap.allocate(1)

        assert p1 % 16 == 0
        assert p2 % 16 == 0
        assert p3 % 16 == 0
        assert p2 >= p1 + 16
        assert p3 >= p2 + 16

    def test_heap_exhaustion_raises_memory_error(self):
        """Verify allocating past max_size raises MemoryError."""
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        heap = HeapManager(uc, base_addr=0x600000000000, max_size=0x10000)

        # Allocate 0x8000 successfully
        heap.allocate(0x8000)
        # Allocate another 0x8000 exceeds 0x10000 limit
        with pytest.raises(MemoryError, match="Emulated heap exhausted"):
            heap.allocate(0x8000)


# ============================================================================
# 8. Real Stripped Target Binary Micro-Emulation
# ============================================================================

class TestRealStrippedBinaryMicroEmulation:
    """Verify micro-emulation on real stripped benchmark target c_service_stripped."""

    def test_config_init_default_and_fact_extraction(self, c_service_stripped_path: Path):
        """Verify _config_init_default initializes secret token in memory."""
        session = global_session_manager.create_session(str(c_service_stripped_path))
        prober = UnicornProber()

        res = prober.trace_function(session, 0x100000894, args=[{"size": 512}])
        assert res.success is True
        assert res.prober == "unicorn"
        assert res.instructions_executed > 10
        assert any("metis_default_secret_token_2026" in s for s in res.captured_strings)

    def test_session_authenticate_differential_vectors(self, c_service_stripped_path: Path):
        """Verify _session_authenticate differentiates valid vs invalid vs empty tokens."""
        session = global_session_manager.create_session(str(c_service_stripped_path))
        prober = UnicornProber()

        cfg_buf = (
            struct.pack("<III", 0x53455256, 8080, 128)
            + b"metis_default_secret_token_2026".ljust(64, b"\x00")
            + struct.pack("<II", 1, 5000)
        )

        # Valid token -> 1
        res_valid = prober.trace_function(
            session,
            0x100000ac8,
            args=[{"size": 128}, cfg_buf, "metis_default_secret_token_2026"],
        )
        assert res_valid.success is True
        assert res_valid.return_value == 1

        # Invalid token -> 0
        res_invalid = prober.trace_function(
            session,
            0x100000ac8,
            args=[{"size": 128}, cfg_buf, "attacker_invalid_secret"],
        )
        assert res_invalid.success is True
        assert res_invalid.return_value == 0

        # Empty token -> 0
        res_empty = prober.trace_function(
            session,
            0x100000ac8,
            args=[{"size": 128}, cfg_buf, ""],
        )
        assert res_empty.success is True
        assert res_empty.return_value == 0
