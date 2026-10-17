"""
Milestone 3 Adversarial Stress & Edge Case Test Suite for Dynamic Tracing & UnicornProber.
Authored by Challenger M3-1.

Challenge Dimensions:
1. Page coalescing with weird, overlapping, zero-sized, and misaligned sections.
2. Deterministic sentinel return trapping at 0xDEAD0000 across ARM64, x86_64, and x86_32.
3. Null pointer dereference trapping (< 0x1000) for reads, writes, and execution jumps.
4. Unmapped memory auto-allocation (> 0x1000), scratch page limits, and auto_alloc=False.
5. Infinite loop protection via instruction count and wall-clock timeout.
6. Libc hooks (strcmp, strncmp, strlen, memcmp, strncpy, strcpy, memcpy, memset, atoi)
   under valid, empty, boundary, and hostile/NULL inputs.
7. Heap manager bounds exhaustion and allocation alignment.
8. End-to-end adversarial micro-emulation on real stripped Mach-O binary.
"""

from __future__ import annotations

import struct
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
# Dimension 1: Page Coalescing Stress & Edge Cases
# ============================================================================

def test_page_coalescing_empty_and_zero_sizes():
    """Verify empty lists, zero sizes, and negative sizes are safely handled."""
    assert build_page_mappings([]) == []

    # Slices with zero or negative virtual sizes must be skipped
    slices = [
        (0x1000, 0, b"", UC_PROT_READ),
        (0x2000, -100, b"ABCD", UC_PROT_WRITE),
        (0x3000, 0, b"XYZ", UC_PROT_EXEC),
    ]
    assert build_page_mappings(slices) == []


def test_page_coalescing_overlapping_and_permission_merging():
    """Verify overlapping slices merge permissions and later slice overwrites bytes."""
    slices = [
        (0x1000, 0x50, b"\xaa" * 0x50, UC_PROT_READ),
        (0x1020, 0x60, b"\xbb" * 0x60, UC_PROT_WRITE),
    ]
    blocks = build_page_mappings(slices, page_size=4096)
    assert len(blocks) == 1
    base_addr, size, content, prot = blocks[0]

    assert base_addr == 0x1000
    assert size == 4096
    assert prot == (UC_PROT_READ | UC_PROT_WRITE)

    # 0x00..0x20: \xaa
    assert content[0:0x20] == b"\xaa" * 0x20
    # 0x20..0x80: overwritten by \xbb
    assert content[0x20:0x80] == b"\xbb" * 0x60
    # 0x80..0x1000: zero filled
    assert content[0x80:4096] == b"\x00" * (4096 - 0x80)


def test_page_coalescing_bss_zero_fill():
    """Verify BSS sections with virtual size exceeding content length are zero-filled."""
    # Virtual size of 2 pages (8192 bytes), but empty content
    slices = [
        (0x4000, 8192, b"", UC_PROT_READ | UC_PROT_WRITE),
    ]
    blocks = build_page_mappings(slices, page_size=4096)
    assert len(blocks) == 1
    base_addr, size, content, prot = blocks[0]
    assert base_addr == 0x4000
    assert size == 8192
    assert len(content) == 8192
    assert content == b"\x00" * 8192


def test_page_coalescing_adjacent_pages_different_permissions():
    """Verify adjacent pages with different permissions are kept as distinct blocks."""
    slices = [
        (0x1000, 4096, b"\x11" * 4096, UC_PROT_READ | UC_PROT_EXEC),
        (0x2000, 4096, b"\x22" * 4096, UC_PROT_READ | UC_PROT_WRITE),
    ]
    blocks = build_page_mappings(slices, page_size=4096)
    assert len(blocks) == 2
    assert blocks[0][0] == 0x1000
    assert blocks[0][1] == 4096
    assert blocks[0][3] == (UC_PROT_READ | UC_PROT_EXEC)

    assert blocks[1][0] == 0x2000
    assert blocks[1][1] == 4096
    assert blocks[1][3] == (UC_PROT_READ | UC_PROT_WRITE)


def test_page_coalescing_misaligned_unaligned_slices():
    """Verify arbitrary unaligned addresses coalesce into valid 4KB page boundaries."""
    slices = [
        (0x1005, 7, b"HELLO12", UC_PROT_READ),
        (0x10FE, 4, b"TEST", UC_PROT_READ),
    ]
    blocks = build_page_mappings(slices, page_size=4096)
    assert len(blocks) == 1
    addr, size, content, prot = blocks[0]
    assert addr == 0x1000
    assert size == 4096
    assert content[5:12] == b"HELLO12"
    assert content[0xFE:0xFE + 4] == b"TEST"


def test_page_coalescing_dense_fragmentation():
    """Verify 64 contiguous 64-byte slices merge into a single 4096-byte block."""
    slices = [
        (0x1000 + (i * 64), 64, bytes([i]) * 64, UC_PROT_READ | UC_PROT_WRITE)
        for i in range(64)
    ]
    blocks = build_page_mappings(slices, page_size=4096)
    assert len(blocks) == 1
    addr, size, content, prot = blocks[0]
    assert addr == 0x1000
    assert size == 4096
    for i in range(64):
        assert content[i * 64 : (i + 1) * 64] == bytes([i]) * 64


# ============================================================================
# Dimension 2: Deterministic Sentinel Return Trapping (ARM64 & x86_64 & x86_32)
# ============================================================================

def test_sentinel_return_trapping_arm64():
    """Verify clean stop at 0xDEAD0000 on ARM64 with return value extraction."""
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
    uc.mem_map(0x7FFF0000, 0x10000, UC_PROT_ALL)

    # ARM64: add x0, x0, x1; ret
    # add x0, x0, x1 = 0x8b010000
    # ret            = 0xd65f03c0
    code = struct.pack("<II", 0x8B010000, 0xD65F03C0)
    uc.mem_write(0x10000, code)

    adapter.setup_frame(uc, 0x7FFF8000, SENTINEL_RETURN_ADDRESS, [40, 2])
    adapter.set_pc(uc, 0x10000)

    uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
    final_pc = adapter.read_pc(uc)
    ret_val = adapter.read_return_value(uc)

    assert final_pc == SENTINEL_RETURN_ADDRESS
    assert ret_val == 42


def test_sentinel_return_trapping_arm64_many_args_and_nested_call():
    """Verify ARM64 stack arguments (> 8 args) and nested function calling."""
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
    uc.mem_map(0x7FFF0000, 0x10000, UC_PROT_ALL)

    # 10 arguments passed: x0..x7 in registers, 9th and 10th on stack [sp] and [sp+8]
    # Function at 0x10000:
    # ldr x8, [sp]      (0xf94003e8)
    # add x0, x0, x8    (0x8b080000)
    # ret               (0xd65f03c0)
    code = struct.pack("<III", 0xF94003E8, 0x8B080000, 0xD65F03C0)
    uc.mem_write(0x10000, code)

    args = [1, 2, 3, 4, 5, 6, 7, 8, 100, 200]
    adapter.setup_frame(uc, 0x7FFF8000, SENTINEL_RETURN_ADDRESS, args)
    adapter.set_pc(uc, 0x10000)

    uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
    assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
    assert adapter.read_return_value(uc) == 101  # 1 + 100


def test_sentinel_return_trapping_x86_64():
    """Verify clean stop at 0xDEAD0000 on x86_64 with System V ABI."""
    adapter = X86_64Adapter()
    uc = adapter.create_engine()
    uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
    uc.mem_map(0x7FFF0000, 0x10000, UC_PROT_ALL)

    # x86_64: lea rax, [rdi + rsi]; ret
    # 48 8d 04 37 c3
    code = b"\x48\x8d\x04\x37\xc3"
    uc.mem_write(0x10000, code)

    adapter.setup_frame(uc, 0x7FFF8000, SENTINEL_RETURN_ADDRESS, [15, 27])
    adapter.set_pc(uc, 0x10000)

    uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
    assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
    assert adapter.read_return_value(uc) == 42


def test_sentinel_return_trapping_x86_64_stack_args():
    """Verify x86_64 stack arguments (> 6 args: RDI, RSI, RDX, RCX, R8, R9, [rsp+8])."""
    adapter = X86_64Adapter()
    uc = adapter.create_engine()
    uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
    uc.mem_map(0x7FFF0000, 0x10000, UC_PROT_ALL)

    # 7 arguments: 7th is at [rsp + 8] (because [rsp] is sentinel return address)
    # mov rax, [rsp + 8] ; add rax, rdi ; ret
    # 48 8b 44 24 08 48 01 f8 c3
    code = b"\x48\x8b\x44\x24\x08\x48\x01\xf8\xc3"
    uc.mem_write(0x10000, code)

    args = [10, 20, 30, 40, 50, 60, 500]
    adapter.setup_frame(uc, 0x7FFF8000, SENTINEL_RETURN_ADDRESS, args)
    adapter.set_pc(uc, 0x10000)

    uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
    assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
    assert adapter.read_return_value(uc) == 510  # 10 + 500


def test_sentinel_return_trapping_x86_32():
    """Verify clean stop at 0xDEAD0000 on x86 32-bit (cdecl)."""
    adapter = X86_32Adapter()
    uc = adapter.create_engine()
    uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
    uc.mem_map(0x70000000, 0x10000, UC_PROT_ALL)

    # cdecl: mov eax, [esp + 4] ; add eax, [esp + 8] ; ret
    # 8b 44 24 04 03 44 24 08 c3
    code = b"\x8b\x44\x24\x04\x03\x44\x24\x08\xc3"
    uc.mem_write(0x10000, code)

    adapter.setup_frame(uc, 0x70008000, SENTINEL_RETURN_ADDRESS, [11, 22])
    adapter.set_pc(uc, 0x10000)

    uc.emu_start(0x10000, until=SENTINEL_RETURN_ADDRESS)
    assert adapter.read_pc(uc) == SENTINEL_RETURN_ADDRESS
    assert adapter.read_return_value(uc) == 33


# ============================================================================
# Dimension 3: Null Pointer Dereference Trapping (< 0x1000)
# ============================================================================

def test_null_pointer_read_trap_arm64():
    """Verify null pointer dereference read (< 0x1000) halts cleanly and records fault."""
    prober = UnicornProber()
    # Mock session with ARM64
    artifact = TargetArtifact(
        file_path="/tmp/mock_bin",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        bitness=64,
        file_size_bytes=1024,
        sections=[
            BinarySection(
                name="__text",
                virtual_address=0x10000,
                virtual_size=0x1000,
                raw_offset=0,
                raw_size=0x100,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                entropy=0.0,
            )
        ],
    )
    session = BinarySession(
        session_id="sess_mock_null",
        artifact=artifact,
        backend_type="mock",
    )

    # ldr x1, [x0] where x0 = 0
    # 0xf9400001
    code = struct.pack("<I", 0xF9400001)

    import tempfile
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(code + b"\x00" * 4096)
        temp_path = f.name

    artifact.file_path = temp_path
    try:
        res = prober.trace_function(session, 0x10000, args=[0])
        assert res.success is False
        assert res.error is not None
        assert "Null pointer dereference at 0x0" in res.error
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_null_pointer_struct_offset_trap_arm64():
    """Verify offset access inside page zero (e.g. ptr->field at 0x38) traps as null deref."""
    prober = UnicornProber()
    artifact = TargetArtifact(
        file_path="/tmp/mock_bin_offset",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        bitness=64,
        file_size_bytes=1024,
        sections=[
            BinarySection(
                name="__text",
                virtual_address=0x10000,
                virtual_size=0x1000,
                raw_offset=0,
                raw_size=0x100,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                entropy=0.0,
            )
        ],
    )
    session = BinarySession(
        session_id="sess_mock_offset",
        artifact=artifact,
        backend_type="mock",
    )

    # ldr x1, [x0, #0x38] where x0 = 0 -> reads 0x38 (< 0x1000)
    # 0xf9401c01
    code = struct.pack("<I", 0xF9401C01)

    import tempfile
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(code + b"\x00" * 4096)
        temp_path = f.name

    artifact.file_path = temp_path
    try:
        res = prober.trace_function(session, 0x10000, args=[0])
        assert res.success is False
        assert "Null pointer dereference at 0x38" in res.error
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_null_pointer_write_trap_x86_64():
    """Verify null pointer write on x86_64 halts cleanly with error."""
    prober = UnicornProber()
    artifact = TargetArtifact(
        file_path="/tmp/mock_bin_x86_null",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.X86_64,
        bitness=64,
        file_size_bytes=1024,
        sections=[
            BinarySection(
                name="__text",
                virtual_address=0x10000,
                virtual_size=0x1000,
                raw_offset=0,
                raw_size=0x100,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                entropy=0.0,
            )
        ],
    )
    session = BinarySession(
        session_id="sess_mock_x86_null",
        artifact=artifact,
        backend_type="mock",
    )

    # mov qword ptr [rdi], 0x1337 where rdi = 0
    # 48 c7 07 37 13 00 00
    code = b"\x48\xc7\x07\x37\x13\x00\x00"

    import tempfile
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(code + b"\x00" * 4096)
        temp_path = f.name

    artifact.file_path = temp_path
    try:
        res = prober.trace_function(session, 0x10000, args=[0])
        assert res.success is False
        assert "Null pointer dereference at 0x0" in res.error
    finally:
        Path(temp_path).unlink(missing_ok=True)


# ============================================================================
# Dimension 4: Unmapped Memory Auto-Allocation (> 0x1000) & Limits
# ============================================================================

def test_unmapped_memory_auto_allocation_success():
    """Verify writing/reading unmapped benign address (> 0x1000) succeeds via auto-alloc."""
    prober = UnicornProber(auto_alloc_unmapped=True)
    artifact = TargetArtifact(
        file_path="/tmp/mock_auto_alloc",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        bitness=64,
        file_size_bytes=1024,
        sections=[
            BinarySection(
                name="__text",
                virtual_address=0x10000,
                virtual_size=0x1000,
                raw_offset=0,
                raw_size=0x100,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                entropy=0.0,
            )
        ],
    )
    session = BinarySession(
        session_id="sess_mock_auto_alloc",
        artifact=artifact,
        backend_type="mock",
    )

    # Write 0x99 to unmapped address 0x50000, read it back into x0, and ret
    # str x1, [x0] (x0=0x50000, x1=0x99) -> 0xf9000001
    # ldr x0, [x0]                       -> 0xf9400000
    # ret                                -> 0xd65f03c0
    code = struct.pack("<III", 0xF9000001, 0xF9400000, 0xD65F03C0)

    import tempfile
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(code + b"\x00" * 4096)
        temp_path = f.name

    artifact.file_path = temp_path
    try:
        res = prober.trace_function(session, 0x10000, args=[0x50000, 0x99])
        assert res.success is True
        assert res.return_value == 0x99
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_unmapped_memory_disabled_auto_allocation():
    """Verify auto_alloc_unmapped=False halts immediately on unmapped access."""
    prober = UnicornProber(auto_alloc_unmapped=False)
    artifact = TargetArtifact(
        file_path="/tmp/mock_auto_alloc_off",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        bitness=64,
        file_size_bytes=1024,
        sections=[
            BinarySection(
                name="__text",
                virtual_address=0x10000,
                virtual_size=0x1000,
                raw_offset=0,
                raw_size=0x100,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                entropy=0.0,
            )
        ],
    )
    session = BinarySession(
        session_id="sess_mock_auto_off",
        artifact=artifact,
        backend_type="mock",
    )

    code = struct.pack("<II", 0xF9000001, 0xD65F03C0)

    import tempfile
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(code + b"\x00" * 4096)
        temp_path = f.name

    artifact.file_path = temp_path
    try:
        res = prober.trace_function(session, 0x10000, args=[0x50000, 0x99])
        assert res.success is False
        assert "Unmapped memory access at 0x50000" in res.error
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_unmapped_scratch_page_exhaustion_limit():
    """Verify max_scratch_pages limit halts execution when exhausted."""
    prober = UnicornProber(auto_alloc_unmapped=True, max_scratch_pages=2)
    artifact = TargetArtifact(
        file_path="/tmp/mock_scratch_limit",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        bitness=64,
        file_size_bytes=1024,
        sections=[
            BinarySection(
                name="__text",
                virtual_address=0x10000,
                virtual_size=0x1000,
                raw_offset=0,
                raw_size=0x100,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                entropy=0.0,
            )
        ],
    )
    session = BinarySession(
        session_id="sess_mock_scratch_limit",
        artifact=artifact,
        backend_type="mock",
    )

    # Access page 1: 0x20000 (allowed)
    # Access page 2: 0x30000 (allowed)
    # Access page 3: 0x40000 (exceeds limit 2 -> fault)
    # str x1, [x0] (0x20000) -> 0xf9000001
    # str x1, [x2] (0x30000) -> 0xf9000041
    # str x1, [x3] (0x40000) -> 0xf9000061
    # ret                    -> 0xd65f03c0
    code = struct.pack("<IIII", 0xF9000001, 0xF9000041, 0xF9000061, 0xD65F03C0)

    import tempfile
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(code + b"\x00" * 4096)
        temp_path = f.name

    artifact.file_path = temp_path
    try:
        res = prober.trace_function(session, 0x10000, args=[0x20000, 1, 0x30000, 0x40000])
        assert res.success is False
        assert "Unmapped memory access at 0x40000" in res.error
    finally:
        Path(temp_path).unlink(missing_ok=True)


# ============================================================================
# Dimension 5: Infinite Loop Protection & Timeouts
# ============================================================================

def test_infinite_loop_max_instructions_halt():
    """Verify execution halts safely when max_instructions is reached."""
    prober = UnicornProber()
    artifact = TargetArtifact(
        file_path="/tmp/mock_loop",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        bitness=64,
        file_size_bytes=1024,
        sections=[
            BinarySection(
                name="__text",
                virtual_address=0x10000,
                virtual_size=0x1000,
                raw_offset=0,
                raw_size=0x100,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                entropy=0.0,
            )
        ],
    )
    session = BinarySession(
        session_id="sess_mock_loop",
        artifact=artifact,
        backend_type="mock",
    )

    # ARM64: b . (0x14000000)
    code = struct.pack("<I", 0x14000000)

    import tempfile
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(code + b"\x00" * 4096)
        temp_path = f.name

    artifact.file_path = temp_path
    try:
        res = prober.trace_function(session, 0x10000, args=[], max_instructions=100)
        assert res.success is False
        assert res.instructions_executed == 100
        assert "limit reached" in res.error
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_finite_loop_under_instruction_limit_succeeds():
    """Verify finite loop running 10 iterations finishes cleanly with success=True."""
    prober = UnicornProber()
    artifact = TargetArtifact(
        file_path="/tmp/mock_finite_loop",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        bitness=64,
        file_size_bytes=1024,
        sections=[
            BinarySection(
                name="__text",
                virtual_address=0x10000,
                virtual_size=0x1000,
                raw_offset=0,
                raw_size=0x100,
                permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                entropy=0.0,
            )
        ],
    )
    session = BinarySession(
        session_id="sess_mock_finite_loop",
        artifact=artifact,
        backend_type="mock",
    )

    # Loop 10 times:
    # 0x10000: subs x0, x0, #1  (0xf1000400)
    # 0x10004: b.ne 0x10000      (0x54ffffe1)
    # 0x10008: ret              (0xd65f03c0)
    code = struct.pack("<III", 0xF1000400, 0x54FFFFE1, 0xD65F03C0)

    import tempfile
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(code + b"\x00" * 4096)
        temp_path = f.name

    artifact.file_path = temp_path
    try:
        res = prober.trace_function(session, 0x10000, args=[10], max_instructions=500)
        assert res.success is True
        assert res.instructions_executed > 10
        assert res.return_value == 0
    finally:
        Path(temp_path).unlink(missing_ok=True)


# ============================================================================
# Dimension 6: Libc Hooks Stress Testing
# ============================================================================

def test_libc_hooks_strcmp_variants():
    """Verify strcmp under identical, divergent, empty, and NULL strings."""
    prober = UnicornProber()
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    heap = HeapManager(uc, base_addr=0x600000000000)

    p_hello = heap.allocate_string("hello")
    p_hello2 = heap.allocate_string("hello")
    p_world = heap.allocate_string("world")
    p_empty = heap.allocate_string("")
    p_null = 0

    # 1. Identical strings -> 0
    uc.reg_write(UC_ARM64_REG_X0, p_hello)
    uc.reg_write(UC_ARM64_REG_X1, p_hello2)
    prober._handle_libc_stub(uc, "strcmp", adapter)
    assert adapter.read_return_value(uc) == 0

    # 2. "hello" vs "world" -> -1
    uc.reg_write(UC_ARM64_REG_X0, p_hello)
    uc.reg_write(UC_ARM64_REG_X1, p_world)
    prober._handle_libc_stub(uc, "strcmp", adapter)
    assert adapter.read_return_value(uc) == -1

    # 3. "world" vs "hello" -> 1
    uc.reg_write(UC_ARM64_REG_X0, p_world)
    uc.reg_write(UC_ARM64_REG_X1, p_hello)
    prober._handle_libc_stub(uc, "strcmp", adapter)
    assert adapter.read_return_value(uc) == 1

    # 4. Empty vs Empty -> 0
    uc.reg_write(UC_ARM64_REG_X0, p_empty)
    uc.reg_write(UC_ARM64_REG_X1, p_empty)
    prober._handle_libc_stub(uc, "strcmp", adapter)
    assert adapter.read_return_value(uc) == 0

    # 5. Empty vs Non-empty -> -1
    uc.reg_write(UC_ARM64_REG_X0, p_empty)
    uc.reg_write(UC_ARM64_REG_X1, p_hello)
    prober._handle_libc_stub(uc, "strcmp", adapter)
    assert adapter.read_return_value(uc) == -1

    # 6. NULL pointer passed safely -> returns without exception
    uc.reg_write(UC_ARM64_REG_X0, p_null)
    uc.reg_write(UC_ARM64_REG_X1, p_hello)
    prober._handle_libc_stub(uc, "strcmp", adapter)
    assert adapter.read_return_value(uc) == -1


def test_libc_hooks_strncmp_variants():
    """Verify strncmp prefix matching, n=0, and length limits."""
    prober = UnicornProber()
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    heap = HeapManager(uc, base_addr=0x600000000000)

    p_prefix1 = heap.allocate_string("token_alpha_1")
    p_prefix2 = heap.allocate_string("token_alpha_2")

    # Match for n=11 ("token_alpha")
    uc.reg_write(UC_ARM64_REG_X0, p_prefix1)
    uc.reg_write(UC_ARM64_REG_X1, p_prefix2)
    uc.reg_write(UC_ARM64_REG_X2, 11)
    prober._handle_libc_stub(uc, "strncmp", adapter)
    assert adapter.read_return_value(uc) == 0

    # Mismatch for n=13 ("token_alpha_1" vs "token_alpha_2")
    uc.reg_write(UC_ARM64_REG_X2, 13)
    prober._handle_libc_stub(uc, "strncmp", adapter)
    assert adapter.read_return_value(uc) == -1

    # n = 0 must return 0 regardless of strings
    uc.reg_write(UC_ARM64_REG_X2, 0)
    prober._handle_libc_stub(uc, "strncmp", adapter)
    assert adapter.read_return_value(uc) == 0


def test_libc_hooks_strlen_variants():
    """Verify strlen with standard, empty, and NULL strings."""
    prober = UnicornProber()
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    heap = HeapManager(uc, base_addr=0x600000000000)

    p_str = heap.allocate_string("1234567890")
    p_empty = heap.allocate_string("")

    # Normal string
    uc.reg_write(UC_ARM64_REG_X0, p_str)
    prober._handle_libc_stub(uc, "strlen", adapter)
    assert adapter.read_return_value(uc) == 10

    # Empty string
    uc.reg_write(UC_ARM64_REG_X0, p_empty)
    prober._handle_libc_stub(uc, "strlen", adapter)
    assert adapter.read_return_value(uc) == 0

    # NULL pointer -> returns 0 safely
    uc.reg_write(UC_ARM64_REG_X0, 0)
    prober._handle_libc_stub(uc, "strlen", adapter)
    assert adapter.read_return_value(uc) == 0


def test_libc_hooks_memcmp_variants():
    """Verify memcmp with binary payloads, embedded nulls, n=0, and NULL pointers."""
    prober = UnicornProber()
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    heap = HeapManager(uc, base_addr=0x600000000000)

    raw1 = b"\x01\x00\x02\x00\x03\x04"
    raw2 = b"\x01\x00\x02\x00\x03\x04"
    raw3 = b"\x01\x00\x02\x00\x03\x05"

    p1 = heap.allocate(len(raw1), raw1)
    p2 = heap.allocate(len(raw2), raw2)
    p3 = heap.allocate(len(raw3), raw3)

    # Identical with embedded nulls
    uc.reg_write(UC_ARM64_REG_X0, p1)
    uc.reg_write(UC_ARM64_REG_X1, p2)
    uc.reg_write(UC_ARM64_REG_X2, len(raw1))
    prober._handle_libc_stub(uc, "memcmp", adapter)
    assert adapter.read_return_value(uc) == 0

    # Different on last byte
    uc.reg_write(UC_ARM64_REG_X0, p1)
    uc.reg_write(UC_ARM64_REG_X1, p3)
    uc.reg_write(UC_ARM64_REG_X2, len(raw1))
    prober._handle_libc_stub(uc, "memcmp", adapter)
    assert adapter.read_return_value(uc) == -1

    # n = 0 -> 0
    uc.reg_write(UC_ARM64_REG_X2, 0)
    prober._handle_libc_stub(uc, "memcmp", adapter)
    assert adapter.read_return_value(uc) == 0

    # NULL pointer -> 0 safely
    uc.reg_write(UC_ARM64_REG_X0, 0)
    uc.reg_write(UC_ARM64_REG_X1, p1)
    uc.reg_write(UC_ARM64_REG_X2, 4)
    prober._handle_libc_stub(uc, "memcmp", adapter)
    assert adapter.read_return_value(uc) == 0


def test_libc_hooks_strncpy_and_strcpy():
    """Verify strncpy and strcpy buffer manipulation."""
    prober = UnicornProber()
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    heap = HeapManager(uc, base_addr=0x600000000000)

    src = heap.allocate_string("sample_text")
    dst = heap.allocate(32)

    # strncpy 6 chars ("sample")
    uc.reg_write(UC_ARM64_REG_X0, dst)
    uc.reg_write(UC_ARM64_REG_X1, src)
    uc.reg_write(UC_ARM64_REG_X2, 6)
    prober._handle_libc_stub(uc, "strncpy", adapter)
    assert adapter.read_return_value(uc) == dst
    assert bytes(uc.mem_read(dst, 6)) == b"sample"

    # strcpy full string
    dst2 = heap.allocate(32)
    uc.reg_write(UC_ARM64_REG_X0, dst2)
    uc.reg_write(UC_ARM64_REG_X1, src)
    prober._handle_libc_stub(uc, "strcpy", adapter)
    assert adapter.read_return_value(uc) == dst2
    assert bytes(uc.mem_read(dst2, 12)) == b"sample_text\x00"


def test_libc_hooks_memcpy_and_memset():
    """Verify memcpy and memset."""
    prober = UnicornProber()
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    heap = HeapManager(uc, base_addr=0x600000000000)

    src = heap.allocate(16, b"\xde\xad\xbe\xef" * 4)
    dst = heap.allocate(16)

    # memcpy 16 bytes
    uc.reg_write(UC_ARM64_REG_X0, dst)
    uc.reg_write(UC_ARM64_REG_X1, src)
    uc.reg_write(UC_ARM64_REG_X2, 16)
    prober._handle_libc_stub(uc, "memcpy", adapter)
    assert bytes(uc.mem_read(dst, 16)) == b"\xde\xad\xbe\xef" * 4

    # memset 8 bytes to 0x77
    uc.reg_write(UC_ARM64_REG_X0, dst)
    uc.reg_write(UC_ARM64_REG_X1, 0x77)
    uc.reg_write(UC_ARM64_REG_X2, 8)
    prober._handle_libc_stub(uc, "memset", adapter)
    assert bytes(uc.mem_read(dst, 8)) == b"\x77" * 8
    assert bytes(uc.mem_read(dst + 8, 8)) == b"\xde\xad\xbe\xef" * 2


def test_libc_hooks_atoi():
    """Verify atoi parsing of integers, negatives, whitespace, and garbage."""
    prober = UnicornProber()
    adapter = ARM64Adapter()
    uc = adapter.create_engine()
    heap = HeapManager(uc, base_addr=0x600000000000)

    tests = [
        ("12345", 12345),
        ("-678", -678),
        ("0", 0),
        ("   42   ", 42),
        ("invalid", 0),
        ("", 0),
    ]
    for text, expected in tests:
        p = heap.allocate_string(text)
        uc.reg_write(UC_ARM64_REG_X0, p)
        prober._handle_libc_stub(uc, "atoi", adapter)
        assert adapter.read_return_value(uc) == expected

    # NULL pointer
    uc.reg_write(UC_ARM64_REG_X0, 0)
    prober._handle_libc_stub(uc, "atoi", adapter)
    assert adapter.read_return_value(uc) == 0


# ============================================================================
# Dimension 7: Heap Manager Stress & Limits
# ============================================================================

def test_heap_manager_exhaustion():
    """Verify HeapManager raises MemoryError when allocating beyond max_size."""
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    heap = HeapManager(uc, base_addr=0x600000000000, max_size=0x10000)

    # Allocating 0x8000 bytes succeeds
    p1 = heap.allocate(0x8000)
    assert p1 >= 0x600000000000

    # Allocating another 0x8000 bytes exceeds 0x10000 total size
    with pytest.raises(MemoryError, match="Emulated heap exhausted"):
        heap.allocate(0x8000)


# ============================================================================
# Dimension 8: Adversarial Micro-Emulation on Real Stripped Binary
# ============================================================================

def test_adversarial_c_service_stripped_authenticate_vectors(c_service_stripped_path: Path):
    """Stress test _session_authenticate on c_service_stripped with boundary tokens."""
    session = global_session_manager.create_session(str(c_service_stripped_path))
    prober = UnicornProber()

    # Pre-init config buffer
    cfg_buf = (
        struct.pack("<III", 0x53455256, 8080, 128)
        + b"metis_default_secret_token_2026".ljust(64, b"\x00")
        + struct.pack("<II", 1, 5000)
    )

    # 1. Empty string token -> return 0
    res_empty = prober.trace_function(
        session,
        0x10000ac8 if 0x10000ac8 in session.functions else 0x100000ac8,
        args=[{"size": 128}, cfg_buf, ""],
    )
    assert res_empty.success is True
    assert res_empty.return_value == 0

    # 2. Huge 512-byte token -> return 0
    huge_token = "A" * 512
    res_huge = prober.trace_function(
        session,
        0x10000ac8 if 0x10000ac8 in session.functions else 0x100000ac8,
        args=[{"size": 128}, cfg_buf, huge_token],
    )
    assert res_huge.success is True
    assert res_huge.return_value == 0

    # 3. Exactly matching token -> return 1
    res_exact = prober.trace_function(
        session,
        0x10000ac8 if 0x10000ac8 in session.functions else 0x100000ac8,
        args=[{"size": 128}, cfg_buf, "metis_default_secret_token_2026"],
    )
    assert res_exact.success is True
    assert res_exact.return_value == 1


def test_adversarial_c_service_stripped_invalid_code_address(c_service_stripped_path: Path):
    """Verify tracing an unmapped or non-executable code address halts safely."""
    session = global_session_manager.create_session(str(c_service_stripped_path))
    prober = UnicornProber()

    # Address 0x99999999 is unmapped
    res = prober.trace_function(session, 0x99999999, args=[])
    assert res.success is False
    assert res.error is not None
    assert "Unmapped memory access" in res.error or "stopped early" in res.error or "Unicorn CPU error" in res.error
