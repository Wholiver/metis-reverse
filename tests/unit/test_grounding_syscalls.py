"""
Unit tests for SyscallPropagator: SyscallDatabase catalog, ABI parameter mappings,
backward/forward instruction tracers, and immutable EvidenceTag generation.
"""

from __future__ import annotations

from metis_reverse.core.models import (
    ArchitectureType,
    Instruction,
)
from metis_reverse.grounding.syscalls import (
    AbiConvention,
    BackwardInstructionTracer,
    ForwardInstructionTracer,
    SyscallDatabase,
)


def test_syscall_database_lookups():
    """Verify lookup of POSIX/libc function signatures and name normalization."""
    SyscallDatabase.initialize()

    # Exact and normalized lookups
    sig_read = SyscallDatabase.get_signature("read")
    assert sig_read is not None
    assert sig_read.return_type == "ssize_t"
    assert len(sig_read.parameters) == 3

    assert SyscallDatabase.get_signature("_read") == sig_read
    assert SyscallDatabase.get_signature("read@plt") == sig_read

    sig_socket = SyscallDatabase.get_signature("socket")
    assert sig_socket is not None
    assert sig_socket.category == "network"
    assert len(sig_socket.parameters) == 3

    sig_mmap = SyscallDatabase.get_signature("mmap")
    assert sig_mmap is not None
    assert sig_mmap.return_type == "void*"

    # Architecture syscall number lookups
    assert SyscallDatabase.get_syscall_by_nr(0, "linux_x86_64") == sig_read
    assert SyscallDatabase.get_syscall_by_nr(63, "linux_arm64") == sig_read
    assert SyscallDatabase.get_syscall_by_nr(3, "darwin_arm64") == sig_read


def test_abi_register_mapping_and_aliasing():
    """Verify ABI register sequencing and sub-register alias resolution."""
    # x86_64 SysV libc call vs Linux syscall (r10 substitution)
    sysv_regs = AbiConvention.get_param_registers(ArchitectureType.X86_64, is_syscall=False)
    assert sysv_regs[0:4] == ["rdi", "rsi", "rdx", "rcx"]

    syscall_regs = AbiConvention.get_param_registers(ArchitectureType.X86_64, is_syscall=True)
    assert syscall_regs[0:4] == ["rdi", "rsi", "rdx", "r10"]

    # ARM64 AAPCS
    arm_regs = AbiConvention.get_param_registers(ArchitectureType.ARM64)
    assert arm_regs[0:4] == ["x0", "x1", "x2", "x3"]

    # Register alias matching
    assert AbiConvention.match_register("x0", "w0") is True
    assert AbiConvention.match_register("x1", "w1") is True
    assert AbiConvention.match_register("rdi", "edi") is True
    assert AbiConvention.match_register("rsi", "esi") is True
    assert AbiConvention.match_register("rdx", "edx") is True


def test_backward_instruction_tracer_arm64():
    """Verify backward tracing on ARM64 instruction sequences."""
    sig_read = SyscallDatabase.get_signature("read")
    assert sig_read is not None

    # Synthesize instructions preceding call:
    # 0: add x1, sp, #0x28   (Arg 1: buf pointer on stack)
    # 1: mov w2, #0x1000     (Arg 2: count = 4096)
    # 2: mov w0, #0          (Arg 0: fd = 0 -> stdin_fd)
    # 3: bl _read            (Call site)
    insns = [
        Instruction(address=0x1000, mnemonic="add", op_str="x1, sp, #0x28", size=4, bytes=b"\x00\x00\x00\x00"),
        Instruction(address=0x1004, mnemonic="mov", op_str="w2, #0x1000", size=4, bytes=b"\x00\x00\x00\x00"),
        Instruction(address=0x1008, mnemonic="mov", op_str="w0, #0", size=4, bytes=b"\x00\x00\x00\x00"),
        Instruction(address=0x100c, mnemonic="bl", op_str="_read", size=4, bytes=b"\x00\x00\x00\x00"),
    ]

    args = BackwardInstructionTracer.trace_arguments(
        instructions=insns,
        call_idx=3,
        sig=sig_read,
        arch=ArchitectureType.ARM64,
    )

    assert len(args) == 3

    # Arg 0: fd
    assert args[0].value_kind == "immediate"
    assert args[0].immediate_value == 0
    assert args[0].suggested_name == "stdin_fd"
    assert args[0].suggested_type == "int"

    # Arg 1: buf
    assert args[1].value_kind == "stack_offset"
    assert args[1].stack_offset == 0x28
    assert args[1].suggested_type == "void*"

    # Arg 2: count
    assert args[2].value_kind == "immediate"
    assert args[2].immediate_value == 0x1000
    assert args[2].suggested_name == "count"
    assert args[2].suggested_type == "size_t"


def test_backward_instruction_tracer_x86_64():
    """Verify backward tracing on x86_64 instruction sequences."""
    sig_write = SyscallDatabase.get_signature("write")
    assert sig_write is not None

    # Synthesize instructions preceding call:
    # 0: mov edi, 1                 (Arg 0: fd = 1 -> stdout_fd)
    # 1: lea rsi, [rsp + 0x18]      (Arg 1: buf pointer)
    # 2: mov edx, 64                (Arg 2: count = 64)
    # 3: call write                 (Call site)
    insns = [
        Instruction(address=0x401000, mnemonic="mov", op_str="edi, 1", size=5, bytes=b"\x00" * 5),
        Instruction(address=0x401005, mnemonic="lea", op_str="rsi, [rsp + 0x18]", size=5, bytes=b"\x00" * 5),
        Instruction(address=0x40100a, mnemonic="mov", op_str="edx, 64", size=5, bytes=b"\x00" * 5),
        Instruction(address=0x40100f, mnemonic="call", op_str="write", size=5, bytes=b"\x00" * 5),
    ]

    args = BackwardInstructionTracer.trace_arguments(
        instructions=insns,
        call_idx=3,
        sig=sig_write,
        arch=ArchitectureType.X86_64,
    )

    assert len(args) == 3
    assert args[0].suggested_name == "stdout_fd"
    assert args[1].value_kind == "stack_offset"
    assert args[1].stack_offset == 24
    assert args[2].immediate_value == 64


def test_forward_instruction_tracer():
    """Verify forward tracing of return value stores into stack variables."""
    sig_read = SyscallDatabase.get_signature("read")
    assert sig_read is not None

    # ARM64: bl _read; str x0, [sp, #0x10]
    insns_arm = [
        Instruction(address=0x2000, mnemonic="bl", op_str="_read", size=4, bytes=b"\x00" * 4),
        Instruction(address=0x2004, mnemonic="str", op_str="x0, [sp, #0x10]", size=4, bytes=b"\x00" * 4),
    ]
    ret_arm = ForwardInstructionTracer.trace_return_value(
        instructions=insns_arm,
        call_idx=0,
        sig=sig_read,
        arch=ArchitectureType.ARM64,
    )
    assert ret_arm is not None
    assert ret_arm["kind"] == "stack_store"
    assert ret_arm["stack_offset"] == 0x10
    assert ret_arm["suggested_type"] == "ssize_t"

    # x86_64: call read; mov [rbp - 0x18], rax
    insns_x86 = [
        Instruction(address=0x3000, mnemonic="call", op_str="read", size=5, bytes=b"\x00" * 5),
        Instruction(address=0x3005, mnemonic="mov", op_str="[rbp - 0x18], rax", size=4, bytes=b"\x00" * 4),
    ]
    ret_x86 = ForwardInstructionTracer.trace_return_value(
        instructions=insns_x86,
        call_idx=0,
        sig=sig_read,
        arch=ArchitectureType.X86_64,
    )
    assert ret_x86 is not None
    assert ret_x86["stack_offset"] == -24
    assert ret_x86["suggested_type"] == "ssize_t"
