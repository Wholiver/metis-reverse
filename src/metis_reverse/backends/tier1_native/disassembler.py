"""
metis_reverse.backends.tier1_native.disassembler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Capstone-based multi-architecture instruction and basic block disassembler.
"""

from __future__ import annotations

import os

import capstone
from capstone import arm64, x86

from metis_reverse.backends.base import DisassemblyError
from metis_reverse.core.models import (
    ArchitectureType,
    BasicBlock,
    BranchType,
    Instruction,
    MemoryOperand,
    Operand,
    OperandType,
)


class CapstoneDisassembler:
    """Multi-architecture disassembler decoding instructions and reconstructing basic blocks."""

    def __init__(
        self,
        arch: ArchitectureType | str | None = None,
        bitness: int = 64,
        architecture: ArchitectureType | str | None = None,
    ):
        target_arch = arch or architecture or ArchitectureType.X86_64
        if isinstance(target_arch, str):
            clean = target_arch.strip().lower()
            if clean in ("arm64", "aarch64"):
                self.arch = ArchitectureType.ARM64
            elif clean in ("x86_64", "amd64", "x64"):
                self.arch = ArchitectureType.X86_64
            elif clean in ("x86", "i386"):
                self.arch = ArchitectureType.X86
            elif clean == "arm":
                self.arch = ArchitectureType.ARM
            else:
                self.arch = ArchitectureType.UNKNOWN
        else:
            self.arch = target_arch

        self.bitness = bitness
        self.cs = self._init_capstone(self.arch, bitness)

    def _init_capstone(self, arch: ArchitectureType, bitness: int) -> capstone.Cs:
        if arch in (ArchitectureType.ARM64, ArchitectureType.ARM):
            if bitness == 64 or arch == ArchitectureType.ARM64:
                cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            else:
                cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif arch == ArchitectureType.X86_64:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif arch == ArchitectureType.X86:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            # Fallback to x86_64 default
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        cs.detail = True
        return cs

    def disassemble_bytes(self, raw_bytes: bytes, base_address: int) -> list[Instruction]:
        """Disassemble raw byte buffer into unified Instruction models."""
        instructions: list[Instruction] = []
        try:
            for insn in self.cs.disasm(raw_bytes, base_address):
                instructions.append(self._convert_instruction(insn))
        except Exception as e:
            raise DisassemblyError(f"Disassembly failed at 0x{base_address:x}: {e}") from e

        return instructions

    def disassemble(self, file_path: str, start_addr: int, size: int) -> list[Instruction]:
        """Read bytes directly from binary file and disassemble."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        offset = start_addr
        if offset >= file_size:
            offset = 0

        with open(file_path, "rb") as f:
            f.seek(offset)
            raw = f.read(size)

        return self.disassemble_bytes(raw, start_addr)

    def _convert_instruction(self, insn: capstone.CsInsn) -> Instruction:
        """Translate Capstone CsInsn into domain Instruction."""
        regs_read_names: list[str] = []
        regs_written_names: list[str] = []

        try:
            regs_read, regs_write = insn.regs_access()
            regs_read_names = [insn.reg_name(r) for r in regs_read if insn.reg_name(r)]
            regs_written_names = [insn.reg_name(r) for r in regs_write if insn.reg_name(r)]
        except Exception:
            regs_read_names = [insn.reg_name(r) for r in insn.regs_read if insn.reg_name(r)]
            regs_written_names = [insn.reg_name(r) for r in insn.regs_write if insn.reg_name(r)]

        # Classify instruction flow
        is_call, is_branch, is_ret, is_syscall, target_addr = self._classify_flow(insn)

        # Decode operands
        operands = self._decode_operands(insn)

        return Instruction(
            address=insn.address,
            size=insn.size,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            raw_bytes=bytes(insn.bytes),
            operands=operands,
            registers_read=regs_read_names,
            registers_written=regs_written_names,
            is_call=is_call,
            is_branch=is_branch,
            is_ret=is_ret,
            is_syscall=is_syscall,
            target_address=target_addr,
        )

    def _classify_flow(
        self, insn: capstone.CsInsn
    ) -> tuple[bool, bool, bool, bool, int | None]:
        """Identify if instruction is a call, branch, return, or syscall and extract target address."""
        is_call = False
        is_branch = False
        is_ret = False
        is_syscall = False
        target_addr: int | None = None

        mnemonic = insn.mnemonic.lower()

        # ARM64 / ARM
        if self.arch in (ArchitectureType.ARM64, ArchitectureType.ARM):
            if mnemonic in ("bl", "blr"):
                is_call = True
            elif mnemonic in (
                "b", "b.eq", "b.ne", "b.gt", "b.lt", "b.ge", "b.le", "b.cs", "b.cc",
                "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "cbz", "cbnz", "tbz", "tbnz",
            ):
                is_branch = True
            elif mnemonic in ("ret", "eret"):
                is_ret = True
            elif mnemonic in ("svc", "hvc", "smc"):
                is_syscall = True

            if (is_call or is_branch) and len(insn.operands) > 0:
                last_op = insn.operands[-1]
                if last_op.type == arm64.ARM64_OP_IMM:
                    target_addr = last_op.value.imm

        # X86 / X86_64
        elif self.arch in (ArchitectureType.X86_64, ArchitectureType.X86):
            if mnemonic.startswith("call"):
                is_call = True
            elif mnemonic.startswith("j") and mnemonic != "jmp" or mnemonic == "jmp":
                is_branch = True
            elif mnemonic in ("ret", "retn", "retf"):
                is_ret = True
            elif mnemonic in ("syscall", "sysenter", "int 0x80"):
                is_syscall = True

            if (is_call or is_branch) and len(insn.operands) > 0:
                op0 = insn.operands[0]
                if op0.type == x86.X86_OP_IMM:
                    target_addr = op0.value.imm

        return is_call, is_branch, is_ret, is_syscall, target_addr

    def _decode_operands(self, insn: capstone.CsInsn) -> list[Operand]:
        """Decode architecture-specific operands into unified Operand objects."""
        operands: list[Operand] = []

        if self.arch in (ArchitectureType.ARM64, ArchitectureType.ARM):
            for op in insn.operands:
                if op.type == arm64.ARM64_OP_REG:
                    reg_name = insn.reg_name(op.value.reg)
                    operands.append(
                        Operand(
                            type=OperandType.REGISTER,
                            value=reg_name or "unknown_reg",
                            size_bytes=4,
                            access="r",
                        )
                    )
                elif op.type == arm64.ARM64_OP_IMM:
                    operands.append(
                        Operand(
                            type=OperandType.IMMEDIATE,
                            value=int(op.value.imm),
                            size_bytes=8,
                            access="r",
                        )
                    )
                elif op.type == arm64.ARM64_OP_MEM:
                    base = insn.reg_name(op.value.mem.base) if op.value.mem.base else None
                    index = insn.reg_name(op.value.mem.index) if op.value.mem.index else None
                    disp = int(op.value.mem.disp)
                    operands.append(
                        Operand(
                            type=OperandType.MEMORY,
                            value=MemoryOperand(
                                base_register=base,
                                index_register=index,
                                scale=1,
                                displacement=disp,
                            ),
                            size_bytes=8,
                            access="rw",
                        )
                    )

        elif self.arch in (ArchitectureType.X86_64, ArchitectureType.X86):
            for op in insn.operands:
                if op.type == x86.X86_OP_REG:
                    reg_name = insn.reg_name(op.value.reg)
                    operands.append(
                        Operand(
                            type=OperandType.REGISTER,
                            value=reg_name or "unknown_reg",
                            size_bytes=int(op.size),
                            access="r",
                        )
                    )
                elif op.type == x86.X86_OP_IMM:
                    operands.append(
                        Operand(
                            type=OperandType.IMMEDIATE,
                            value=int(op.value.imm),
                            size_bytes=int(op.size),
                            access="r",
                        )
                    )
                elif op.type == x86.X86_OP_MEM:
                    base = insn.reg_name(op.value.mem.base) if op.value.mem.base else None
                    index = insn.reg_name(op.value.mem.index) if op.value.mem.index else None
                    scale = int(op.value.mem.scale)
                    disp = int(op.value.mem.disp)
                    segment = insn.reg_name(op.value.mem.segment) if op.value.mem.segment else None
                    operands.append(
                        Operand(
                            type=OperandType.MEMORY,
                            value=MemoryOperand(
                                base_register=base,
                                index_register=index,
                                scale=scale,
                                displacement=disp,
                                segment=segment,
                            ),
                            size_bytes=int(op.size),
                            access="rw",
                        )
                    )

        return operands

    def segment_basic_blocks(self, instructions: list[Instruction]) -> list[BasicBlock]:
        """
        Segment a linear sequence of instructions into basic blocks based on
        branching terminators and targets.
        """
        if not instructions:
            return []

        blocks: list[BasicBlock] = []
        current_insns: list[Instruction] = []

        for insn in instructions:
            current_insns.append(insn)

            is_terminator = insn.is_ret or insn.is_branch or insn.is_syscall

            if is_terminator:
                start_addr = current_insns[0].address
                end_addr = insn.address + insn.size
                term_type = BranchType.FALLTHROUGH

                if insn.is_ret:
                    term_type = BranchType.RETURN
                elif insn.is_branch:
                    term_type = (
                        BranchType.CONDITIONAL
                        if ("b." in insn.mnemonic or (insn.mnemonic.startswith("j") and insn.mnemonic != "jmp"))
                        else BranchType.UNCONDITIONAL
                    )
                elif insn.is_syscall:
                    term_type = BranchType.TRAP

                successors: list[int] = []
                if insn.target_address:
                    successors.append(insn.target_address)
                if term_type == BranchType.CONDITIONAL:
                    successors.append(end_addr)

                blocks.append(
                    BasicBlock(
                        id=f"bb_0x{start_addr:x}",
                        start_address=start_addr,
                        end_address=end_addr,
                        size=end_addr - start_addr,
                        instructions=list(current_insns),
                        predecessors=[],
                        successors=successors,
                        jump_targets=successors,
                        terminator_type=term_type,
                    )
                )
                current_insns.clear()

        # Flush any trailing instructions
        if current_insns:
            start_addr = current_insns[0].address
            end_addr = current_insns[-1].address + current_insns[-1].size
            blocks.append(
                BasicBlock(
                    id=f"bb_0x{start_addr:x}",
                    start_address=start_addr,
                    end_address=end_addr,
                    size=end_addr - start_addr,
                    instructions=list(current_insns),
                    predecessors=[],
                    successors=[],
                    jump_targets=[],
                    terminator_type=BranchType.FALLTHROUGH,
                )
            )

        return blocks
