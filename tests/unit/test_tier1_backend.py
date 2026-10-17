"""
Unit tests for Tier 1 native backend: LIEF parser, Capstone disassembler,
Angr lazy decompiler, Tree-sitter AST engine, and Tier1NativeBackend.
"""

from __future__ import annotations

import os
import tempfile

from metis_reverse.backends.tier1_native.ast_engine import TreeSitterAstEngine
from metis_reverse.backends.tier1_native.backend import Tier1NativeBackend
from metis_reverse.backends.tier1_native.binary_parser import LiefBinaryParser
from metis_reverse.backends.tier1_native.disassembler import CapstoneDisassembler
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BranchType,
    OperandType,
)

# Minimal synthetic ELF x86_64 binary bytes
SYNTHETIC_ELF_X86_64 = (
    b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 +
    b"\x02\x00" +                       # e_type: ET_EXEC
    b"\x3e\x00" +                       # e_machine: x86_64
    b"\x01\x00\x00\x00" +               # e_version: 1
    b"\x00\x10\x40\x00\x00\x00\x00\x00" +  # e_entry: 0x401000
    b"\x40\x00\x00\x00\x00\x00\x00\x00" +  # e_phoff: 64
    b"\x00\x00\x00\x00\x00\x00\x00\x00" +  # e_shoff: 0
    b"\x00\x00\x00\x00" +               # e_flags
    b"\x40\x00" +                       # e_ehsize: 64
    b"\x38\x00" +                       # e_phentsize: 56
    b"\x01\x00" +                       # e_phnum: 1
    b"\x40\x00" +                       # e_shentsize: 64
    b"\x00\x00" +                       # e_shnum: 0
    b"\x00\x00" +                       # e_shstrndx: 0
    # Program header: PT_LOAD
    b"\x01\x00\x00\x00" +               # p_type: PT_LOAD
    b"\x05\x00\x00\x00" +               # p_flags: r-x
    b"\x00\x00\x00\x00\x00\x00\x00\x00" +  # p_offset: 0
    b"\x00\x00\x40\x00\x00\x00\x00\x00" +  # p_vaddr: 0x400000
    b"\x00\x00\x40\x00\x00\x00\x00\x00" +  # p_paddr: 0x400000
    b"\xb8\x00\x00\x00\x00\x00\x00\x00" +  # p_filesz: 0xb8
    b"\xb8\x00\x00\x00\x00\x00\x00\x00" +  # p_memsz: 0xb8
    b"\x00\x10\x00\x00\x00\x00\x00\x00"    # p_align: 0x1000
)

# Minimal synthetic PE32+ (x86_64) binary bytes
SYNTHETIC_PE_X86_64 = (
    b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" +  # e_lfanew = 0x40
    b"PE\x00\x00" +                               # Signature
    b"\x64\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x22\x00" + # COFF Header
    b"\x0b\x02" + b"\x00" * 238 +                 # Optional Header PE32+
    b".text\x00\x00\x00" +                        # Section Name
    b"\x00\x10\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00" +
    b"\x00" * 16 + b"\x00" * 1024                 # Padding
)


class TestLiefBinaryParser:
    """Test suite for LIEF binary parser on ELF and PE binaries."""

    def test_parse_synthetic_elf(self):
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(SYNTHETIC_ELF_X86_64)
            temp_path = f.name

        try:
            artifact, symbols, strings = LiefBinaryParser.parse(temp_path)
            assert artifact.format == ArtifactFormat.ELF
            assert artifact.architecture == ArchitectureType.X86_64
            assert artifact.bitness == 64
            assert artifact.entry_points == [0x401000]
            assert artifact.base_address == 0x400000
        finally:
            os.unlink(temp_path)

    def test_parse_synthetic_pe(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(SYNTHETIC_PE_X86_64)
            temp_path = f.name

        try:
            artifact, symbols, strings = LiefBinaryParser.parse(temp_path)
            assert artifact.format == ArtifactFormat.PE
            assert artifact.architecture == ArchitectureType.X86_64
            assert artifact.bitness == 64
        finally:
            os.unlink(temp_path)


class TestCapstoneDisassembler:
    """Test suite for Capstone multi-arch instruction and basic block decoding."""

    def test_disassemble_arm64_instructions(self):
        disasm = CapstoneDisassembler(ArchitectureType.ARM64, bitness=64)
        # mov x0, #1; mov x1, x0; bl 0x1008
        arm64_bytes = b"\x20\x00\x80\xd2\xe1\x03\x00\xaa\x00\x00\x00\x94"
        insns = disasm.disassemble_bytes(arm64_bytes, base_address=0x1000)

        assert len(insns) == 3
        assert insns[0].mnemonic == "mov"
        assert insns[0].registers_written == ["x0"]
        assert insns[1].registers_read == ["x0"]
        assert insns[1].registers_written == ["x1"]
        assert insns[2].is_call is True
        assert insns[2].target_address == 0x1008

    def test_disassemble_x86_64_instructions_and_memory(self):
        disasm = CapstoneDisassembler(ArchitectureType.X86_64, bitness=64)
        # mov rdi, rbx; mov rax, [rbp - 8]; ret
        x86_bytes = b"\x48\x89\xdf\x48\x8b\x45\xf8\xc3"
        insns = disasm.disassemble_bytes(x86_bytes, base_address=0x401000)

        assert len(insns) == 3
        assert insns[0].mnemonic == "mov"
        assert "rbx" in insns[0].registers_read
        assert "rdi" in insns[0].registers_written
        assert insns[1].operands[1].type == OperandType.MEMORY
        assert insns[1].operands[1].value.base_register == "rbp"
        assert insns[1].operands[1].value.displacement == -8
        assert insns[2].is_ret is True

    def test_basic_block_segmentation(self):
        disasm = CapstoneDisassembler(ArchitectureType.X86_64, bitness=64)
        # mov rax, 1; cmp rax, 2; jne 0x40100c; ret; mov rax, 0; ret
        x86_code = (
            b"\x48\xc7\xc0\x01\x00\x00\x00"  # mov rax, 1
            b"\x48\x83\xf8\x02"              # cmp rax, 2
            b"\x75\x01"                      # jne +1 -> 0x40100e
            b"\xc3"                          # ret
            b"\x48\xc7\xc0\x00\x00\x00\x00"  # mov rax, 0
            b"\xc3"                          # ret
        )
        insns = disasm.disassemble_bytes(x86_code, base_address=0x401000)
        blocks = disasm.segment_basic_blocks(insns)

        assert len(blocks) >= 2
        assert blocks[0].terminator_type == BranchType.CONDITIONAL
        assert blocks[-1].terminator_type == BranchType.RETURN


class TestTreeSitterAstEngine:
    """Test suite for Tree-sitter C syntax tokenization and semantic renaming."""

    def test_c_identifier_extraction(self):
        engine = TreeSitterAstEngine()
        code = """
        long long calculate_sum(int a0, int a1) {
            int result = a0 + a1;
            return result;
        }
        """
        tokens = engine.extract_identifiers(code)
        names = [t.name for t in tokens]

        assert "calculate_sum" in names
        assert "a0" in names
        assert "a1" in names
        assert "result" in names

    def test_semantic_variable_rename_no_regex_corruption(self):
        engine = TreeSitterAstEngine()
        code = """
        int parse(int a0, int a0_flag) {
            // Note: a0 should not be changed inside comments or string literals
            const char* msg = "a0 is valid";
            return a0 + a0_flag;
        }
        """
        # Rename a0 to target_param
        rewritten = engine.rename_identifier(code, "a0", "target_param")

        # Confirm target_param replaced exact identifier a0
        assert "int parse(int target_param, int a0_flag)" in rewritten
        assert "return target_param + a0_flag;" in rewritten
        # Confirm string literal and a0_flag were preserved without corruption
        assert '"a0 is valid"' in rewritten
        assert "a0_flag" in rewritten


class TestTier1NativeBackend:
    """End-to-end integration test suite for Tier1NativeBackend."""

    def test_backend_properties(self):
        backend = Tier1NativeBackend()
        assert backend.name == "Tier1-Native-LIEF-Capstone-Angr"
        assert backend.tier == 1

    def test_end_to_end_synthetic_load(self):
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
            f.write(SYNTHETIC_ELF_X86_64)
            temp_path = f.name

        try:
            backend = Tier1NativeBackend()
            artifact, session = backend.load_artifact(temp_path)

            assert artifact.format == ArtifactFormat.ELF
            assert session.session_id.startswith("sess_")

            # Disassemble range
            insns = backend.disassemble_range(session, 0x401000, 16)
            assert isinstance(insns, list)

            # Mutate symbol
            backend.mutate_symbol(session, 0x401000, "entry_point")
            assert session.symbols[0x401000].name == "entry_point"
        finally:
            os.unlink(temp_path)
