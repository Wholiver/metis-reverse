"""
Adversarial Stress Test Suite for Milestone 2 Grounding Engine
============================================================
Targets:
- FormatStringGrounder (malformed format strings, weird specifiers, edge cases)
- AssertMacroGrounder (complex conditions, nested parentheses, ternary, Yoda, null checks)
- SyscallPropagator & AbiConvention (x86_64 vs ARM64 calling conventions, sub-register aliasing, Darwin vs Linux)
- Clean / Empty binaries (zero hallucinations, zero unhandled exceptions)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySection,
    BinarySession,
    Function,
    Instruction,
    SectionPermission,
    TargetArtifact,
)
from metis_reverse.grounding.assert_macros import (
    AssertMacroGrounder,
)
from metis_reverse.grounding.format_strings import (
    FormatStringGrounder,
    FormatStringMetadata,
)
from metis_reverse.grounding.syscalls import (
    AbiConvention,
    BackwardInstructionTracer,
    ForwardInstructionTracer,
    SyscallDatabase,
    SyscallPropagator,
)

# ============================================================================
# 1. Adversarial Format String Tests
# ============================================================================

class TestAdversarialFormatStrings:
    """Stress-test FormatStringGrounder against corrupt, weird, and malicious format strings."""

    @pytest.mark.parametrize(
        "spec_str,expected_spec,expected_type",
        [
            ("%999$s", "%999$s", "const char*"),
            ("%0*d", "%0*d", "int"),
            ("%hn", "%hn", "uint64_t"),  # Note: defaults to uint64_t because %n is omitted from TYPE_MAP
            ("%llu", "%llu", "uint64_t"),
            ("%08llx", "%08llx", "uint64_t"),
            ("%+10.5f", "%+10.5f", "double"),
            ("%#x", "%#x", "uint32_t"),
            ("%zd", "%zd", "ssize_t"),
            ("%zu", "%zu", "size_t"),
            ("%Lf", "%Lf", "long double"),
        ],
    )
    def test_weird_format_specifiers_do_not_crash(self, spec_str: str, expected_spec: str, expected_type: str) -> None:
        """Verify that exotic, positional, and modified format specifiers parse without exception."""
        meta = FormatStringGrounder.parse_format_string(f"Test value: {spec_str}")
        assert meta.is_valid_format is True
        assert len(meta.parameters) >= 1
        param = meta.parameters[0]
        assert param.specifier == expected_spec
        assert param.inferred_type == expected_type

    @pytest.mark.parametrize(
        "corrupt_input",
        [
            "%",
            "%%",
            "%%%",
            "%%%%",
            "%0",
            "%+",
            "%-",
            "%#",
            "% ",
            "%10",
            "%.",
            "%h",
            "%ll",
            "%z",
            "malformed escapes: %! %@ %# %^",
            "\x00%s\x00",
            "\xff\xfe\xfd",
            "",
            "   \t\r\n",
            "{",
            "}",
            "{}",
            "{broken",
            "broken}",
            "{{escaped}}",
            "{::}",
            "{0:>{1}}",
        ],
    )
    def test_corrupt_and_malformed_escapes_never_crash(self, corrupt_input: str) -> None:
        """Verify that malformed escapes, incomplete specifiers, and garbage strings never raise exceptions."""
        try:
            meta = FormatStringGrounder.parse_format_string(corrupt_input)
            assert isinstance(meta, FormatStringMetadata)
        except Exception as exc:
            pytest.fail(f"parse_format_string raised unexpected exception on {corrupt_input!r}: {exc}")

    def test_repeated_escaped_percent_prefix_tracking(self) -> None:
        """Stress-test handling of escaped %% mixed with real format specifiers."""
        fmt = "Progress: 100%% complete, code: %d, ratio: 50%%, result: %s"
        meta = FormatStringGrounder.parse_format_string(fmt)
        assert meta.is_valid_format is True
        assert len(meta.parameters) == 2
        assert meta.parameters[0].inferred_type == "int"
        assert meta.parameters[1].inferred_type == "const char*"

    def test_huge_repetition_format_string(self) -> None:
        """Verify parser performance and absence of catastrophic backtracking / ReDoS on large inputs."""
        large_fmt = "Data: " + ("%s %d " * 500)
        meta = FormatStringGrounder.parse_format_string(large_fmt)
        assert meta.is_valid_format is True
        assert len(meta.parameters) == 1000

    def test_positional_parameter_indexing_behavior(self) -> None:
        """Document positional parameter behavior (%2$s %1$d)."""
        fmt = "User %2$s has logged in with ID %1$d"
        meta = FormatStringGrounder.parse_format_string(fmt)
        assert meta.is_valid_format is True
        assert len(meta.parameters) == 2
        # Observe: FormatStringGrounder assigns index based on order of appearance (len(params))
        assert meta.parameters[0].specifier == "%2$s"
        assert meta.parameters[0].index == 0
        assert meta.parameters[1].specifier == "%1$d"
        assert meta.parameters[1].index == 1


# ============================================================================
# 2. Adversarial Assert Macro Tests
# ============================================================================

class TestAdversarialAssertMacros:
    """Stress-test AssertMacroGrounder against complex boolean logic, Yoda conditions, and edge cases."""

    def test_nested_parentheses_and_multiple_and_conditions(self) -> None:
        """Verify parsing of deeply nested parentheses and multi-clause boolean expressions."""
        raw = "(((x > 0) && (y < 10)))"
        cond = AssertMacroGrounder.parse_assert_expression(raw)
        assert len(cond.comparisons) == 2
        assert cond.comparisons[0].base_var == "x"
        assert cond.comparisons[0].op == ">"
        assert cond.comparisons[0].rhs == "0"
        assert cond.comparisons[1].base_var == "y"
        assert cond.comparisons[1].op == "<"
        assert cond.comparisons[1].rhs == "10"

    def test_ternary_operator_in_assert(self) -> None:
        """Verify behavior when assert contains ternary operator expressions."""
        raw = "is_valid ? (count > 0) : (fallback != NULL)"
        cond = AssertMacroGrounder.parse_assert_expression(raw)
        assert len(cond.comparisons) == 2
        assert cond.comparisons[0].base_var == "count"
        assert cond.comparisons[0].op == ">"
        assert cond.comparisons[1].base_var == "fallback"
        assert cond.comparisons[1].op == "!="
        assert cond.comparisons[1].is_null_check is True

    def test_multi_condition_with_diagnostic_tag(self) -> None:
        """Verify compound condition with trailing && 'tag'."""
        raw = 'a != NULL && b > 0 && c == 42 && "all_checks_passed"'
        cond = AssertMacroGrounder.parse_assert_expression(raw)
        assert cond.diagnostic_tag == "all_checks_passed"
        assert len(cond.comparisons) == 3
        assert cond.comparisons[0].base_var == "a"
        assert cond.comparisons[0].is_null_check is True
        assert cond.comparisons[1].base_var == "b"
        assert cond.comparisons[2].base_var == "c"

    def test_null_check_heuristics_on_integers(self) -> None:
        """
        Empirical check: Verify whether integer comparisons against literal 0
        (e.g., ret != 0, status == 0) are classified as null checks.
        """
        cond_ret = AssertMacroGrounder.parse_assert_expression("ret != 0")
        assert len(cond_ret.comparisons) == 1
        # In current implementation, '0' is in ('NULL', '0', 'NIL', 'NULLPTR'),
        # so is_null_check is True even for integer return codes.
        assert cond_ret.comparisons[0].is_null_check is True

        cond_ptr = AssertMacroGrounder.parse_assert_expression("ptr != NULL")
        assert cond_ptr.comparisons[0].is_null_check is True

        cond_nullptr = AssertMacroGrounder.parse_assert_expression("ptr == nullptr")
        assert cond_nullptr.comparisons[0].is_null_check is True

    def test_yoda_condition_behavior(self) -> None:
        """
        Empirical check: Test Yoda conditions (literal on LHS, variable on RHS).
        """
        # Case A: NULL != ptr
        cond_yoda = AssertMacroGrounder.parse_assert_expression("NULL != ptr")
        assert len(cond_yoda.comparisons) == 1
        # Note: lhs='NULL', base_var='NULL' -> inverted extraction
        assert cond_yoda.comparisons[0].base_var == "NULL"
        assert cond_yoda.comparisons[0].is_null_check is False

        # Case B: 0 != count
        cond_yoda_zero = AssertMacroGrounder.parse_assert_expression("0 != count")
        # COND_CMP_REGEX requires [A-Za-z_] at start of lhs, so 0 != count fails to match
        assert len(cond_yoda_zero.comparisons) == 0

    def test_malformed_and_empty_asserts(self) -> None:
        """Verify that malformed, single-token, and blank asserts do not crash."""
        for bad_assert in ["", "   ", "!=", "a = b", "&& \"tag_only\"", "\"tag_only\"", "((()))", "x"]:
            try:
                cond = AssertMacroGrounder.parse_assert_expression(bad_assert)
                assert isinstance(cond.comparisons, list)
            except Exception as exc:
                pytest.fail(f"parse_assert_expression raised on {bad_assert!r}: {exc}")


# ============================================================================
# 3. Architecture Calling Conventions & Register Aliasing Tests
# ============================================================================

class TestArchitectureConventionsAndAliasing:
    """Stress-test ABI conventions, sub-register aliasing, and instruction tracing."""

    def test_x86_64_calling_conventions(self) -> None:
        """Verify x86_64 SysV libc vs Linux syscall parameter register mappings."""
        sysv = AbiConvention.get_param_registers(ArchitectureType.X86_64, is_syscall=False)
        assert sysv == ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

        syscall = AbiConvention.get_param_registers(ArchitectureType.X86_64, is_syscall=True)
        assert syscall == ["rdi", "rsi", "rdx", "r10", "r8", "r9"]

        ret = AbiConvention.get_return_register(ArchitectureType.X86_64)
        assert ret == "rax"

    def test_arm64_calling_conventions(self) -> None:
        """Verify ARM64 AAPCS parameter and return register mappings."""
        aapcs = AbiConvention.get_param_registers(ArchitectureType.ARM64)
        assert aapcs == ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]

        ret = AbiConvention.get_return_register(ArchitectureType.ARM64)
        assert ret == "x0"

    def test_sub_register_alias_matching_x86_64(self) -> None:
        """Verify 64-bit to 32-bit/16-bit/8-bit alias matching on x86_64."""
        # rdi
        assert AbiConvention.match_register("rdi", "edi") is True
        assert AbiConvention.match_register("rdi", "di") is True
        assert AbiConvention.match_register("rdi", "dil") is True
        # rsi
        assert AbiConvention.match_register("rsi", "esi") is True
        assert AbiConvention.match_register("rsi", "sil") is True
        # rdx
        assert AbiConvention.match_register("rdx", "edx") is True
        assert AbiConvention.match_register("rdx", "dl") is True
        assert AbiConvention.match_register("rdx", "dh") is True
        # rcx
        assert AbiConvention.match_register("rcx", "ecx") is True
        assert AbiConvention.match_register("rcx", "cl") is True
        # r8 - r10
        assert AbiConvention.match_register("r8", "r8d") is True
        assert AbiConvention.match_register("r8", "r8b") is True
        assert AbiConvention.match_register("r9", "r9d") is True
        assert AbiConvention.match_register("r10", "r10d") is True
        # rax
        assert AbiConvention.match_register("rax", "eax") is True
        assert AbiConvention.match_register("rax", "al") is True

    def test_sub_register_alias_matching_arm64(self) -> None:
        """Verify 64-bit xN to 32-bit wN alias matching on ARM64."""
        for i in range(8):
            assert AbiConvention.match_register(f"x{i}", f"w{i}") is True
        assert AbiConvention.match_register("x16", "w16") is True
        assert AbiConvention.match_register("x29", "w29") is True
        assert AbiConvention.match_register("x29", "fp") is True
        assert AbiConvention.match_register("x30", "lr") is True

    def test_case_sensitivity_in_architecture_specification(self) -> None:
        """
        Verify architecture normalization across enum and string representations.
        Tests whether uppercase strings like 'ARM64' and 'X86_64' are handled.
        """
        # Enum instances
        assert AbiConvention.get_param_registers(ArchitectureType.ARM64)[0] == "x0"
        assert AbiConvention.get_param_registers(ArchitectureType.X86_64)[0] == "rdi"

        # Lowercase string
        assert AbiConvention.get_param_registers("arm64")[0] == "x0"
        assert AbiConvention.get_param_registers("x86_64")[0] == "rdi"

        # Note: Document behavior with uppercase string 'ARM64'
        # In current code: if arch not normalized, 'ARM64' falls back to default sysv registers
        arm_upper_regs = AbiConvention.get_param_registers("ARM64")
        arm_upper_ret = AbiConvention.get_return_register("ARM64")
        assert arm_upper_regs == ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        assert arm_upper_ret == "rax"

    def test_forward_instruction_tracer_with_sub_registers(self) -> None:
        """Verify forward instruction tracer tracking 32-bit sub-register stores."""
        SyscallDatabase.initialize()
        sig_read = SyscallDatabase.get_signature("read")
        assert sig_read is not None

        # ARM64: str w0, [sp, #0x18]
        insns_arm = [
            Instruction(address=0x1000, mnemonic="bl", op_str="_read", size=4, raw_bytes=b"\x00"*4),
            Instruction(address=0x1004, mnemonic="str", op_str="w0, [sp, #0x18]", size=4, raw_bytes=b"\x00"*4),
        ]
        ret_arm = ForwardInstructionTracer.trace_return_value(insns_arm, 0, sig_read, ArchitectureType.ARM64)
        assert ret_arm is not None
        assert ret_arm["kind"] == "stack_store"
        assert ret_arm["stack_offset"] == 24
        assert ret_arm["suggested_name"] == "bytes_read"

        # x86_64: mov [rbp - 0x10], eax
        insns_x86 = [
            Instruction(address=0x2000, mnemonic="call", op_str="read", size=5, raw_bytes=b"\x00"*5),
            Instruction(address=0x2005, mnemonic="mov", op_str="[rbp - 0x10], eax", size=5, raw_bytes=b"\x00"*5),
        ]
        ret_x86 = ForwardInstructionTracer.trace_return_value(insns_x86, 0, sig_read, ArchitectureType.X86_64)
        assert ret_x86 is not None
        assert ret_x86["kind"] == "stack_store"
        assert ret_x86["stack_offset"] == -16
        assert ret_x86["suggested_name"] == "bytes_read"

    def test_arm64_adrp_backward_tracer_limitation(self) -> None:
        """
        Document empirical limitation: BackwardInstructionTracer scans backwards from call,
        so when encountering add x0, x0, #off it breaks before visiting adrp x0, #page.
        """
        SyscallDatabase.initialize()
        sig_open = SyscallDatabase.get_signature("open")
        assert sig_open is not None

        insns = [
            Instruction(address=0x1000, mnemonic="adrp", op_str="x0, #0x2000", size=4, raw_bytes=b"\x00"*4),
            Instruction(address=0x1004, mnemonic="add", op_str="x0, x0, #0x40", size=4, raw_bytes=b"\x00"*4),
            Instruction(address=0x1008, mnemonic="bl", op_str="_open", size=4, raw_bytes=b"\x00"*4),
        ]
        args = BackwardInstructionTracer.trace_arguments(insns, 2, sig_open, ArchitectureType.ARM64)
        # Empirical observation: arg0 is left as unknown because backward iteration reaches 'add' first
        assert args[0].value_kind == "unknown"
        assert args[0].symbol_address is None


# ============================================================================
# 4. Zero Crashes & Zero Hallucinations on Clean / Empty Binaries
# ============================================================================

class TestZeroHallucinationsAndCleanBinaries:
    """Verify that empty, non-format, or stripped binaries produce 0 hallucinations and 0 crashes."""

    def test_empty_binary_file(self, tmp_path: Path) -> None:
        """Verify behavior on an empty 0-byte file."""
        empty_file = tmp_path / "empty_binary"
        empty_file.write_bytes(b"")

        art = TargetArtifact(
            artifact_id="art_empty",
            file_path=str(empty_file),
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
            sections=[],
        )
        session = BinarySession(artifact=art)

        fmt_tags = FormatStringGrounder.ground(session)
        assert len(fmt_tags) == 0

        assert_tags = AssertMacroGrounder.ground(session)
        assert len(assert_tags) == 0

        sys_tags = SyscallPropagator.propagate_session(session)
        assert len(sys_tags) == 0

    def test_binary_with_unrelated_plain_strings(self, tmp_path: Path) -> None:
        """
        Verify that a binary containing ordinary strings (e.g. error messages, copyright, help)
        produces zero format string or assert macro hallucinations.
        """
        plain_strings = (
            b"Copyright (C) 2026 Acme Corp.\x00"
            b"Usage: myprogram [options] <input>\x00"
            b"Invalid command line option provided.\x00"
            b"Internal initialization complete.\x00"
        )
        bin_file = tmp_path / "plain_strings_bin"
        bin_file.write_bytes(plain_strings)

        sec = BinarySection(
            name=".rodata",
            virtual_address=0x400000,
            virtual_size=len(plain_strings),
            raw_offset=0,
            raw_size=len(plain_strings),
            permissions=[SectionPermission.READ],
        )
        art = TargetArtifact(
            artifact_id="art_plain",
            file_path=str(bin_file),
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
            sections=[sec],
        )
        session = BinarySession(artifact=art)

        fmt_tags = FormatStringGrounder.ground(session)
        assert len(fmt_tags) == 0, f"Expected 0 format tags, got {len(fmt_tags)}"

        assert_tags = AssertMacroGrounder.ground(session)
        assert len(assert_tags) == 0, f"Expected 0 assert tags, got {len(assert_tags)}"

    def test_nonexistent_binary_file(self) -> None:
        """Verify graceful error handling when artifact file path does not exist."""
        art = TargetArtifact(
            artifact_id="art_missing",
            file_path="/tmp/definitely_nonexistent_file_path_12345",
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
            sections=[],
        )
        session = BinarySession(artifact=art)

        fmt_tags = FormatStringGrounder.ground(session)
        assert fmt_tags == []

        assert_tags = AssertMacroGrounder.ground(session)
        assert assert_tags == []

        sys_tags = SyscallPropagator.propagate_session(session)
        assert sys_tags == []

    def test_functions_without_syscalls_emit_no_tags(self, tmp_path: Path) -> None:
        """Verify that functions executing arithmetic / control flow without syscalls emit zero syscall tags."""
        bin_file = tmp_path / "math_bin"
        bin_file.write_bytes(b"\x90" * 64)  # NOP sled

        art = TargetArtifact(
            artifact_id="art_math",
            file_path=str(bin_file),
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
            sections=[],
        )
        session = BinarySession(artifact=art)

        # Function with simple arithmetic (mov eax, 1; add eax, 2; ret)
        func = Function(
            id="func_0x401000",
            name="math_func",
            address=0x401000,
            size=16,
        )
        session.functions[0x401000] = func

        sys_tags = SyscallPropagator.propagate_session(session)
        assert len(sys_tags) == 0
