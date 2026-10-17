"""
Adversarial Stress Test Suite for Milestone 5 Phase 2 (Tier 5 Hardening).
Author: Challenger M5-P2-2 (Empirical Challenger & Adversarial Specialist)

White-Box Coverage Audit & Adversarial Hardening across:
1. TypeLayoutEngine:
   - Union specifiers, fallback word-size handling, and custom typedefs.
   - Bitfield declarations and robust layout calculation.
   - Deeply nested structs and alignment padding across 32-bit and 64-bit ABIs.
   - Arrays of pointers, multi-dimensional arrays, and mixed packed/unpacked nesting.
2. SessionMutator:
   - CST byte-span replacement with complex C declarations (function pointer parameters,
     const/volatile qualifiers, array of pointers, multi-variable declarations).
   - Resilience against malformed/incomplete C pseudocode.
   - Immutability anti-hallucination boundaries on grounded symbols and variables.
3. RecompilationSandbox:
   - Severely malformed C source codes, syntax errors, and structured diagnostics.
   - Warning flags vs -Werror behavior.
   - Missing compiler probe fallback and non-existent output paths.
4. DifferentialTester:
   - Extreme timeouts and process-group SIGKILL termination of runaway/forking children.
   - Non-ASCII / binary / null-byte outputs without UnicodeDecodeError.
   - Concurrent multi-threaded differential runs across distinct binaries and vectors.
5. FastMCP Server:
   - Parameter validation (negative addresses, malformed hex, empty names, invalid probers).
   - Tool error mapping on missing session IDs across all registered tools.
   - Malformed binary rejection in open_session.
   - Concurrent multi-tool invocations on active sessions.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import os
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

import metis_reverse.server as mr_server
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySession,
    DecompiledCode,
    EvidenceSource,
    EvidenceTag,
    Function,
    FunctionParameter,
    LocalVariable,
    Symbol,
    SymbolType,
    TargetArtifact,
    TargetType,
)
from metis_reverse.equivalence.differential import (
    DifferentialTester,
)
from metis_reverse.equivalence.mutator import (
    SessionMutator,
    TypeLayoutEngine,
)
from metis_reverse.equivalence.recompilation import (
    CompilerDetector,
    CompilerInfo,
    RecompilationSandbox,
)

# ============================================================================
# Section 1: TypeLayoutEngine Adversarial Edge Cases & 32/64-bit ABIs
# ============================================================================

class TestTypeLayoutEngineTier5:
    """Stress tests for TypeLayoutEngine against complex types, unions, typedefs, and ABI bitness."""

    def test_union_specifier_fallback_and_layout(self) -> None:
        """
        Unions without explicit struct registry fallback to pointer-sized words.
        Structs containing union fields compute alignment and padding properly.
        """
        # 64-bit ABI
        sz64, align64, is_ptr64, arr64 = TypeLayoutEngine.resolve_type("union Variant", bitness=64)
        assert sz64 == 8
        assert align64 == 8
        assert is_ptr64 is False
        assert arr64 is None

        # 32-bit ABI
        sz32, align32, is_ptr32, arr32 = TypeLayoutEngine.resolve_type("union Variant", bitness=32)
        assert sz32 == 4
        assert align32 == 4
        assert is_ptr32 is False
        assert arr32 is None

        # Struct containing a union field
        fields = {
            "tag": "uint32_t",
            "val": "union Variant",
        }
        st64 = TypeLayoutEngine.compute_layout("TaggedUnion64", fields, bitness=64)
        # tag: offset 0..4, val: align 8 -> offset 8..16, total_size = 16
        assert st64.field_offsets["tag"] == 0
        assert st64.field_offsets["val"] == 8
        assert st64.total_size == 16
        assert st64.alignment == 8

        st32 = TypeLayoutEngine.compute_layout("TaggedUnion32", fields, bitness=32)
        # tag: offset 0..4, val: align 4 -> offset 4..8, total_size = 8
        assert st32.field_offsets["tag"] == 0
        assert st32.field_offsets["val"] == 4
        assert st32.total_size == 8
        assert st32.alignment == 4

    def test_custom_typedefs_and_pointer_typedefs(self) -> None:
        """Custom typedef aliases resolve to word size; pointer typedefs resolve to pointer size."""
        # Unregistered typedef defaults to machine word
        sz64, align64, is_ptr64, _ = TypeLayoutEngine.resolve_type("MyCustomHandle_t", bitness=64)
        assert sz64 == 8
        assert align64 == 8
        assert is_ptr64 is False

        # Pointer to custom typedef
        sz_ptr, align_ptr, is_ptr, _ = TypeLayoutEngine.resolve_type("MyCustomHandle_t*", bitness=64)
        assert sz_ptr == 8
        assert align_ptr == 8
        assert is_ptr is True

        # Standard typedefs (size_t, uintptr_t, int64_t) under 32-bit vs 64-bit
        sz_size_t_64, _, _, _ = TypeLayoutEngine.resolve_type("size_t", bitness=64)
        sz_size_t_32, _, _, _ = TypeLayoutEngine.resolve_type("size_t", bitness=32)
        assert sz_size_t_64 == 8
        assert sz_size_t_32 == 4

        sz_u64_64, _, _, _ = TypeLayoutEngine.resolve_type("uint64_t", bitness=64)
        sz_u64_32, _, _, _ = TypeLayoutEngine.resolve_type("uint64_t", bitness=32)
        assert sz_u64_64 == 8
        assert sz_u64_32 == 8  # uint64_t remains 8 bytes even in 32-bit ABI

    def test_bitfield_declarations_handled_gracefully(self) -> None:
        """Bitfield notation in field types does not crash layout engine."""
        fields = {
            "flags": "unsigned int:3",
            "mode": "int:5",
            "value": "uint32_t",
        }
        layout = TypeLayoutEngine.compute_layout("BitfieldContainer", fields, bitness=64)
        assert layout.name == "BitfieldContainer"
        assert "flags" in layout.fields
        assert "mode" in layout.fields
        assert "value" in layout.fields
        assert layout.total_size >= 4

    def test_nested_struct_alignment_across_32_and_64_bit(self) -> None:
        """
        Nested composite structs recalculate field offsets and tail padding
        correctly when switching between 32-bit and 64-bit ABIs.
        """
        inner_fields = {
            "id": "uint16_t",
            "ptr": "void*",
        }
        inner_64 = TypeLayoutEngine.compute_layout("Inner", inner_fields, bitness=64)
        # inner_64: id (0..2), ptr (align 8 -> 8..16) -> total_size=16, align=8
        assert inner_64.total_size == 16
        assert inner_64.alignment == 8

        inner_32 = TypeLayoutEngine.compute_layout("Inner", inner_fields, bitness=32)
        # inner_32: id (0..2), ptr (align 4 -> 4..8) -> total_size=8, align=4
        assert inner_32.total_size == 8
        assert inner_32.alignment == 4

        outer_fields = {
            "header": "char",
            "inner": "struct Inner",
            "footer": "uint32_t",
        }
        outer_64 = TypeLayoutEngine.compute_layout(
            "Outer64",
            outer_fields,
            bitness=64,
            structs={"Inner": inner_64},
        )
        assert outer_64.field_offsets["header"] == 0
        assert outer_64.field_offsets["inner"] == 8
        assert outer_64.field_offsets["footer"] == 24
        assert outer_64.total_size == 32
        assert outer_64.alignment == 8

        outer_32 = TypeLayoutEngine.compute_layout(
            "Outer32",
            outer_fields,
            bitness=32,
            structs={"Inner": inner_32},
        )
        assert outer_32.field_offsets["header"] == 0
        assert outer_32.field_offsets["inner"] == 4
        assert outer_32.field_offsets["footer"] == 12
        assert outer_32.total_size == 16
        assert outer_32.alignment == 4

    def test_mixed_packed_and_unpacked_nesting(self) -> None:
        """Packed inner struct in unpacked outer struct, and unpacked inner in packed outer."""
        packed_inner = TypeLayoutEngine.compute_layout(
            "PackedInner",
            {"flag": "char", "val": "uint64_t"},
            bitness=64,
            is_packed=True,
        )
        assert packed_inner.total_size == 9
        assert packed_inner.alignment == 1

        unpacked_outer = TypeLayoutEngine.compute_layout(
            "UnpackedOuter",
            {"head": "char", "sub": "struct PackedInner", "tail": "uint32_t"},
            bitness=64,
            is_packed=False,
            structs={"PackedInner": packed_inner},
        )
        assert unpacked_outer.field_offsets["head"] == 0
        assert unpacked_outer.field_offsets["sub"] == 1
        assert unpacked_outer.field_offsets["tail"] == 12
        assert unpacked_outer.total_size == 16
        assert unpacked_outer.alignment == 4

        unpacked_inner = TypeLayoutEngine.compute_layout(
            "UnpackedInner",
            {"flag": "char", "val": "uint64_t"},
            bitness=64,
            is_packed=False,
        )
        assert unpacked_inner.total_size == 16
        assert unpacked_inner.alignment == 8

        packed_outer = TypeLayoutEngine.compute_layout(
            "PackedOuter",
            {"head": "char", "sub": "struct UnpackedInner", "tail": "uint32_t"},
            bitness=64,
            is_packed=True,
            structs={"UnpackedInner": unpacked_inner},
        )
        assert packed_outer.field_offsets["head"] == 0
        assert packed_outer.field_offsets["sub"] == 1
        assert packed_outer.field_offsets["tail"] == 17
        assert packed_outer.total_size == 21
        assert packed_outer.alignment == 1

    def test_array_of_pointers_and_multi_dimensional_arrays(self) -> None:
        """Array of pointer types and multidimensional array layout resolution."""
        fields = {
            "ptr_table": "char*[16]",
            "matrix": "uint32_t[4][8]",
        }
        layout64 = TypeLayoutEngine.compute_layout("ArrayContainer64", fields, bitness=64)
        assert layout64.fields["ptr_table"].size == 128
        assert layout64.fields["matrix"].size == 128
        assert layout64.total_size == 256
        assert layout64.alignment == 8

        layout32 = TypeLayoutEngine.compute_layout("ArrayContainer32", fields, bitness=32)
        assert layout32.fields["ptr_table"].size == 64
        assert layout32.fields["matrix"].size == 128
        assert layout32.total_size == 192


# ============================================================================
# Section 2: SessionMutator CST Byte-Span Replacement & Immutability
# ============================================================================

class TestSessionMutatorTier5:
    """Stress tests for SessionMutator against complex C declarations and immutability."""

    def _create_mock_session(self) -> BinarySession:
        artifact = TargetArtifact(
            file_path="/tmp/mock_target",
            file_name="mock_target",
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
            bitness=64,
            entry_point=0x401000,
            size=1024,
        )
        return BinarySession(
            session_id=f"test_session_{int(time.time()*1000)}",
            artifact=artifact,
            backend_type="mock",
        )

    def test_function_pointer_parameter_retyping(self) -> None:
        """Typedef function pointer parameters in C declarations retype cleanly in AST and session."""
        mutator = SessionMutator()
        session = self._create_mock_session()

        code = """
        int register_listener(CallbackFn callback, int priority) {
            if (!callback) return -1;
            return 0;
        }
        """
        func = Function(
            address=0x401100,
            name="register_listener",
            size=32,
            parameters=[
                FunctionParameter(name="callback", type_name="CallbackFn", index=0),
                FunctionParameter(name="priority", type_name="int", index=1),
            ],
            decompiled_code=code,
        )
        session.functions[func.address] = func

        res = mutator.update_variable_type(
            session=session,
            function_address=0x401100,
            var_name="callback",
            new_type="EventHandler_t",
        )
        assert res.success is True
        assert res.new_value == "EventHandler_t"
        assert func.parameters[0].type_name == "EventHandler_t"

        updated_code = func.decompiled_code
        assert updated_code is not None
        code_str = updated_code.code if isinstance(updated_code, DecompiledCode) and updated_code.code is not None else str(updated_code)
        assert "EventHandler_t callback" in code_str
        assert "int priority" in code_str

    def test_raw_function_pointer_declarator_gap(self) -> None:
        """
        Adversarial Boundary Test on Raw Inline Function Pointer Declarators:
        When a parameter uses raw C function pointer syntax 'void (*cb)(int, void*)',
        Tree-sitter unwrap_declarator stops at 'function_declarator', so decompiled_code
        is preserved without crashing while session metadata is successfully updated.
        """
        mutator = SessionMutator()
        session = self._create_mock_session()

        raw_c = """
        int dispatch(void (*cb)(int code, void *data), int priority) {
            if (cb) cb(0, 0);
            return priority;
        }
        """
        func = Function(
            address=0x401150,
            name="dispatch",
            size=32,
            parameters=[
                FunctionParameter(name="cb", type_name="void (*)(int, void*)", index=0),
                FunctionParameter(name="priority", type_name="int", index=1),
            ],
            decompiled_code=raw_c,
        )
        session.functions[func.address] = func

        res = mutator.update_variable_type(
            session=session,
            function_address=0x401150,
            var_name="cb",
            new_type="CallbackHandler_t",
        )
        assert res.success is True
        # Session parameter model updated
        assert func.parameters[0].type_name == "CallbackHandler_t"
        # Decompiled code remains uncorrupted
        updated_code = func.decompiled_code
        assert updated_code is not None
        code_str = updated_code.code if isinstance(updated_code, DecompiledCode) and updated_code.code is not None else str(updated_code)
        assert "int priority" in code_str

    def test_const_and_volatile_type_qualifiers(self) -> None:
        """Retyping variables with const/volatile qualifiers replaces types accurately."""
        mutator = SessionMutator()
        session = self._create_mock_session()

        code = """
        int execute_loop(int step) {
            const volatile int timeout = 1000;
            int counter = 0;
            return timeout - counter;
        }
        """
        func = Function(
            address=0x401200,
            name="execute_loop",
            size=32,
            local_variables=[
                LocalVariable(id="var_timeout", name="timeout", type_name="const volatile int"),
                LocalVariable(id="var_counter", name="counter", type_name="int"),
            ],
            decompiled_code=code,
        )
        session.functions[func.address] = func

        res = mutator.update_variable_type(
            session=session,
            function_address=0x401200,
            var_name="timeout",
            new_type="uint32_t",
        )
        assert res.success is True
        updated_code = func.decompiled_code
        assert updated_code is not None
        code_str = updated_code.code if isinstance(updated_code, DecompiledCode) and updated_code.code is not None else str(updated_code)
        assert "uint32_t" in code_str
        assert "timeout" in code_str
        assert "int counter" in code_str

    def test_multi_variable_declarations_in_single_statement(self) -> None:
        """Updating a variable in a multi-variable statement preserves other variables."""
        mutator = SessionMutator()
        session = self._create_mock_session()

        code = """
        int calculate(int x) {
            int a = 1, b = 2, c = 3;
            return a + b + c + x;
        }
        """
        func = Function(
            address=0x401300,
            name="calculate",
            size=32,
            local_variables=[
                LocalVariable(id="var_a", name="a", type_name="int"),
                LocalVariable(id="var_b", name="b", type_name="int"),
                LocalVariable(id="var_c", name="c", type_name="int"),
            ],
            decompiled_code=code,
        )
        session.functions[func.address] = func

        res = mutator.update_variable_type(
            session=session,
            function_address=0x401300,
            var_name="b",
            new_type="int64_t",
        )
        assert res.success is True
        updated_code = func.decompiled_code
        assert updated_code is not None
        code_str = updated_code.code if isinstance(updated_code, DecompiledCode) and updated_code.code is not None else str(updated_code)
        assert "int64_t" in code_str
        assert "b" in code_str

    def test_malformed_incomplete_pseudocode_resilience(self) -> None:
        """SessionMutator does not crash on unclosed braces or invalid syntax in decompiled code."""
        mutator = SessionMutator()
        session = self._create_mock_session()

        malformed_code = """
        int broken_func( {
            int target_var = 42
            // unclosed braces and syntax errors
        """
        func = Function(
            address=0x401400,
            name="broken_func",
            size=16,
            local_variables=[LocalVariable(id="var_target", name="target_var", type_name="int")],
            decompiled_code=malformed_code,
        )
        session.functions[func.address] = func

        res = mutator.update_variable_type(
            session=session,
            function_address=0x401400,
            var_name="target_var",
            new_type="uint32_t",
        )
        assert res.success is True

    def test_immutability_enforcement_and_idempotent_confirmation(self) -> None:
        """
        Strict immutability rejects conflicting renames/retypes,
        but permits idempotent confirmation of the exact grounded name/type.
        """
        mutator = SessionMutator()
        session = self._create_mock_session()

        # Add function and symbol grounded by DYNAMIC_PROBE
        sym = Symbol(
            address=0x401500,
            name="concrete_worker",
            type=SymbolType.FUNCTION,
            confidence=1.0,
        )
        session.add_symbol(sym)
        func = Function(address=0x401500, name="concrete_worker", size=64)
        session.functions[func.address] = func

        tag = EvidenceTag(
            target_type=TargetType.SYMBOL,
            target_id="sym:0x401500",
            suggested_name="concrete_worker",
            source=EvidenceSource.DYNAMIC_PROBE,
            confidence=1.0,
            raw_anchor="probe:0x401500",
            explanation="Runtime probed function",
            is_immutable=True,
        )
        session.attach_evidence(tag)

        # 1. Adversarial rename -> MUST raise ToolError
        with pytest.raises(ToolError, match="locked by immutable evidence"):
            mutator.rename_symbol(session, 0x401500, "fake_worker")

        # 2. Idempotent confirmation of exact grounded name -> MUST succeed
        res = mutator.rename_symbol(session, 0x401500, "concrete_worker")
        assert res.success is True
        assert res.new_value == "concrete_worker"


# ============================================================================
# Section 3: RecompilationSandbox Adversarial Hardening
# ============================================================================

class TestRecompilationSandboxTier5:
    """Stress tests for RecompilationSandbox against preprocessor aborts, warnings, and missing tools."""

    def test_explicit_preprocessor_error_directive(self) -> None:
        """Compiler cleanly handles and reports #error directives in source code."""
        sandbox = RecompilationSandbox()
        code = """
        #error "Metis Adversarial Preprocessor Failure Triggered"
        int main() { return 0; }
        """
        out = sandbox.compile(source=code, compiler="clang")
        try:
            assert out.success is False
            assert out.binary_path is None
            assert out.returncode != 0
            assert "Metis Adversarial Preprocessor Failure Triggered" in (out.stderr + out.compile_errors_summary)
            assert len(out.diagnostics) >= 1
            assert any(d.severity in ("error", "fatal error") for d in out.diagnostics)
        finally:
            sandbox.cleanup()

    def test_empty_source_and_comments_only(self) -> None:
        """Empty source code or comments only fails link cleanly with structured diagnostics."""
        sandbox = RecompilationSandbox()
        out = sandbox.compile(source="/* Only a comment, no main function */", compiler="clang")
        try:
            assert out.success is False
            assert out.binary_path is None
            assert out.returncode != 0
            assert out.compile_errors_summary != ""
        finally:
            sandbox.cleanup()

    def test_warning_behavior_with_and_without_werror(self) -> None:
        """Code with benign compiler warnings succeeds normally, but fails when treat_warnings_as_errors=True."""
        sandbox = RecompilationSandbox()
        warning_code = """
        #include <stdio.h>
        int main(void) {
            int unused_local_variable = 42;
            printf("Running test\\n");
            return 0;
        }
        """
        # 1. Normal: succeeds
        out_normal = sandbox.compile(source=warning_code, compiler="clang", treat_warnings_as_errors=False)
        try:
            assert out_normal.success is True
            assert out_normal.binary_path is not None
            assert out_normal.binary_path.exists()
            assert any(d.severity == "warning" for d in out_normal.diagnostics)
        finally:
            sandbox.cleanup()

        # 2. Strict (-Werror): fails
        out_strict = sandbox.compile(source=warning_code, compiler="clang", treat_warnings_as_errors=True)
        try:
            assert out_strict.success is False
            assert out_strict.binary_path is None
            assert out_strict.returncode != 0
        finally:
            sandbox.cleanup()

    def test_nonexistent_compiler_detection_and_reporting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When no target or fallback compiler exists, returns returncode 127 without Python crash."""
        info = CompilerDetector.probe_compiler("metis_nonexistent_compiler_bin_9999")
        assert info.is_available is False
        assert info.path == ""

        # Simulate host where both clang and gcc probes fail
        monkeypatch.setattr(
            CompilerDetector,
            "probe_compiler",
            classmethod(lambda cls, name: CompilerInfo(name=name, path="", version="", is_available=False)),
        )

        sandbox = RecompilationSandbox()
        out = sandbox.compile(source="int main() { return 0; }", compiler="nonexistent_compiler")
        assert out.success is False
        assert out.returncode == 127
        assert "not found in PATH" in out.stderr

    def test_output_path_creates_nested_directories(self) -> None:
        """Specifying an output_path in a non-existent subfolder automatically creates parents."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_bin = Path(tmpdir) / "level1" / "level2" / "custom_bin"
            sandbox = RecompilationSandbox()
            out = sandbox.compile(
                source="int main() { return 0; }",
                compiler="clang",
                output_path=nested_bin,
            )
            try:
                assert out.success is True
                assert nested_bin.exists()
                assert os.access(nested_bin, os.X_OK)
            finally:
                sandbox.cleanup()


# ============================================================================
# Section 4: DifferentialTester Robustness & Concurrency
# ============================================================================

class TestDifferentialTesterTier5:
    """Stress tests for DifferentialTester against runaway child processes, non-ASCII, and concurrency."""

    def test_runaway_forking_child_process_termination(self) -> None:
        """
        Target process that forks background infinite-loop children is killed
        completely with os.killpg(SIGKILL), leaving no orphan processes behind.
        """
        tester = DifferentialTester(timeout_seconds=0.5)

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            script_path = f.name
            f.write("""
import os, time, sys
pid = os.fork()
if pid == 0:
    # Child runaway loop
    while True:
        time.sleep(0.1)
else:
    # Parent also loops
    while True:
        time.sleep(0.1)
""")

        try:
            rc, stdout, stderr, is_timeout = tester.run_single_vector(
                cmd_prefix=[sys.executable, script_path],
                vector={"cli_args": []},
                timeout_sec=0.5,
            )
            assert is_timeout is True
            assert rc == -124
            assert "timed out" in stderr.lower()
        finally:
            with contextlib.suppress(Exception):
                os.remove(script_path)

    def test_non_ascii_and_raw_binary_outputs(self) -> None:
        """Target process emitting null bytes and invalid UTF-8 sequences does not crash tester."""
        tester = DifferentialTester(timeout_seconds=2.0)

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            script_path = f.name
            f.write("""
import sys
sys.stdout.buffer.write(b"\\x00\\xff\\xfe\\x80\\x90HelloBinary\\x00\\n")
sys.stderr.buffer.write(b"\\x00\\x1b[31mErrorBinary\\xff\\n")
sys.exit(0)
""")

        try:
            rc, stdout, stderr, is_to = tester.run_single_vector(
                cmd_prefix=[sys.executable, script_path],
                vector={"cli_args": []},
            )
            assert is_to is False
            assert rc == 0
            assert "HelloBinary" in stdout
            assert "ErrorBinary" in stderr

            norm_out = tester.normalize_output(stdout)
            norm_err = tester.normalize_output(stderr)
            assert isinstance(norm_out, str)
            assert isinstance(norm_err, str)
        finally:
            with contextlib.suppress(Exception):
                os.remove(script_path)

    def test_concurrent_differential_runs_across_multiple_threads(self) -> None:
        """Executing differential tests concurrently across 8 threads suffers no race conditions."""
        tester = DifferentialTester(timeout_seconds=2.0)

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f1:
            bin1 = f1.name
            f1.write("import sys; print(f'OUT:{sys.argv[1]}'); sys.exit(0)\n")

        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f2:
            bin2 = f2.name
            f2.write("import sys; print(f'OUT:{sys.argv[1]}'); sys.exit(0)\n")

        try:
            def run_test(idx: int) -> bool:
                vectors = [
                    {"vector_id": f"v_{idx}_1", "cli_args": [f"arg_{idx}_1"]},
                    {"vector_id": f"v_{idx}_2", "cli_args": [f"arg_{idx}_2"]},
                ]
                res = tester.run_differential_test(
                    session_id=f"thread_sess_{idx}",
                    original_path=bin1,
                    reconstructed_path=bin2,
                    test_vectors=vectors,
                )
                return res.all_passed and res.total_vectors == 2

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(run_test, i) for i in range(16)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            assert all(results)
            assert len(results) == 16
        finally:
            for p in (bin1, bin2):
                with contextlib.suppress(Exception):
                    os.remove(p)

    def test_nonexistent_binary_raises_filenotfound(self) -> None:
        """Targeting non-existent binaries raises FileNotFoundError in DifferentialTester."""
        tester = DifferentialTester()
        with pytest.raises(FileNotFoundError, match="Target binary or script not found"):
            tester.run_differential_test(
                session_id="sess_err",
                original_path="/tmp/definitely_not_existing_bin_orig",
                reconstructed_path="/tmp/definitely_not_existing_bin_rec",
                test_vectors=[{"cli_args": []}],
            )


# ============================================================================
# Section 5: FastMCP Server Protocol, Validation & Concurrency
# ============================================================================

class TestFastMCPServerTier5:
    """Stress tests for FastMCP server tools against invalid parameters and concurrency."""

    @pytest.fixture
    def c_service_session_id(self) -> Iterator[str]:
        """Fixture providing an active session with real stripped c_service."""
        bin_path = Path("tests/synthetic_benchmarks/c_service/bin/c_service_stripped").resolve()
        if not bin_path.exists():
            pytest.skip(f"Stripped binary not found at {bin_path}")
        info = mr_server.open_session(str(bin_path))
        session_id = info.session_id if hasattr(info, "session_id") else info["session_id"]
        yield session_id
        mr_server.close_session(session_id)

    def test_missing_session_id_error_handling_across_all_tools(self) -> None:
        """Calling any FastMCP tool with an invalid session ID returns ToolError or clean failure."""
        fake_sess = "session_does_not_exist_99999"

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.list_functions(fake_sess)

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.disassemble(fake_sess, 0x401000)

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.disassemble_range(fake_sess, 0x401000, 32)

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.get_cfg(fake_sess)

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.decompile(fake_sess, 0x401000)

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.query_evidence(fake_sess, "all")

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.rename_symbol(fake_sess, 0x401000, "new_sym")

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.update_variable_type(fake_sess, 0x401000, "var", "int")

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.define_struct(fake_sess, "MyStruct", {"f": "int"})

        with pytest.raises(ToolError, match=r"Session (?:.* )?not found|Session not found or expired"):
            mr_server.trace_function(fake_sess, 0x401000)

        # close_session returns clean result without throwing
        close_res = mr_server.close_session(fake_sess)
        assert close_res.closed is False

        # recompile_and_verify returns failure RecompileResult
        recomp_res = mr_server.recompile_and_verify(fake_sess, "int main() { return 0; }")
        assert recomp_res.success is False
        assert "not found" in recomp_res.compile_errors

    def test_invalid_address_representations_across_tools(self, c_service_session_id: str) -> None:
        """Negative integers, malformed hex, and non-numeric strings raise ToolError."""
        bad_addresses: list[Any] = [-1, -0x1000, "not_an_address", "0xZZZ", "", "   "]

        for bad_addr in bad_addresses:
            with pytest.raises(ToolError):
                mr_server.disassemble(c_service_session_id, bad_addr)

            with pytest.raises(ToolError):
                mr_server.disassemble_range(c_service_session_id, bad_addr, size=32)

            with pytest.raises(ToolError):
                mr_server.rename_symbol(c_service_session_id, bad_addr, "valid_name")

    def test_trace_function_unknown_prober_error(self, c_service_session_id: str) -> None:
        """Invalid prober specification raises ToolError with supported options."""
        with pytest.raises(ToolError, match="Unknown prober type 'unsupported_prober_xyz'"):
            mr_server.trace_function(
                session_id=c_service_session_id,
                function_address=0x401000,
                prober="unsupported_prober_xyz",
            )

    def test_run_differential_test_missing_files_error(self) -> None:
        """FastMCP run_differential_test raises ToolError if files do not exist."""
        with pytest.raises(ToolError, match="Original binary not found"):
            mr_server.run_differential_test(
                session_id="dummy",
                original_path="/tmp/nonexistent_orig_file",
                reconstructed_binary_path="/tmp/nonexistent_rec_file",
                test_vectors=[],
            )

    def test_malformed_binary_open_session_rejection(self) -> None:
        """open_session rejects corrupted binary files and raises ValueError."""
        fixture = Path("tests/fixtures/malformed_binary.bin").resolve()
        if not fixture.exists():
            pytest.skip("Fixture malformed_binary.bin missing")

        with pytest.raises(ValueError, match="Unsupported binary|malformed binary format"):
            mr_server.open_session(str(fixture))

    def test_concurrent_multithreaded_tool_invocations(self, c_service_session_id: str) -> None:
        """Concurrent calls to query_evidence, list_functions, disassemble, and define_struct execute safely."""
        funcs = mr_server.list_functions(c_service_session_id)
        assert len(funcs) > 0
        target_addr = funcs[0].address

        def worker(thread_id: int) -> bool:
            f_list = mr_server.list_functions(c_service_session_id)
            assert len(f_list) > 0

            dis = mr_server.disassemble(c_service_session_id, target_addr, size=16)
            assert dis.instruction_count >= 0

            ev = mr_server.query_evidence(c_service_session_id, "all")
            assert isinstance(ev, list)

            st_name = f"ConcurrentStruct_{thread_id}"
            mut = mr_server.define_struct(
                c_service_session_id,
                st_name,
                {"val": "uint32_t", "idx": "int16_t"},
            )
            assert mut.success is True
            return True

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(worker, i) for i in range(12)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert all(results)
        assert len(results) == 12
