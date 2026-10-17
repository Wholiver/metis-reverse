"""
Unit Tests for Metis Reverse Milestone 4: Interactive DB Mutation & Equivalence Recompilation Loop.
Covers:
- TypeLayoutEngine & Struct Layout (SysV / AAPCS ABI rules, alignment, padding, arrays)
- SessionMutator (rename_symbol, update_variable_type, define_struct, Tree-sitter CST rewrites, immutability)
- RecompilationSandbox (Clang/GCC sandbox compilation, diagnostics parsing, synthetic prelude, warnings vs errors)
- DifferentialTester (Subprocess isolation, timeouts, stdin EOF, normalization, unified diff generation)
- Milestone 4 Domain Models (StructDefinition, DifferentialVectorResult, DifferentialResult, RecompileResult)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

from metis_reverse.backends.tier1_native.ast_engine import TreeSitterAstEngine
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySession,
    DifferentialResult,
    DifferentialVectorResult,
    EvidenceSource,
    EvidenceTag,
    Function,
    LocalVariable,
    RecompileResult,
    StructDefinition,
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
    RecompilationSandbox,
)

# ============================================================================
# Dimension 1: Milestone 4 Domain Models
# ============================================================================

class TestMilestone4Models:
    """Verifies domain model contracts: attribute access, dict subscripting, .get(), and awaitability."""

    def test_struct_definition_model(self):
        struct_def = StructDefinition(
            name="TestConfig",
            fields={"port": "uint32_t", "magic": "uint32_t"},
            size=8,
            alignment=4,
            field_offsets={"port": 0, "magic": 4},
        )
        # Attribute access
        assert struct_def.name == "TestConfig"
        assert struct_def.size == 8
        assert struct_def.total_size == 8
        assert struct_def.alignment == 4
        assert struct_def.field_offsets["port"] == 0
        # Dict subscripting
        assert struct_def["size"] == 8
        assert struct_def["name"] == "TestConfig"
        # .get() access
        assert struct_def.get("size") == 8
        assert struct_def.get("nonexistent", "default") == "default"

    @pytest.mark.asyncio
    async def test_struct_definition_awaitable(self):
        struct_def = StructDefinition(name="AsyncStruct", size=16, alignment=8)
        res = await struct_def
        assert res.name == "AsyncStruct"
        assert res.size == 16

    def test_differential_vector_result_model(self):
        vec = DifferentialVectorResult(
            vector_name="V01_TEST",
            passed=True,
            original_exit_code=0,
            reconstructed_exit_code=0,
            original_stdout="hello\n",
            reconstructed_stdout="hello\n",
        )
        assert vec.vector_name == "V01_TEST"
        assert vec.vector_id == "V01_TEST"
        assert vec.passed is True
        assert vec["passed"] is True
        assert vec.get("original_exit_code") == 0

    @pytest.mark.asyncio
    async def test_differential_vector_result_awaitable(self):
        vec = DifferentialVectorResult(
            vector_name="V_ASYNC",
            passed=False,
            original_exit_code=0,
            reconstructed_exit_code=1,
            diff_details="Exit code mismatch",
        )
        awaited = await vec
        assert awaited.passed is False
        assert awaited["diff_details"] == "Exit code mismatch"

    def test_differential_result_model(self):
        vec = DifferentialVectorResult(
            vector_name="V01",
            passed=True,
            original_exit_code=0,
            reconstructed_exit_code=0,
        )
        diff_res = DifferentialResult(
            session_id="s_test",
            all_passed=True,
            total_vectors=1,
            passed_vectors=1,
            equivalence_percentage=100.0,
            vector_results=[vec],
        )
        assert diff_res.all_passed is True
        assert diff_res["equivalence_percentage"] == 100.0
        assert diff_res.get("total_vectors") == 1
        assert len(diff_res.vector_results) == 1

    @pytest.mark.asyncio
    async def test_differential_result_awaitable(self):
        diff_res = DifferentialResult(
            session_id="s_async",
            all_passed=False,
            total_vectors=2,
            passed_vectors=1,
            equivalence_percentage=50.0,
        )
        awaited = await diff_res
        assert awaited.all_passed is False
        assert awaited.equivalence_percentage == 50.0

    def test_recompile_result_model(self):
        rec = RecompileResult(
            session_id="s_rec",
            success=True,
            binary_path="/tmp/build/bin",
            compile_errors="",
            compile_warnings="unused var",
            equivalence_percentage=100.0,
        )
        assert rec.success is True
        assert rec["binary_path"] == "/tmp/build/bin"
        assert rec.get("compile_warnings") == "unused var"
        assert rec.equivalence_percentage == 100.0

    @pytest.mark.asyncio
    async def test_recompile_result_awaitable(self):
        rec = RecompileResult(
            session_id="s_async_rec",
            success=False,
            compile_errors="syntax error",
        )
        awaited = await rec
        assert awaited.success is False
        assert awaited.compile_errors == "syntax error"


# ============================================================================
# Dimension 2: TypeLayoutEngine & Struct Layout
# ============================================================================

class TestTypeLayoutEngine:
    """Verifies C ABI alignment, padding, and field offset computation."""

    def test_primitive_type_resolutions(self):
        # 1-byte types
        for t in ("char", "int8_t", "uint8_t", "bool", "unsigned char"):
            sz, align, is_ptr, arr = TypeLayoutEngine.resolve_type(t)
            assert sz == 1 and align == 1 and not is_ptr and arr is None

        # 2-byte types
        for t in ("short", "int16_t", "uint16_t"):
            sz, align, is_ptr, arr = TypeLayoutEngine.resolve_type(t)
            assert sz == 2 and align == 2 and not is_ptr and arr is None

        # 4-byte types
        for t in ("int", "uint32_t", "int32_t", "float"):
            sz, align, is_ptr, arr = TypeLayoutEngine.resolve_type(t)
            assert sz == 4 and align == 4 and not is_ptr and arr is None

        # 8-byte types
        for t in ("long", "uint64_t", "int64_t", "double", "size_t", "uintptr_t"):
            sz, align, is_ptr, arr = TypeLayoutEngine.resolve_type(t, bitness=64)
            assert sz == 8 and align == 8 and not is_ptr and arr is None

        # Pointers
        for p in ("void*", "char*", "int*", "ServiceConfig*"):
            sz, align, is_ptr, arr = TypeLayoutEngine.resolve_type(p, bitness=64)
            assert sz == 8 and align == 8 and is_ptr is True and arr is None

    def test_array_type_resolution(self):
        sz, align, is_ptr, arr = TypeLayoutEngine.resolve_type("char[64]")
        assert sz == 64 and align == 1 and not is_ptr and arr == 64

        sz4, align4, _, arr4 = TypeLayoutEngine.resolve_type("uint32_t[4]")
        assert sz4 == 16 and align4 == 4 and arr4 == 4

    def test_service_config_benchmark_struct_layout(self):
        """Verifies ServiceConfig layout matching C ABI: total 72 bytes."""
        layout = TypeLayoutEngine.compute_layout(
            struct_name="ServiceConfig",
            fields_map={
                "magic": "uint32_t",
                "port": "uint32_t",
                "secret_token": "char[64]",
            },
            bitness=64,
            is_packed=False,
        )
        assert layout.name == "ServiceConfig"
        assert layout.field_offsets["magic"] == 0
        assert layout.field_offsets["port"] == 4
        assert layout.field_offsets["secret_token"] == 8
        assert layout.alignment == 4
        assert layout.total_size == 72
        assert layout.size == 72

    def test_struct_alignment_padding_rules(self):
        """Test alignment gap between char and uint64_t."""
        layout = TypeLayoutEngine.compute_layout(
            struct_name="PaddedStruct",
            fields_map={
                "tag": "char",      # offset 0, sz 1, pad 7
                "id": "uint64_t",   # offset 8, sz 8
                "flag": "char",     # offset 16, sz 1, pad 7 for struct alignment
            },
            bitness=64,
            is_packed=False,
        )
        assert layout.field_offsets["tag"] == 0
        assert layout.field_offsets["id"] == 8
        assert layout.field_offsets["flag"] == 16
        assert layout.alignment == 8
        assert layout.total_size == 24

    def test_packed_struct_layout(self):
        """Packed structs must have alignment 1 and zero inter-field padding."""
        layout = TypeLayoutEngine.compute_layout(
            struct_name="PackedHeader",
            fields_map={
                "tag": "char",
                "id": "uint64_t",
                "flag": "char",
            },
            bitness=64,
            is_packed=True,
        )
        assert layout.field_offsets["tag"] == 0
        assert layout.field_offsets["id"] == 1
        assert layout.field_offsets["flag"] == 9
        assert layout.alignment == 1
        assert layout.total_size == 10

    def test_nested_struct_layout(self):
        inner = TypeLayoutEngine.compute_layout(
            struct_name="Point",
            fields_map={"x": "int", "y": "int"},
        )
        assert inner.total_size == 8

        outer = TypeLayoutEngine.compute_layout(
            struct_name="Shape",
            fields_map={"origin": "struct Point", "color": "int"},
            structs={"Point": inner},
        )
        assert outer.field_offsets["origin"] == 0
        assert outer.field_offsets["color"] == 8
        assert outer.total_size == 12


# ============================================================================
# Dimension 3: SessionMutator & Tree-sitter CST Cascaded Updates
# ============================================================================

class TestSessionMutator:
    """Verifies SessionMutator rename, retype, struct definition, and immutability invariants."""

    @pytest.fixture
    def mock_session(self) -> BinarySession:
        artifact = TargetArtifact(
            artifact_id="art_test",
            file_path="/tmp/test_binary",
            architecture=ArchitectureType.ARM64,
            format=ArtifactFormat.MACHO,
            bitness=64,
        )
        sess = BinarySession(session_id="sess_mock_mutator", artifact=artifact)

        # Add a test function with decompiled C pseudocode
        f1 = Function(
            name="sub_1000",
            address=0x1000,
            size=64,
            decompiled_code=(
                "int sub_1000(int client_fd, int port) {\n"
                "    int status = 0;\n"
                "    return status + port;\n"
                "}\n"
            ),
        )
        f1.parameters = [
            {"name": "client_fd", "type_name": "int"},
            {"name": "port", "type_name": "int"},
        ]
        f1.local_variables = [
            LocalVariable(id="var_status", name="status", type_name="int", offset=-4, size=4),
        ]
        sess.functions[0x1000] = f1

        sym1 = Symbol(
            address=0x1000,
            name="sub_1000",
            type=SymbolType.FUNCTION,
        )
        sess.add_symbol(sym1)
        return sess

    def test_rename_symbol_success_and_ast_cascade(self, mock_session: BinarySession):
        mutator = SessionMutator()
        res = mutator.rename_symbol(
            session=mock_session,
            address=0x1000,
            new_name="handle_connection",
            reason="Reverse engineered handler",
        )
        assert res.success is True
        assert res.new_value == "handle_connection"
        assert mock_session.functions[0x1000].name == "handle_connection"
        assert mock_session.symbols["handle_connection"].address == 0x1000

        # Verify cascaded AST pseudocode rewrite
        code = str(mock_session.functions[0x1000].decompiled_code)
        assert "handle_connection(int client_fd, int port)" in code
        assert "sub_1000" not in code

    def test_rename_symbol_rejects_empty_name_or_invalid_address(self, mock_session: BinarySession):
        mutator = SessionMutator()
        with pytest.raises(ToolError, match="cannot be empty"):
            mutator.rename_symbol(mock_session, 0x1000, "")

        with pytest.raises(ToolError, match="cannot be negative"):
            mutator.rename_symbol(mock_session, -1, "valid_name")

    def test_rename_symbol_blocks_grounded_symbol_immutability(self, mock_session: BinarySession):
        # Attach grounded compiler symbol tag
        tag = EvidenceTag(
            target_type=TargetType.SYMBOL,
            target_id="sym:0x1000",
            suggested_name="sub_1000",
            source=EvidenceSource.GO_PCLNTAB,
            confidence=1.0,
            is_immutable=True,
        )
        mock_session.attach_evidence(tag)

        mutator = SessionMutator()
        with pytest.raises(ToolError, match="locked by immutable evidence"):
            mutator.rename_symbol(mock_session, 0x1000, "renamed_symbol")

    def test_format_string_parameter_evidence_does_not_lock_function_symbol(self, mock_session: BinarySession):
        """Format string parameter tags infer variable facts and do not lock function symbols."""
        tag = EvidenceTag(
            target_type=TargetType.FUNCTION,
            target_id="func:0x1000",
            suggested_name="port",
            source=EvidenceSource.FORMAT_STRING,
            confidence=1.0,
            is_immutable=True,
        )
        mock_session.attach_evidence(tag)

        mutator = SessionMutator()
        # Unlocked function allows clean constructive renaming
        res = mutator.rename_symbol(mock_session, 0x1000, "reconstructed_service")
        assert res.success is True
        assert mock_session.functions[0x1000].name == "reconstructed_service"

    def test_update_variable_type_success_and_ast_cascade(self, mock_session: BinarySession):
        mutator = SessionMutator()
        # Retype parameter
        res_param = mutator.update_variable_type(
            session=mock_session,
            function_address=0x1000,
            var_name="port",
            new_type="uint32_t",
        )
        assert res_param.success is True
        code = str(mock_session.functions[0x1000].decompiled_code)
        assert "uint32_t port" in code

        # Retype local variable
        res_local = mutator.update_variable_type(
            session=mock_session,
            function_address=0x1000,
            var_name="status",
            new_type="int32_t",
        )
        assert res_local.success is True
        code2 = str(mock_session.functions[0x1000].decompiled_code)
        assert "int32_t status" in code2

    def test_update_variable_type_blocks_immutable_evidence(self, mock_session: BinarySession):
        tag = EvidenceTag(
            target_type=TargetType.VARIABLE,
            target_id="func:0x1000:var:port",
            suggested_name="port",
            suggested_type="uint32_t",
            source=EvidenceSource.FORMAT_STRING,
            confidence=1.0,
            is_immutable=True,
        )
        mock_session.attach_evidence(tag)

        mutator = SessionMutator()
        # Adversarial or conflicting retype should be blocked
        with pytest.raises(ToolError, match="locked by immutable evidence"):
            mutator.update_variable_type(mock_session, 0x1000, "port", "char*")

    def test_retype_pointer_parameter_no_double_pointer(self, mock_session: BinarySession):
        """Retyping int *ptr to char* must produce char* ptr, not char* *ptr."""
        func = Function(
            name="process_buffer",
            address=0x2000,
            decompiled_code="void process_buffer(int *ptr, int size) {\n    return;\n}\n",
        )
        mock_session.functions[0x2000] = func
        mutator = SessionMutator()
        res = mutator.update_variable_type(mock_session, 0x2000, "ptr", "char*")
        assert res.success is True
        code = str(mock_session.functions[0x2000].decompiled_code)
        assert "char* ptr" in code
        assert "char* *ptr" not in code

    def test_retype_uninitialized_local_pointer_cst(self, mock_session: BinarySession):
        """Retyping uninitialized local pointer int *local_ptr to char* via CST walk."""
        func = Function(
            name="worker",
            address=0x3000,
            decompiled_code="void worker() {\n    int *local_ptr;\n    *local_ptr = 1;\n}\n",
        )
        mock_session.functions[0x3000] = func
        mutator = SessionMutator()
        res = mutator.update_variable_type(mock_session, 0x3000, "local_ptr", "char*")
        assert res.success is True
        code = str(mock_session.functions[0x3000].decompiled_code)
        assert "char* local_ptr;" in code

    def test_ast_engine_field_identifier_and_rename_isolation(self):
        """AstEngine captures field_identifier and rename_identifier isolates fields from variables."""
        ast_eng = TreeSitterAstEngine()
        c_code = (
            "struct Config {\n"
            "    int port;\n"
            "};\n"
            "int run(struct Config *cfg) {\n"
            "    int port = 8080;\n"
            "    return cfg->port + port;\n"
            "}\n"
        )
        tokens = ast_eng.extract_identifiers(c_code)
        field_tokens = [t for t in tokens if t.node_type == "field_identifier" and t.name == "port"]
        ident_tokens = [t for t in tokens if t.node_type == "identifier" and t.name == "port"]
        assert len(field_tokens) >= 1
        assert len(ident_tokens) >= 1

        # Renaming identifier with include_fields=False should rename variable but preserve cfg->port
        renamed = ast_eng.rename_identifier(c_code, "port", "new_port", include_fields=False)
        assert "cfg->port" in renamed
        assert "int new_port = 8080;" in renamed
        assert "return cfg->port + new_port;" in renamed

    def test_define_struct_success(self, mock_session: BinarySession):
        mutator = SessionMutator()
        res = mutator.define_struct(
            session=mock_session,
            struct_name="PacketHeader",
            fields={"magic": "uint32_t", "length": "uint16_t"},
        )
        assert res.success is True
        assert "PacketHeader" in mock_session.struct_definitions
        st = mock_session.get_struct_definition("PacketHeader")
        assert st is not None
        assert st.total_size == 8
        assert st.field_offsets["magic"] == 0
        assert st.field_offsets["length"] == 4


# ============================================================================
# Dimension 4: RecompilationSandbox & Diagnostics
# ============================================================================

class TestRecompilationSandbox:
    """Verifies isolated Clang compilation, diagnostics parsing, and synthetic prelude."""

    def test_compiler_detection(self):
        info = CompilerDetector.probe_compiler("clang")
        assert info.is_available is True
        assert info.path != ""

    def test_compile_clean_valid_c_program(self):
        sandbox = RecompilationSandbox()
        code = (
            "#include <stdio.h>\n"
            "int main(void) {\n"
            "    printf(\"sandbox test pass\\n\");\n"
            "    return 0;\n"
            "}\n"
        )
        output = sandbox.compile(source=code, compiler="clang")
        try:
            assert output.success is True
            assert output.binary_path is not None
            assert output.binary_path.exists()
            assert output.returncode == 0
            assert len([d for d in output.diagnostics if d.severity == "error"]) == 0
        finally:
            sandbox.cleanup()

    def test_compile_with_warnings_preserves_binary(self):
        """Unused variables generate warnings in compile_warnings but compile still succeeds."""
        sandbox = RecompilationSandbox()
        code = (
            "#include <stdio.h>\n"
            "int main(void) {\n"
            "    int unused_counter = 42;\n"
            "    printf(\"warning test\\n\");\n"
            "    return 0;\n"
            "}\n"
        )
        output = sandbox.compile(source=code, compiler="clang")
        try:
            assert output.success is True
            assert output.binary_path is not None
            assert "unused" in output.compile_warnings_summary.lower()
        finally:
            sandbox.cleanup()

    def test_compile_syntax_errors_returns_failure_and_diagnostics(self):
        sandbox = RecompilationSandbox()
        bad_code = (
            "#include <stdio.h>\n"
            "int main(void) {\n"
            "    undefined_function_call();\n"
            "    return 0\n"  # Missing semicolon
            "}\n"
        )
        output = sandbox.compile(source=bad_code, compiler="clang")
        try:
            assert output.success is False
            assert output.binary_path is None
            assert output.returncode != 0
            assert output.compile_errors_summary != ""
            assert len(output.diagnostics) > 0
        finally:
            sandbox.cleanup()

    def test_synthetic_prelude_injection_resolves_missing_includes(self):
        """Code missing #include <stdint.h> and <stdio.h> compiles via synthetic prelude."""
        sandbox = RecompilationSandbox()
        code_without_includes = (
            "int main(void) {\n"
            "    uint32_t val = 12345;\n"
            "    printf(\"val: %u\\n\", val);\n"
            "    return 0;\n"
            "}\n"
        )
        output = sandbox.compile(source=code_without_includes, compiler="clang", auto_prelude=True)
        try:
            assert output.success is True
            assert output.binary_path is not None
        finally:
            sandbox.cleanup()


# ============================================================================
# Dimension 5: DifferentialTester
# ============================================================================

class TestDifferentialTester:
    """Verifies subprocess execution, timeout handling, output normalization, and unified diff."""

    def test_normalize_output_line_endings_and_masks(self):
        tester = DifferentialTester()
        raw = "Line 1\r\n2026-10-16T12:00:00Z [INFO] Service started pid 12345\r\n"
        norm = tester.normalize_output(raw)
        assert "\r" not in norm
        assert "<TIMESTAMP>" in norm
        assert "<PID>" in norm

    def test_run_single_vector_timeout_protection(self):
        tester = DifferentialTester(timeout_seconds=0.5)
        # sleep 10 will time out after 0.5s
        rc, out, err, is_to = tester.run_single_vector(
            cmd_prefix=["/bin/sleep"],
            vector={"cli_args": ["10"]},
            timeout_sec=0.5,
        )
        assert is_to is True
        assert rc == -124
        assert "timed out" in err.lower()

    def test_differential_comparison_identical_binaries(self):
        tester = DifferentialTester()
        ls_path = "/bin/ls"
        if not Path(ls_path).exists():
            ls_path = "/usr/bin/ls"

        vectors = [
            {"vector_id": "V1", "cli_args": ["-d", "/tmp"]},
        ]
        res = tester.run_differential_test(
            session_id="s1",
            original_path=ls_path,
            reconstructed_path=ls_path,
            test_vectors=vectors,
        )
        assert res.all_passed is True
        assert res.equivalence_percentage == 100.0
        assert res.passed_vectors == 1

    def test_differential_comparison_detects_mismatch_with_unified_diff(self):
        tester = DifferentialTester()
        true_bin = "/usr/bin/true"
        false_bin = "/usr/bin/false"

        vectors = [
            {"vector_id": "V_MISMATCH", "cli_args": []},
        ]
        res = tester.run_differential_test(
            session_id="s2",
            original_path=true_bin,
            reconstructed_path=false_bin,
            test_vectors=vectors,
        )
        assert res.all_passed is False
        assert res.equivalence_percentage == 0.0
        assert res.vector_results[0].passed is False
        assert "Exit code mismatch" in (res.vector_results[0].diff_details or "")
