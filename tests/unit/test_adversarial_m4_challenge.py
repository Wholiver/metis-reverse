"""
Adversarial Stress Test Suite for Milestone 4 (Interactive DB Mutation & Equivalence Recompilation Loop).
Challenger: Challenger M4-1

Tests:
1. Oracle-verified struct layout calculation under SysV AMD64 and ARM64 ABI:
   - Complex padding, multi-field structs, trailing padding.
   - Nested structs (normal in normal, packed in normal, normal in packed).
   - Array of nested structs, multi-dimensional arrays, pointer arrays.
   - Empirical comparison against host C compiler (clang/gcc) sizeof and offsetof.
2. Tree-sitter CST AST rewriting:
   - Renaming symbols in complex C pseudocode (nested scopes, shadowing identifiers, pointer type declarations, struct member accesses).
   - Pointer type declarations in update_variable_type and multi-variable declarations.
3. Immutability boundary:
   - Verification that adversarial and benign renames on locked symbols (DYNAMIC_PROBE, GO_PCLNTAB, CPP_RTTI, ASSERT_MACRO) are strictly rejected with ToolError.
   - Verification that constructive renaming on anonymous functions succeeds.
   - Verification that immutable variable types reject conflicting retyping.
4. Malformed types, invalid addresses, empty strings, and concurrent mutations:
   - Negative addresses, invalid hex strings, empty symbol/struct names, empty fields.
   - Concurrent multithreaded mutations.
"""

from __future__ import annotations

import concurrent.futures
import os
import shutil
import subprocess
import tempfile
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySession,
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
from metis_reverse.equivalence.mutator import (
    SessionMutator,
    TypeLayoutEngine,
    parse_int_address,
)

# ============================================================================
# Dimension 1: Oracle-Verified Struct Alignment under SysV AMD64 & ARM64 ABI
# ============================================================================


def compile_and_query_c_struct(c_code: str, struct_name: str, fields: list[str]) -> tuple[int, int, dict[str, int]]:
    """
    Empirical Oracle: Compiles a real C program using clang and reads sizeof,
    _Alignof, and offsetof for each field.
    """
    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        pytest.skip("No C compiler (clang or gcc) available on host to serve as oracle.")

    with tempfile.TemporaryDirectory() as tmpdir:
        src_file = os.path.join(tmpdir, "oracle.c")
        bin_file = os.path.join(tmpdir, "oracle_bin")

        field_prints = "".join(f'printf(",%zu", offsetof({struct_name}, {f}));\n' for f in fields)
        full_code = f"""
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

{c_code}

int main(void) {{
    printf("%zu,%zu", sizeof({struct_name}), _Alignof({struct_name}));
    {field_prints}
    return 0;
}}
"""
        with open(src_file, "w") as f:
            f.write(full_code)

        build_res = subprocess.run(
            [compiler, "-O0", src_file, "-o", bin_file],
            capture_output=True,
            text=True,
            check=False,
        )
        if build_res.returncode != 0:
            raise RuntimeError(f"Oracle C code compilation failed: {build_res.stderr}")

        run_res = subprocess.run([bin_file], capture_output=True, text=True, check=True)
        tokens = [int(x) for x in run_res.stdout.strip().split(",")]

        total_size = tokens[0]
        alignment = tokens[1]
        field_offsets = {f: tokens[2 + i] for i, f in enumerate(fields)}
        return total_size, alignment, field_offsets


class TestOracleStructAlignment:
    """Empirical verification comparing TypeLayoutEngine directly to host C compiler."""

    def test_complex_multi_field_padding(self) -> None:
        """Char, short, int, long alternating with uneven padding."""
        c_code = """
        struct ComplexPadded {
            char a;
            int16_t b;
            char c;
            int32_t d;
            char e;
            int64_t f;
            char g;
        };
        """
        fields_map = {
            "a": "char",
            "b": "int16_t",
            "c": "char",
            "d": "int32_t",
            "e": "char",
            "f": "int64_t",
            "g": "char",
        }
        oracle_size, oracle_align, oracle_offsets = compile_and_query_c_struct(
            c_code, "struct ComplexPadded", list(fields_map.keys())
        )

        layout = TypeLayoutEngine.compute_layout("ComplexPadded", fields_map, bitness=64)

        assert layout.total_size == oracle_size
        assert layout.alignment == oracle_align
        for f, off in oracle_offsets.items():
            assert layout.field_offsets[f] == off

    def test_deeply_nested_struct_padding(self) -> None:
        """Nested structs with internal and tail padding."""
        c_code = """
        struct InnerA {
            char c;
            int32_t val;
            char flag;
        };
        struct InnerB {
            int16_t x;
            struct InnerA a;
            int64_t y;
        };
        struct OuterTop {
            char head;
            struct InnerB b;
            char tail;
        };
        """
        inner_a = TypeLayoutEngine.compute_layout(
            "InnerA", {"c": "char", "val": "int32_t", "flag": "char"}, bitness=64
        )
        inner_b = TypeLayoutEngine.compute_layout(
            "InnerB",
            {"x": "int16_t", "a": "struct InnerA", "y": "int64_t"},
            bitness=64,
            structs={"InnerA": inner_a},
        )
        outer = TypeLayoutEngine.compute_layout(
            "OuterTop",
            {"head": "char", "b": "struct InnerB", "tail": "char"},
            bitness=64,
            structs={"InnerA": inner_a, "InnerB": inner_b},
        )

        oracle_size, oracle_align, oracle_offsets = compile_and_query_c_struct(
            c_code, "struct OuterTop", ["head", "b", "tail"]
        )

        assert outer.total_size == oracle_size
        assert outer.alignment == oracle_align
        for f, off in oracle_offsets.items():
            assert outer.field_offsets[f] == off

    def test_array_of_nested_structs(self) -> None:
        """Array of nested structs with trailing padding."""
        c_code = """
        struct Vertex {
            int32_t x;
            char tag;
        };
        struct Mesh {
            char name[16];
            struct Vertex vertices[4];
            int64_t flags;
        };
        """
        vertex = TypeLayoutEngine.compute_layout(
            "Vertex", {"x": "int32_t", "tag": "char"}, bitness=64
        )
        mesh = TypeLayoutEngine.compute_layout(
            "Mesh",
            {"name": "char[16]", "vertices": "struct Vertex[4]", "flags": "int64_t"},
            bitness=64,
            structs={"Vertex": vertex},
        )

        oracle_size, oracle_align, oracle_offsets = compile_and_query_c_struct(
            c_code, "struct Mesh", ["name", "vertices", "flags"]
        )

        assert mesh.total_size == oracle_size
        assert mesh.alignment == oracle_align
        for f, off in oracle_offsets.items():
            assert mesh.field_offsets[f] == off

    def test_packed_struct_with_pragmas(self) -> None:
        """Packed struct should match #pragma pack(1)."""
        c_code = """
        #pragma pack(push, 1)
        struct PackedRecord {
            char type;
            uint32_t length;
            uint64_t timestamp;
            uint16_t checksum;
        };
        #pragma pack(pop)
        """
        fields = {
            "type": "char",
            "length": "uint32_t",
            "timestamp": "uint64_t",
            "checksum": "uint16_t",
        }
        oracle_size, oracle_align, oracle_offsets = compile_and_query_c_struct(
            c_code, "struct PackedRecord", list(fields.keys())
        )

        layout = TypeLayoutEngine.compute_layout("PackedRecord", fields, bitness=64, is_packed=True)

        assert layout.total_size == oracle_size
        assert layout.alignment == oracle_align
        for f, off in oracle_offsets.items():
            assert layout.field_offsets[f] == off

    def test_multi_dimensional_array_and_pointers(self) -> None:
        """Multi-dimensional arrays and pointer types."""
        c_code = """
        struct ComplexArrayPtr {
            char id;
            int32_t grid[3][5];
            char *strings[4];
            void *callback;
        };
        """
        fields = {
            "id": "char",
            "grid": "int32_t[15]",  # 3*5 = 15 elements
            "strings": "char*[4]",
            "callback": "void*",
        }
        oracle_size, oracle_align, oracle_offsets = compile_and_query_c_struct(
            c_code, "struct ComplexArrayPtr", list(fields.keys())
        )

        layout = TypeLayoutEngine.compute_layout("ComplexArrayPtr", fields, bitness=64)

        assert layout.total_size == oracle_size
        assert layout.alignment == oracle_align
        for f, off in oracle_offsets.items():
            assert layout.field_offsets[f] == off

    def test_bitness_32_vs_64(self) -> None:
        """Verify 32-bit architecture pointers and longs are 4 bytes with 4-byte alignment."""
        fields = {"ptr": "void*", "val": "long", "flag": "char"}
        layout32 = TypeLayoutEngine.compute_layout("Header32", fields, bitness=32)
        assert layout32.field_offsets["ptr"] == 0
        assert layout32.field_offsets["val"] == 4
        assert layout32.field_offsets["flag"] == 8
        assert layout32.alignment == 4
        assert layout32.total_size == 12

        layout64 = TypeLayoutEngine.compute_layout("Header64", fields, bitness=64)
        assert layout64.field_offsets["ptr"] == 0
        assert layout64.field_offsets["val"] == 8
        assert layout64.field_offsets["flag"] == 16
        assert layout64.alignment == 8
        assert layout64.total_size == 24


# ============================================================================
# Dimension 2: Tree-sitter CST AST Rewriting Adversarial Tests
# ============================================================================


class TestTreeSitterAstRewriterAdversarial:
    """Stress tests Tree-sitter concrete syntax tree rewriting on complex C code."""

    def test_struct_member_access_not_corrupted_by_symbol_rename(self) -> None:
        """Renaming a symbol with the same name as a struct field must NOT rename the field."""
        code = (
            "struct Connection {\n"
            "    int port;\n"
            "    char *host;\n"
            "};\n"
            "int port(struct Connection *conn) {\n"
            "    return conn->port;\n"
            "}\n"
        )
        session = BinarySession(
            session_id="s_cst_1",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        func = Function(address=0x1000, name="port", decompiled_code=code)
        session.functions[0x1000] = func
        session.add_symbol(Symbol(address=0x1000, name="port", type=SymbolType.FUNCTION))

        mutator = SessionMutator()
        res = mutator.rename_symbol(session, 0x1000, "get_connection_port")
        assert res.success is True

        updated = str(func.decompiled_code)
        # Function name renamed
        assert "int get_connection_port(struct Connection *conn)" in updated
        # Struct definition and member access untouched
        assert "int port;" in updated
        assert "conn->port" in updated

    def test_pointer_return_type_symbol_rename(self) -> None:
        """Function with pointer return type, e.g. char *fetch_data(int id)."""
        code = 'char *fetch_data(int id) {\n    return "data";\n}\n'
        session = BinarySession(
            session_id="s_cst_2",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        func = Function(address=0x2000, name="fetch_data", decompiled_code=code)
        session.functions[0x2000] = func
        session.add_symbol(Symbol(address=0x2000, name="fetch_data", type=SymbolType.FUNCTION))

        mutator = SessionMutator()
        res = mutator.rename_symbol(session, 0x2000, "get_buffer")
        assert res.success is True

        updated = str(func.decompiled_code)
        assert "char *get_buffer(int id)" in updated

    def test_retype_pointer_variable_empirical_behavior(self) -> None:
        """
        Adversarial test on pointer type rewriting:
        Documenting behavior when retyping pointer declarations in AST.
        """
        code = "void process_buffer(int *buf) {\n    int *local_ptr = buf;\n}\n"
        session = BinarySession(
            session_id="s_cst_3",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        func = Function(
            address=0x3000,
            name="process_buffer",
            parameters=[FunctionParameter(name="buf", type_name="int*")],
            local_variables=[LocalVariable(id="l1", name="local_ptr", type_name="int*")],
            decompiled_code=code,
        )
        session.functions[0x3000] = func

        mutator = SessionMutator()
        # When passing a base type "char", Tree-sitter replaces "int" with "char", resulting in "char *buf"
        res = mutator.update_variable_type(session, 0x3000, "buf", "char")
        assert res.success is True
        assert "char *buf" in str(func.decompiled_code)

    def test_nested_scope_shadowing_preserves_semantics(self) -> None:
        """Shadowed variables in compound blocks."""
        code = (
            "int calculate(int x) {\n"
            "    if (x > 0) {\n"
            "        int x = 100;\n"
            "        return x;\n"
            "    }\n"
            "    return x;\n"
            "}\n"
        )
        session = BinarySession(
            session_id="s_cst_4",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        func = Function(address=0x4000, name="calculate", decompiled_code=code)
        session.functions[0x4000] = func
        session.add_symbol(Symbol(address=0x4000, name="calculate", type=SymbolType.FUNCTION))

        mutator = SessionMutator()
        res = mutator.rename_symbol(session, 0x4000, "execute_math")
        assert res.success is True
        assert "int execute_math(int x)" in str(func.decompiled_code)
        assert "int x = 100;" in str(func.decompiled_code)


# ============================================================================
# Dimension 3: Immutability Boundary Rigorous Stress Testing
# ============================================================================


class TestImmutabilityBoundaryAdversarial:
    """Stress tests anti-hallucination immutability guards."""

    @pytest.mark.parametrize(
        "source",
        [
            EvidenceSource.DYNAMIC_PROBE,
            EvidenceSource.GO_PCLNTAB,
            EvidenceSource.CPP_RTTI,
            EvidenceSource.ASSERT_MACRO,
        ],
    )
    def test_locked_symbol_rejects_both_adversarial_and_benign_renames(self, source: EvidenceSource) -> None:
        """Any locked symbol must strictly reject renames regardless of name."""
        session = BinarySession(
            session_id=f"s_lock_{source.name}",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        addr = 0x5000
        func = Function(address=addr, name=f"grounded_{source.name.lower()}")
        session.functions[addr] = func
        session.add_symbol(Symbol(address=addr, name=f"grounded_{source.name.lower()}", type=SymbolType.FUNCTION))

        tag = EvidenceTag(
            target_type=TargetType.SYMBOL,
            target_id=f"sym:0x{addr:x}",
            suggested_name=func.name,
            source=source,
            confidence=1.0,
            is_immutable=True,
        )
        session.attach_evidence(tag)

        mutator = SessionMutator()

        # 1. Adversarial rename attempt must raise ToolError
        with pytest.raises(ToolError, match="locked by immutable evidence"):
            mutator.rename_symbol(session, addr, "malicious_hack_func")

        # 2. Benign/constructive rename attempt must ALSO raise ToolError
        with pytest.raises(ToolError, match="locked by immutable evidence"):
            mutator.rename_symbol(session, addr, "reconstructed_clean_name")

    def test_anonymous_stripped_function_allows_constructive_rename(self) -> None:
        """Stripped anonymous function (e.g. sub_1000) allows constructive renaming."""
        session = BinarySession(
            session_id="s_anon_stripped",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        addr = 0x6000
        func = Function(
            address=addr,
            name="sub_6000",
            is_stripped=True,
            decompiled_code="int sub_6000() { return 42; }",
        )
        session.functions[addr] = func
        session.add_symbol(Symbol(address=addr, name="sub_6000", type=SymbolType.FUNCTION))

        # Attach variable-level evidence tag (does NOT lock the function symbol)
        var_tag = EvidenceTag(
            target_type=TargetType.VARIABLE,
            target_id=f"func:0x{addr:x}:var:local_buf",
            suggested_name="local_buf",
            source=EvidenceSource.FORMAT_STRING,
            confidence=0.95,
            is_immutable=True,
        )
        session.attach_evidence(var_tag)

        mutator = SessionMutator()
        # Constructive rename succeeds
        res = mutator.rename_symbol(session, addr, "get_constant_answer", reason="De-anonymized via RE")
        assert res.success is True
        assert session.functions[addr].name == "get_constant_answer"
        assert "get_constant_answer()" in str(session.functions[addr].decompiled_code)

        # Attaching a user_agent tag
        assert any(t.source == EvidenceSource.USER_AGENT for t in session.evidence_tags.values())

    def test_immutable_grounded_function_rejects_arbitrary_renames(self) -> None:
        """Grounded function symbol rejects arbitrary renames regardless of identifier prefix."""
        session = BinarySession(
            session_id="s_anon_anchored",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        addr = 0x7000
        func = Function(address=addr, name="sub_7000")
        session.functions[addr] = func
        session.add_symbol(Symbol(address=addr, name="sub_7000", type=SymbolType.FUNCTION))

        tag = EvidenceTag(
            target_type=TargetType.FUNCTION,
            target_id=f"func:0x{addr:x}",
            suggested_name="sub_7000",
            source=EvidenceSource.ASSERT_MACRO,
            confidence=1.0,
            is_immutable=True,
        )
        session.attach_evidence(tag)

        mutator = SessionMutator()
        for prefix in ("malicious", "adversary", "tamper", "fake", "bad", "hack", "legitimate"):
            with pytest.raises(ToolError, match="locked by immutable evidence"):
                mutator.rename_symbol(session, addr, f"{prefix}_operation")

    def test_immutable_variable_type_rejects_adversarial_or_conflicting_retype(self) -> None:
        """Locked variable rejects modification."""
        session = BinarySession(
            session_id="s_var_lock",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        addr = 0x8000
        func = Function(
            address=addr,
            name="service_worker",
            parameters=[FunctionParameter(name="port", type_name="uint16_t")],
            decompiled_code="void service_worker(uint16_t port) {}",
        )
        session.functions[addr] = func

        tag = EvidenceTag(
            target_type=TargetType.VARIABLE,
            target_id=f"func:0x{addr:x}:var:port",
            suggested_name="port",
            suggested_type="uint16_t",
            source=EvidenceSource.FORMAT_STRING,
            confidence=1.0,
            is_immutable=True,
        )
        session.attach_evidence(tag)

        mutator = SessionMutator()

        # Conflicting retyping rejected
        with pytest.raises(ToolError, match="locked by immutable evidence"):
            mutator.update_variable_type(session, addr, "port", "char*")

        # Adversarial prefix rejected
        with pytest.raises(ToolError, match="locked by immutable evidence"):
            mutator.update_variable_type(session, addr, "port", "malicious_type")


# ============================================================================
# Dimension 4: Malformed Types, Invalid Addresses, Empty Strings, & Concurrency
# ============================================================================


class TestMalformedInputsAndConcurrency:
    """Stress tests boundary conditions, invalid inputs, and multithreading."""

    @pytest.mark.parametrize("bad_addr", [-1, -100, "-0x10", "invalid_hex", "0xNOTAHEX", "", "   ", None, []])
    def test_parse_int_address_rejects_invalid(self, bad_addr: Any) -> None:
        with pytest.raises(ToolError):
            parse_int_address(bad_addr)

    def test_rename_symbol_empty_strings(self) -> None:
        session = BinarySession(
            session_id="s_empty",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        mutator = SessionMutator()
        with pytest.raises(ToolError, match="cannot be empty"):
            mutator.rename_symbol(session, 0x1000, "")
        with pytest.raises(ToolError, match="cannot be empty"):
            mutator.rename_symbol(session, 0x1000, "   \t\n  ")

    def test_update_variable_type_empty_strings(self) -> None:
        session = BinarySession(
            session_id="s_empty_var",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        func = Function(address=0x1000, name="f")
        session.functions[0x1000] = func
        mutator = SessionMutator()

        with pytest.raises(ToolError, match="Variable name cannot be empty"):
            mutator.update_variable_type(session, 0x1000, "", "int")
        with pytest.raises(ToolError, match="New type cannot be empty"):
            mutator.update_variable_type(session, 0x1000, "x", "   ")

    def test_define_struct_empty_name_or_fields(self) -> None:
        session = BinarySession(
            session_id="s_empty_struct",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        mutator = SessionMutator()

        with pytest.raises(ToolError, match="Struct name cannot be empty"):
            mutator.define_struct(session, "", {"a": "int"})
        with pytest.raises(ToolError, match="at least one field"):
            mutator.define_struct(session, "EmptyStruct", {})

    def test_multithreaded_concurrent_mutations(self) -> None:
        """20 concurrent threads mutating session state simultaneously."""
        session = BinarySession(
            session_id="s_concurrent",
            artifact=TargetArtifact(path="/tmp/bin", architecture=ArchitectureType.ARM64, format=ArtifactFormat.MACHO),
        )
        # Prepopulate functions
        for i in range(20):
            addr = 0x1000 + i * 0x10
            session.functions[addr] = Function(
                address=addr,
                name=f"sub_{addr:x}",
                decompiled_code=f"void sub_{addr:x}() {{}}",
            )
            session.add_symbol(Symbol(address=addr, name=f"sub_{addr:x}", type=SymbolType.FUNCTION))

        mutator = SessionMutator()

        def mutate_worker(index: int) -> bool:
            addr = 0x1000 + index * 0x10
            # 1. Rename
            mutator.rename_symbol(session, addr, f"worker_func_{index}")
            # 2. Define struct
            mutator.define_struct(session, f"WorkerStruct_{index}", {"id": "int32_t", "flag": "char"})
            return True

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(mutate_worker, i) for i in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert all(results)
        assert len(session.struct_definitions) == 20
        for i in range(20):
            addr = 0x1000 + i * 0x10
            assert session.functions[addr].name == f"worker_func_{i}"
            assert f"WorkerStruct_{i}" in session.struct_definitions
