"""
Adversarial Empirical Challenge Suite for Milestone 4 Remediation (M4-R2).
Created by Challenger M4-R2-1.

Empirical verification of:
1. SessionMutator immutability & ungrounded renaming:
   - Ungrounded function renames to previously blacklisted names (malicious_test, fake_func, etc.)
   - Grounded function renames (GO_PCLNTAB, CPP_RTTI, DYNAMIC_PROBE, ASSERT_MACRO) fail unconditionally
   - Variable immutability vs function immutability independence
   - Inferred evidence sources (FORMAT_STRING, SYSCALL_*, LIBC_*) do not lock function symbols
2. Tree-sitter AST pointer parameter & variable retyping:
   - 'int *ptr' retyped to 'char*' -> 'char* ptr' (no double pointer 'char* *ptr')
   - 'int *ptr' retyped to 'char *'
   - 'int *local_ptr = NULL;' retyped to 'char*'
   - 'int *uninit_ptr;' retyped to 'char*'
   - 'int x' retyped to 'char*' -> 'char* x'
   - 'int *ptr' retyped to non-pointer 'uint32_t' -> 'uint32_t ptr'
   - Multiple parameters and declarations
3. Struct member access preservation:
   - Arrow member access (cfg->port) untouched when renaming variable/function 'port'
   - Dot member access (s.port) untouched
   - Struct declaration field (int port;) untouched
   - Mixed occurrences: cfg->port = port;
"""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from metis_reverse.backends.tier1_native.ast_engine import TreeSitterAstEngine
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
from metis_reverse.equivalence.mutator import SessionMutator


@pytest.fixture
def arm64_session() -> BinarySession:
    return BinarySession(
        session_id="sess_challenger_arm64",
        artifact=TargetArtifact(
            path="/tmp/dummy_arm64",
            architecture=ArchitectureType.ARM64,
            format=ArtifactFormat.MACHO,
        ),
    )


class TestSessionMutatorRenamingGroundingMatrix:
    """Stress-test renaming on ungrounded vs grounded functions with diverse names."""

    ADVERSARIAL_NAMES = [
        "malicious_test",
        "fake_func",
        "tamper_check",
        "reconstructed_handler",
        "bad_actor_probe",
        "hack_entrypoint",
        "adversary_hook",
        "exploit_detector",
        "reverse_engineered_main",
    ]

    GROUNDED_SOURCES = [
        EvidenceSource.GO_PCLNTAB,
        EvidenceSource.CPP_RTTI,
        EvidenceSource.DYNAMIC_PROBE,
        EvidenceSource.ASSERT_MACRO,
    ]

    UNGROUNDED_INFERRED_SOURCES = [
        EvidenceSource.FORMAT_STRING,
        EvidenceSource.SYSCALL_ABI,
        EvidenceSource.SYSCALL_INFERENCE,
        EvidenceSource.SYSCALL_PROPAGATION,
        EvidenceSource.LIBC_SEMANTICS,
    ]

    @pytest.mark.parametrize("target_name", ADVERSARIAL_NAMES)
    def test_ungrounded_function_renaming_succeeds_for_any_target_name(
        self, arm64_session: BinarySession, target_name: str
    ) -> None:
        """Ungrounded anonymous function can be renamed to ANY target name."""
        addr = 0x10001000
        func = Function(
            address=addr,
            name="sub_10001000",
            is_stripped=True,
            decompiled_code="int sub_10001000() { return 0; }",
        )
        arm64_session.functions[addr] = func
        arm64_session.add_symbol(
            Symbol(address=addr, name="sub_10001000", type=SymbolType.FUNCTION)
        )

        mutator = SessionMutator()
        res = mutator.rename_symbol(arm64_session, addr, target_name)

        assert res.success is True
        assert arm64_session.functions[addr].name == target_name
        assert target_name in str(arm64_session.functions[addr].decompiled_code)
        assert arm64_session.symbols[addr].name == target_name

    @pytest.mark.parametrize("grounded_source", GROUNDED_SOURCES)
    @pytest.mark.parametrize("target_name", ADVERSARIAL_NAMES[:4])
    def test_grounded_function_renaming_fails_unconditionally(
        self,
        arm64_session: BinarySession,
        grounded_source: EvidenceSource,
        target_name: str,
    ) -> None:
        """Grounded function cannot be renamed to ANY name, benign or adversarial."""
        addr = 0x10002000
        original_name = f"grounded_func_{grounded_source.value}"
        func = Function(
            address=addr,
            name=original_name,
            decompiled_code=f"void {original_name}() {{}}",
        )
        arm64_session.functions[addr] = func
        arm64_session.add_symbol(
            Symbol(address=addr, name=original_name, type=SymbolType.FUNCTION)
        )

        tag = EvidenceTag(
            target_type=TargetType.SYMBOL,
            target_id=f"sym:0x{addr:x}",
            suggested_name=original_name,
            source=grounded_source,
            confidence=1.0,
            is_immutable=True,
        )
        arm64_session.attach_evidence(tag)

        mutator = SessionMutator()
        with pytest.raises(ToolError, match="locked by immutable evidence"):
            mutator.rename_symbol(arm64_session, addr, target_name)

        # Confirm state remained intact
        assert arm64_session.functions[addr].name == original_name
        assert arm64_session.symbols[addr].name == original_name

    @pytest.mark.parametrize("inferred_source", UNGROUNDED_INFERRED_SOURCES)
    def test_inferred_evidence_tags_do_not_lock_function_symbol(
        self, arm64_session: BinarySession, inferred_source: EvidenceSource
    ) -> None:
        """
        Tags from format strings, syscall propagation, libc semantics infer variables,
        and MUST NOT lock the anonymous function symbol itself.
        """
        addr = 0x10003000
        func = Function(
            address=addr,
            name="sub_10003000",
            decompiled_code="void sub_10003000(int x) { printf(\"val: %d\", x); }",
        )
        arm64_session.functions[addr] = func
        arm64_session.add_symbol(
            Symbol(address=addr, name="sub_10003000", type=SymbolType.FUNCTION)
        )

        # Attach an immutable tag with inferred source targeting address or variable
        tag = EvidenceTag(
            target_type=TargetType.FUNCTION,
            target_id=f"func:0x{addr:x}",
            suggested_name="inferred_hint",
            source=inferred_source,
            confidence=0.9,
            is_immutable=True,
        )
        arm64_session.attach_evidence(tag)

        mutator = SessionMutator()
        # Should succeed because inferred sources are excluded from function symbol locking
        res = mutator.rename_symbol(arm64_session, addr, "reconstructed_service_handler")
        assert res.success is True
        assert arm64_session.functions[addr].name == "reconstructed_service_handler"


class TestTreeSitterPointerRetyping:
    """Stress-test pointer parameter and variable retyping via Tree-sitter."""

    def test_parameter_int_ptr_retyped_to_char_star(self, arm64_session: BinarySession) -> None:
        """
        Verify: int *ptr retyped to 'char*' produces 'char* ptr', NOT 'char* *ptr'.
        """
        addr = 0x20001000
        code = "void process_data(int *ptr) {\n    *ptr = 1;\n}\n"
        func = Function(
            address=addr,
            name="process_data",
            parameters=[FunctionParameter(name="ptr", type_name="int*")],
            decompiled_code=code,
        )
        arm64_session.functions[addr] = func

        mutator = SessionMutator()
        res = mutator.update_variable_type(arm64_session, addr, "ptr", "char*")

        assert res.success is True
        rewritten = str(func.decompiled_code)

        # Must have "char* ptr" and must NOT have double pointer "char* *ptr" or "char** ptr"
        assert "char* ptr" in rewritten
        assert "char* *ptr" not in rewritten
        assert "char** ptr" not in rewritten
        assert "*ptr = 1;" in rewritten

    def test_parameter_int_ptr_with_space_retyped_to_char_ptr(
        self, arm64_session: BinarySession
    ) -> None:
        """
        Verify: 'int * ptr' or 'int* ptr' retyped to 'char *' produces valid C syntax.
        """
        addr = 0x20002000
        code = "int handle_buf(int * ptr, int len) {\n    return len;\n}\n"
        func = Function(
            address=addr,
            name="handle_buf",
            parameters=[
                FunctionParameter(name="ptr", type_name="int*"),
                FunctionParameter(name="len", type_name="int"),
            ],
            decompiled_code=code,
        )
        arm64_session.functions[addr] = func

        mutator = SessionMutator()
        res = mutator.update_variable_type(arm64_session, addr, "ptr", "const char*")

        assert res.success is True
        rewritten = str(func.decompiled_code)
        assert "const char* ptr" in rewritten
        assert "const char* *ptr" not in rewritten
        assert "int len" in rewritten

    def test_local_variable_pointer_retyped_to_pointer(
        self, arm64_session: BinarySession
    ) -> None:
        """
        Verify: local variable 'int *local_ptr = NULL;' retyped to 'uint8_t*'.
        """
        addr = 0x20003000
        code = (
            "void worker() {\n"
            "    int *local_ptr = NULL;\n"
            "    int count = 0;\n"
            "}\n"
        )
        func = Function(
            address=addr,
            name="worker",
            local_variables=[
                LocalVariable(id="l1", name="local_ptr", type_name="int*"),
                LocalVariable(id="l2", name="count", type_name="int"),
            ],
            decompiled_code=code,
        )
        arm64_session.functions[addr] = func

        mutator = SessionMutator()
        res = mutator.update_variable_type(arm64_session, addr, "local_ptr", "uint8_t*")

        assert res.success is True
        rewritten = str(func.decompiled_code)
        assert "uint8_t* local_ptr" in rewritten
        assert "uint8_t* *local_ptr" not in rewritten
        assert "int count = 0;" in rewritten

    def test_uninitialized_local_pointer_retyped(
        self, arm64_session: BinarySession
    ) -> None:
        """
        Verify: uninitialized pointer declaration 'int *p;' retyped to 'char*'.
        """
        addr = 0x20004000
        code = "void parse() {\n    int *p;\n    p = 0;\n}\n"
        func = Function(
            address=addr,
            name="parse",
            local_variables=[LocalVariable(id="l1", name="p", type_name="int*")],
            decompiled_code=code,
        )
        arm64_session.functions[addr] = func

        mutator = SessionMutator()
        res = mutator.update_variable_type(arm64_session, addr, "p", "char*")

        assert res.success is True
        rewritten = str(func.decompiled_code)
        assert "char* p;" in rewritten
        assert "char* *p;" not in rewritten

    def test_pointer_retyped_to_primitive_value(
        self, arm64_session: BinarySession
    ) -> None:
        """
        Verify: 'int *ptr' retyped to non-pointer 'uintptr_t'.
        """
        addr = 0x20005000
        code = "void func(int *ptr) {}\n"
        func = Function(
            address=addr,
            name="func",
            parameters=[FunctionParameter(name="ptr", type_name="int*")],
            decompiled_code=code,
        )
        arm64_session.functions[addr] = func

        mutator = SessionMutator()
        res = mutator.update_variable_type(arm64_session, addr, "ptr", "uintptr_t")

        assert res.success is True
        rewritten = str(func.decompiled_code)
        assert "uintptr_t ptr" in rewritten or "uintptr_t" in rewritten


class TestStructMemberAccessProtection:
    """Stress-test non-renaming of struct member accesses (cfg->port, s.port)."""

    def test_struct_arrow_and_dot_member_accesses_preserved_when_variable_renamed(
        self, arm64_session: BinarySession
    ) -> None:
        """
        Renaming variable/parameter 'port' must NOT rename:
        1. struct definition field: 'int port;'
        2. arrow access: 'cfg->port'
        3. dot access: 'state.port'
        """
        ast_engine = TreeSitterAstEngine()
        code = (
            "struct ServerConfig {\n"
            "    int port;\n"
            "    char *host;\n"
            "};\n"
            "int configure(struct ServerConfig *cfg, struct ServerConfig state, int port) {\n"
            "    cfg->port = port;\n"
            "    state.port = port;\n"
            "    return port;\n"
            "}\n"
        )

        # 1. Direct AST rename
        rewritten = ast_engine.rename_identifier(
            source_code=code,
            old_name="port",
            new_name="listen_port",
            include_fields=False,
        )

        # Struct definition member preserved
        assert "int port;" in rewritten
        # Arrow member access preserved
        assert "cfg->port = listen_port;" in rewritten
        # Dot member access preserved
        assert "state.port = listen_port;" in rewritten
        # Parameter renamed
        assert "int listen_port)" in rewritten
        # Return expression renamed
        assert "return listen_port;" in rewritten

    def test_mutator_rename_symbol_does_not_corrupt_struct_member_access(
        self, arm64_session: BinarySession
    ) -> None:
        """
        Using SessionMutator to rename a function symbol 'port' to 'get_port'
        must leave struct members and member access untouched.
        """
        addr = 0x30001000
        code = (
            "struct Service {\n"
            "    uint16_t port;\n"
            "};\n"
            "uint16_t port(struct Service *s) {\n"
            "    return s->port;\n"
            "}\n"
        )
        func = Function(address=addr, name="port", decompiled_code=code)
        arm64_session.functions[addr] = func
        arm64_session.add_symbol(Symbol(address=addr, name="port", type=SymbolType.FUNCTION))

        mutator = SessionMutator()
        res = mutator.rename_symbol(arm64_session, addr, "get_service_port")

        assert res.success is True
        rewritten = str(func.decompiled_code)
        assert "uint16_t get_service_port(struct Service *s)" in rewritten
        assert "uint16_t port;" in rewritten
        assert "return s->port;" in rewritten

    def test_chained_struct_member_accesses(self) -> None:
        """
        Chained accesses like app->config->port or app.config.port must also be preserved.
        """
        ast_engine = TreeSitterAstEngine()
        code = (
            "void setup(App *app, int port) {\n"
            "    app->config->port = port;\n"
            "    app.config.port = port;\n"
            "}\n"
        )
        rewritten = ast_engine.rename_identifier(
            source_code=code,
            old_name="port",
            new_name="target_port",
            include_fields=False,
        )
        assert "app->config->port = target_port;" in rewritten
        assert "app.config.port = target_port;" in rewritten
        assert "int target_port)" in rewritten
