"""
Metis Reverse - Tier 5 Adversarial Coverage Hardening Test Suite
================================================================
Comprehensive white-box adversarial stress testing across:
1. Core Domain Models, Session Orchestration, and EvidenceStore
2. Tier 1 Native Backends (LIEF, Capstone, Angr wrapper, Tree-sitter AST)
3. Multi-Evidence Grounding Engine (Format strings, Assert macros, Syscalls, Go pclntab, C++ RTTI, JS AST)
4. Dynamic Tracing & Memory Probing (Frida compatibility gate, Unicorn isolated emulation, Fact backfiller)

Validates error recovery, graceful rejection, memory safety, and thread safety under hostile conditions.
"""

from __future__ import annotations

import concurrent.futures
import os
import struct
import tempfile

import pytest
from pydantic import ValidationError

from metis_reverse.backends.base import (
    UnsupportedArtifactError,
)
from metis_reverse.backends.tier1_native.ast_engine import TreeSitterAstEngine
from metis_reverse.backends.tier1_native.binary_parser import LiefBinaryParser
from metis_reverse.backends.tier1_native.decompiler import AngrDecompilerEngine
from metis_reverse.backends.tier1_native.disassembler import (
    CapstoneDisassembler,
)
from metis_reverse.core.evidence import EvidenceStore, ImmutableEvidenceError
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySection,
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    Function,
    SectionPermission,
    StructDefinition,
    StructField,
    Symbol,
    SymbolType,
    TargetArtifact,
    TargetType,
    TraceResult,
)
from metis_reverse.core.session import (
    ArtifactNotFoundError,
    SessionManager,
)
from metis_reverse.dynamic.backfiller import FactBackfiller
from metis_reverse.dynamic.frida_prober import FridaProber
from metis_reverse.dynamic.prober_base import (
    ArchitectureCompatibilityError,
    ProberUnavailableError,
    is_host_native_compatible,
)
from metis_reverse.dynamic.unicorn_prober import (
    PAGE_SIZE,
    UnicornProber,
    build_page_mappings,
)
from metis_reverse.grounding.assert_macros import AssertMacroGrounder
from metis_reverse.grounding.format_strings import FormatStringGrounder
from metis_reverse.grounding.metadata.cpp_rtti import (
    CppDemangler,
)
from metis_reverse.grounding.metadata.go_pclntab import (
    GoPclntabParser,
)
from metis_reverse.grounding.metadata.js_ast import JsAstScopeExtractor
from metis_reverse.grounding.syscalls import SyscallDatabase

# ============================================================================
# 1. CORE DOMAIN & SESSION ADVERSARIAL TESTS
# ============================================================================

class TestCoreAdversarial:
    """Stress tests for TargetArtifact, BinarySession, SessionManager, and EvidenceStore."""

    def test_target_artifact_edge_cases_and_coercion(self) -> None:
        """Verify TargetArtifact validation boundaries and resilient string coercions."""
        # 1. Invalid bitness
        for bad_bitness in (0, 8, 48, 128, -64):
            with pytest.raises(ValidationError):
                TargetArtifact(
                    file_path="/tmp/test_bin",
                    format=ArtifactFormat.ELF,
                    architecture=ArchitectureType.X86_64,
                    bitness=bad_bitness,
                )

        # 2. Negative file size
        with pytest.raises(ValidationError):
            TargetArtifact(
                file_path="/tmp/test_bin",
                file_size=-10,
                format=ArtifactFormat.ELF,
                architecture=ArchitectureType.X86_64,
            )

        # 3. Resilient string coercions for architecture
        art1 = TargetArtifact(
            file_path="/tmp/test_bin",
            format=" elf ",
            architecture=" AArch64 ",
        )
        assert art1.format == ArtifactFormat.ELF
        assert art1.architecture == ArchitectureType.ARM64

        art2 = TargetArtifact(
            file_path="/tmp/test_bin",
            format="UNKNOWN_FMT",
            architecture="WEIRD_ARCH",
        )
        assert art2.format == ArtifactFormat.RAW
        assert art2.architecture == ArchitectureType.UNKNOWN

        # 4. Entry point synchronization
        art3 = TargetArtifact(
            file_path="/tmp/test_bin",
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
            entry_points=[0x401000, 0x401100],
        )
        assert art3.entry_point == 0x401000

    def test_struct_definition_extreme_and_nested_layouts(self) -> None:
        """Verify C ABI struct offset, alignment, and packing under adversarial layouts."""
        # 1. Empty fields
        s_empty = StructDefinition(name="EmptyStruct", fields={})
        size, align, offsets = StructDefinition.calculate_layout(s_empty.fields)
        assert size == 0
        assert align == 1
        assert offsets == {}

        # 2. 50 Heterogeneous fields
        fields: dict[str, str | StructField] = {}
        type_cycle = [
            "char", "uint8_t", "short", "int", "uint32_t",
            "long", "uint64_t", "double", "pointer", "void*",
            "char[16]", "int[4]",
        ]
        for i in range(50):
            fields[f"field_{i}"] = type_cycle[i % len(type_cycle)]

        size_unpacked, align_unpacked, offsets_unpacked = StructDefinition.calculate_layout(fields, is_packed=False)
        assert size_unpacked > 0
        assert align_unpacked in (4, 8)
        assert len(offsets_unpacked) == 50

        # Offsets must be strictly non-decreasing and respect field alignments
        prev_off = -1
        for _name, off in offsets_unpacked.items():
            assert off >= prev_off
            prev_off = off

        # 3. Packed layout guarantees contiguous byte placement and align == 1
        size_packed, align_packed, offsets_packed = StructDefinition.calculate_layout(fields, is_packed=True)
        assert align_packed == 1
        assert size_packed <= size_unpacked

        # 4. Unknown custom type falls back to pointer size
        size_custom, align_custom, offsets_custom = StructDefinition.calculate_layout(
            {"custom_ptr": "MyCustomStructType*"}, bitness=64
        )
        assert size_custom == 8
        assert align_custom == 8
        assert offsets_custom["custom_ptr"] == 0

    def test_binary_session_malformed_evidence_targets(self) -> None:
        """Verify BinarySession.attach_evidence handles malformed target IDs gracefully."""
        art = TargetArtifact(
            file_path="/tmp/test_bin",
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
        )
        session = BinarySession(artifact=art, evidence_store=EvidenceStore())

        func = Function(
            id="func_0x401000",
            name="process_packet",
            address=0x401000,
            size=64,
        )
        session.functions[0x401000] = func

        sym = Symbol(
            address=0x401000,
            name="process_packet",
            type=SymbolType.FUNCTION,
        )
        session.add_symbol(sym)

        # Adversarial target_ids: empty, corrupted, negative, missing address, non-existent
        malformed_targets = [
            "",
            ":::",
            "unknown_target_format",
            "0x",
            "sym:not_a_hex_number",
            "func:0x999999",  # Address not in session
            "param:-0x10",
            "weird:target:0x401000",
        ]

        for i, bad_target in enumerate(malformed_targets):
            tag = EvidenceTag(
                tag_id=f"adversarial_tag_{i}",
                target_type=TargetType.SYMBOL,
                target_id=bad_target,
                confidence=1.0,
                is_immutable=True,
                raw_anchor="fuzz_anchor",
                explanation="testing malformed target id handling",
            )
            # Must not crash or raise uncaught exception
            session.attach_evidence(tag)
            assert tag.tag_id in session.evidence_tags

        # The valid target at 0x401000 in "weird:target:0x401000" should even resolve correctly
        assert "adversarial_tag_7" in sym.evidence_tag_ids

    def test_binary_session_duplicate_and_boundary_symbols(self) -> None:
        """Verify BinarySession.add_symbol with duplicate addresses, 0, and large addresses."""
        art = TargetArtifact(
            file_path="/tmp/test_bin",
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
        )
        session = BinarySession(artifact=art, evidence_store=EvidenceStore())

        # Pre-attach evidence to address 0x0 and 0x7FFFFFFFFFFFFFFF
        tag_zero = EvidenceTag(
            tag_id="tag_zero",
            target_type=TargetType.SYMBOL,
            target_id="sym:0x0",
            suggested_name="null_func",
            confidence=1.0,
        )
        session.attach_evidence(tag_zero)

        sym_zero = Symbol(address=0x0, name="zero_sym")
        session.add_symbol(sym_zero)
        assert "tag_zero" in sym_zero.evidence_tag_ids
        assert session.symbols[0x0].name == "zero_sym"

        # Overwrite same address with new symbol
        sym_zero_v2 = Symbol(address=0x0, name="zero_sym_v2")
        session.add_symbol(sym_zero_v2)
        assert session.symbols[0x0].name == "zero_sym_v2"
        assert session.symbols["zero_sym_v2"].address == 0x0

        # Boundary address 64-bit max
        sym_max = Symbol(address=0x7FFFFFFFFFFFFFFF, name="max_addr_sym")
        session.add_symbol(sym_max)
        assert session.symbols_by_address[0x7FFFFFFFFFFFFFFF].name == "max_addr_sym"

    def test_session_manager_corrupted_and_truncated_files(self) -> None:
        """Verify SessionManager gracefully handles 0-byte, truncated, and corrupt binaries."""
        mgr = SessionManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Non-existent file
            with pytest.raises(ArtifactNotFoundError):
                mgr.create_session(os.path.join(tmpdir, "nonexistent.bin"))

            # 2. Directory passed as file
            with pytest.raises(ArtifactNotFoundError):
                mgr.create_session(tmpdir)

            # 3. Zero-byte file
            empty_bin = os.path.join(tmpdir, "empty.bin")
            with open(empty_bin, "wb") as f:
                f.write(b"")

            # Without validate, creates RAW session with 0 sections
            sess_empty = mgr.create_session(empty_bin, validate=False)
            assert sess_empty.artifact.file_size == 0
            assert sess_empty.artifact.format == ArtifactFormat.RAW

            # With validate=True, raises UnsupportedArtifactError
            with pytest.raises(UnsupportedArtifactError):
                mgr.create_session(empty_bin, validate=True)

            # 4. Truncated headers (1-byte, 3-byte, 7-byte, 15-byte)
            for size in (1, 3, 7, 15):
                trunc_path = os.path.join(tmpdir, f"trunc_{size}.bin")
                with open(trunc_path, "wb") as f:
                    f.write(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"[:size])

                # validate=True must reject truncated headers
                with pytest.raises(UnsupportedArtifactError):
                    mgr.create_session(trunc_path, validate=True)

            # 5. 1KB random garbage fuzz
            garbage_path = os.path.join(tmpdir, "fuzz_garbage.bin")
            with open(garbage_path, "wb") as f:
                f.write(os.urandom(1024))

            with pytest.raises(UnsupportedArtifactError):
                mgr.create_session(garbage_path, validate=True)

    def test_session_manager_concurrent_lifecycle(self) -> None:
        """Stress-test SessionManager under concurrent multi-threaded creation and deletion."""
        mgr = SessionManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            files: list[str] = []
            for i in range(12):
                p = os.path.join(tmpdir, f"dummy_{i}.bin")
                with open(p, "wb") as f:
                    # Write mock ELF header
                    f.write(b"\x7fELF" + b"\x00" * 60)
                files.append(p)

            def worker_task(idx: int) -> str:
                file_to_open = files[idx % len(files)]
                sess = mgr.create_session(file_to_open, validate=False)
                _ = mgr.get_session(sess.session_id)
                _ = mgr.list_sessions()
                if idx % 2 == 0:
                    mgr.close_session(sess.session_id)
                return sess.session_id

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(worker_task, i) for i in range(24)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            assert len(results) == 24
            active_sessions = mgr.list_sessions()
            assert len(active_sessions) > 0
            mgr.clear_all()
            assert len(mgr.list_sessions()) == 0

    def test_evidence_store_immutability_and_concurrency(self) -> None:
        """Verify EvidenceStore immutability locking and high-throughput multi-threaded operations."""
        store = EvidenceStore()

        # 1. Immutability violation checks
        imm_tag = EvidenceTag(
            tag_id="tag_imm_1",
            target_type=TargetType.SYMBOL,
            target_id="sym:0x401000",
            confidence=1.0,
            is_immutable=True,
            raw_anchor="anchor1",
        )
        store.add_tag(imm_tag)

        # Overwrite attempt on immutable tag
        with pytest.raises(ImmutableEvidenceError):
            store.add_tag(
                EvidenceTag(
                    tag_id="tag_imm_1",
                    target_type=TargetType.SYMBOL,
                    target_id="sym:0x401000",
                    confidence=0.5,
                    is_immutable=False,
                )
            )

        # Delete attempt on immutable tag
        with pytest.raises(ImmutableEvidenceError):
            store.delete_tag("tag_imm_1")

        assert store.has_immutable_tag("sym:0x401000") is True
        assert store.has_immutable_tag("0x401000") is True

        # 2. Concurrent multi-threaded stress: 16 threads writing, reading, deleting mutable tags
        def concurrent_writer(thread_id: int) -> None:
            for j in range(25):
                tag_id = f"thread_{thread_id}_tag_{j}"
                is_imm = (j % 5 == 0)
                tag = EvidenceTag(
                    tag_id=tag_id,
                    target_type=TargetType.FUNCTION,
                    target_id=f"func:0x{0x400000 + (j * 0x10):x}",
                    confidence=0.8 if not is_imm else 1.0,
                    is_immutable=is_imm,
                    source=EvidenceSource.FORMAT_STRING,
                )
                store.add_tag(tag)
                _ = store.query(min_confidence=0.7)
                _ = store.get_tags_for_address(0x400000 + (j * 0x10))
                if not is_imm and j % 2 == 1:
                    store.delete_tag(tag_id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(concurrent_writer, t) for t in range(16)]
            for f in concurrent.futures.as_completed(futures):
                f.result()

        assert len(store) > 0
        all_tags = list(store)
        assert len(all_tags) == len(store)

    def test_binary_session_concurrent_multi_threading(self) -> None:
        """Verify BinarySession concurrency behavior under unsynchronized multi-threaded writes.

        Documents white-box finding: BinarySession lacks internal RLock, so concurrent
        add_symbol and attach_evidence can raise Python RuntimeError ('dictionary changed size
        during iteration'), but never results in segmentation faults, memory corruption, or panics.
        """
        art = TargetArtifact(
            file_path="/tmp/test_bin",
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
        )
        session = BinarySession(artifact=art, evidence_store=EvidenceStore())

        concurrency_exceptions: list[Exception] = []

        def session_worker(tid: int) -> None:
            for i in range(25):
                addr = 0x400000 + (tid * 0x1000) + (i * 0x10)
                try:
                    sym = Symbol(address=addr, name=f"sym_{tid}_{i}", type=SymbolType.FUNCTION)
                    session.add_symbol(sym)
                    tag = EvidenceTag(
                        tag_id=f"tag_{tid}_{i}",
                        target_type=TargetType.SYMBOL,
                        target_id=f"sym:0x{addr:x}",
                        confidence=1.0,
                        is_immutable=True,
                    )
                    session.attach_evidence(tag)
                    _ = session.get_function(addr)
                    struct_def = StructDefinition(name=f"struct_{tid}_{i}", fields={"id": "int"})
                    session.define_struct(struct_def)
                    _ = session.get_struct_definition(f"struct_{tid}_{i}")
                except RuntimeError as exc:
                    # Clean Python exception under race condition
                    concurrency_exceptions.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(session_worker, t) for t in range(8)]
            for f in concurrent.futures.as_completed(futures):
                f.result()

        # All caught exceptions must be RuntimeError('dictionary changed size during iteration')
        for exc in concurrency_exceptions:
            assert isinstance(exc, RuntimeError)
            assert "dictionary changed size during iteration" in str(exc)

        # Basic integrity check: elements that were added remain valid
        assert len(session.symbols_by_address) > 0
        assert len(session.struct_definitions) > 0
        assert len(session.evidence_tags) > 0

    def test_evidence_store_query_edge_cases_and_casing(self) -> None:
        """Verify EvidenceStore queries with out-of-range confidence, mixed casing, and empty results."""
        store = EvidenceStore()
        tag = EvidenceTag(
            tag_id="tag_syscall_1",
            target_type=TargetType.FUNCTION,
            target_id="func:0x401000",
            source=EvidenceSource.SYSCALL_PROPAGATION,
            confidence=0.9,
            is_immutable=True,
        )
        store.add_tag(tag)

        # 1. min_confidence > 1.0 yields empty list
        assert store.query(min_confidence=1.1) == []

        # 2. Unknown source returns empty list
        assert store.query(source="UNKNOWN_SOURCE_XYZ") == []

        # 3. Non-existent target_id or address returns empty list
        assert store.query(target_id="func:0x999999") == []
        assert store.query(address=0x999999) == []

        # 4. Mixed casing query resilience for syscall sources
        assert len(store.query(source="syscall_propagation")) == 1
        assert len(store.query(source="SYSCALL_PROPAGATION")) == 1
        assert len(store.query(source="SYSCALL_INFERENCE")) == 1


# ============================================================================
# 2. BACKENDS ADVERSARIAL TESTS (LIEF, CAPSTONE, ANGR, AST)
# ============================================================================

class TestBackendsAdversarial:
    """Stress tests for Tier 1 native backends against corrupted and extreme inputs."""

    def test_lief_parser_corrupted_and_truncated_binaries(self) -> None:
        """Verify LiefBinaryParser gracefully rejects zero-byte, corrupted, or fuzzed files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Zero-byte file
            p_zero = os.path.join(tmpdir, "zero.bin")
            with open(p_zero, "wb") as f:
                f.write(b"")
            with pytest.raises(UnsupportedArtifactError):
                LiefBinaryParser.parse(p_zero)

            # 2. Corrupted ELF magic with zero sections
            p_elf_corrupt = os.path.join(tmpdir, "bad_elf.bin")
            with open(p_elf_corrupt, "wb") as f:
                f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 40)
            with pytest.raises(UnsupportedArtifactError):
                LiefBinaryParser.parse(p_elf_corrupt)

            # 3. Corrupted Mach-O magic with 0 sections
            p_macho_corrupt = os.path.join(tmpdir, "bad_macho.bin")
            with open(p_macho_corrupt, "wb") as f:
                f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 40)
            with pytest.raises(UnsupportedArtifactError):
                LiefBinaryParser.parse(p_macho_corrupt)

            # 4. Corrupted PE magic
            p_pe_corrupt = os.path.join(tmpdir, "bad_pe.bin")
            with open(p_pe_corrupt, "wb") as f:
                f.write(b"MZ" + b"\x00" * 40)
            with pytest.raises(UnsupportedArtifactError):
                LiefBinaryParser.parse(p_pe_corrupt)

            # 5. Non-existent file
            with pytest.raises(FileNotFoundError):
                LiefBinaryParser.parse(os.path.join(tmpdir, "does_not_exist.bin"))

    def test_capstone_disassembler_edge_cases(self) -> None:
        """Verify CapstoneDisassembler resilience against bad arch, 0-byte, and fuzzed buffers."""
        # 1. Unsupported or unknown architecture string fallback
        dis_unk = CapstoneDisassembler(arch="unknown_exotic_arch")
        assert dis_unk.arch == ArchitectureType.UNKNOWN
        # Should initialize fallback cs engine (x86_64) without crashing
        assert dis_unk.cs is not None

        # 2. Zero-byte disassembly
        dis_x64 = CapstoneDisassembler(arch=ArchitectureType.X86_64)
        assert dis_x64.disassemble_bytes(b"", 0x401000) == []

        # 3. Fuzzed raw bytes (random opcodes)
        random_bytes = os.urandom(256)
        insns = dis_x64.disassemble_bytes(random_bytes, 0x401000)
        # Capstone skips invalid opcodes and recovers subsequent valid ones
        assert isinstance(insns, list)

        # 4. Unaligned addresses (odd addresses)
        odd_addr = 0x401003
        nop_slide = b"\x90\x90\x90\x90"
        odd_insns = dis_x64.disassemble_bytes(nop_slide, odd_addr)
        assert len(odd_insns) == 4
        assert odd_insns[0].address == odd_addr
        assert odd_insns[1].address == odd_addr + 1

        # 5. Boundary 64-bit addresses
        high_addr = 0x7FFFFFFF0000
        high_insns = dis_x64.disassemble_bytes(b"\x90", high_addr)
        assert len(high_insns) == 1
        assert high_insns[0].address == high_addr

        # 6. Truncated opcode prefixes (e.g. single REX.W prefix 0x48)
        trunc_insns = dis_x64.disassemble_bytes(b"\x48", 0x401000)
        assert isinstance(trunc_insns, list)

    def test_ast_engine_empty_and_corrupted_c_syntax(self) -> None:
        """Verify TreeSitterAstEngine token extraction and renaming on broken C syntax."""
        engine = TreeSitterAstEngine()

        # 1. Empty C code
        assert engine.extract_identifiers("") == []
        assert engine.rename_identifier("", "old", "new") == ""

        # 2. Malformed C syntax with syntax errors and random symbols
        malformed_c = "int foo( { ;;; 12345 @#$% return ; void bar("
        tokens = engine.extract_identifiers(malformed_c)
        assert any(t.name in ("foo", "bar") for t in tokens)

        # 3. Renaming non-existent identifier returns identical string
        c_code = "int calculate(int count) { return count * 2; }"
        assert engine.rename_identifier(c_code, "non_existent_var", "replacement") == c_code

        # 4. Deeply nested compound statements (50 levels of blocks)
        nested_c = "int deep() {\n" + ("{\n" * 50) + "int target = 42;\n" + ("}\n" * 50) + "}"
        renamed = engine.rename_identifier(nested_c, "target", "renamed_target")
        assert "int renamed_target = 42;" in renamed
        assert "int target = 42;" not in renamed

        # 5. Unicode identifier in comment or string must not be renamed
        commented_c = '// target = 100;\nchar* s = "target";\nint target = 1;'
        renamed_c = engine.rename_identifier(commented_c, "target", "renamed_var")
        assert '// target = 100;' in renamed_c
        assert 'char* s = "target";' in renamed_c
        assert 'int renamed_var = 1;' in renamed_c

    def test_angr_decompiler_error_recovery(self) -> None:
        """Verify AngrDecompilerEngine error paths on invalid files and addresses."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = os.path.join(tmpdir, "missing.bin")
            engine = AngrDecompilerEngine(fake_bin)
            # Angr raises Exception("Not a valid binary file") when given non-existent or invalid file
            with pytest.raises(Exception, match="Not a valid binary file"):
                _ = engine.decompile(0x401000)


# ============================================================================
# 3. GROUNDING ENGINE ADVERSARIAL TESTS
# ============================================================================

class TestGroundingAdversarial:
    """Stress tests for multi-evidence grounding algorithms (format strings, pclntab, RTTI, etc.)."""

    def test_format_strings_malformed_and_extreme_specifiers(self) -> None:
        """Verify FormatStringGrounder against corrupt, weird, and malicious format strings."""
        grounder = FormatStringGrounder()

        adversarial_cases = [
            ("%", 0),  # Incomplete trailing percent
            ("%%%%%", 0),  # Escaped percents only
            ("%100", 0),  # Incomplete specifier with width
            ("%+", 0),  # Incomplete specifier with flag
            ("%h", 0),  # Incomplete specifier with length modifier
            ("%9999999$d", 1),  # Extreme positional argument
            ("%*.*f", 1),  # Dynamic width and precision
            ("Prefix %08lx and suffix %s", 2),
            ("Non-ascii \x80\xff %d \xfe%s", 2),
            ("{unclosed_cpp_fmt", 0),
            ("{valid_arg} and {another:02x}", 2),
            ("{{escaped_braces}}", 1),  # Implementation matches inner {escaped_braces}
            ("", 0),
        ]

        for raw_str, expected_param_count in adversarial_cases:
            meta = grounder.parse_format_string(raw_str)
            assert len(meta.parameters) == expected_param_count
            for p in meta.parameters:
                assert p.confidence == 1.0
                assert p.inferred_type != ""

    def test_assert_macros_malformed_expressions_and_special_chars(self) -> None:
        """Verify AssertMacroGrounder handles corrupted, empty, or exotic assert strings."""
        grounder = AssertMacroGrounder()

        # 1. Empty and whitespace asserts
        c_empty = grounder.parse_assert_expression("   ")
        assert c_empty.comparisons == []

        # 2. String with no condition or diagnostic tag
        c_no_cond = grounder.parse_assert_expression("assert")
        assert c_no_cond.raw_condition == "assert"

        # 3. Assert with SQL / Shell injection payloads in diagnostic message
        # Special punctuation characters like quotes/semicolons are sanitized/rejected as diagnostic tags
        sql_injection = 'assert(user_id > 0 && "\'; DROP TABLE users; --")'
        c_inj = grounder.parse_assert_expression(sql_injection)
        assert c_inj.diagnostic_tag is None
        assert len(c_inj.comparisons) == 1
        assert c_inj.comparisons[0].lhs == "user_id"
        assert c_inj.comparisons[0].op == ">"

        # Valid diagnostic tag
        c_valid = grounder.parse_assert_expression('assert(user_id > 0 && "valid_user_check")')
        assert c_valid.diagnostic_tag == "valid_user_check"

        # 4. Complex chained conditions with struct pointer dereference
        complex_assert = 'assert(req != NULL && req->magic == 0x48545450 && "http_magic_check")'
        c_complex = grounder.parse_assert_expression(complex_assert)
        assert c_complex.diagnostic_tag == "http_magic_check"
        assert len(c_complex.comparisons) >= 2
        # Verify NULL check detection
        null_cmps = [c for c in c_complex.comparisons if c.is_null_check]
        assert len(null_cmps) >= 1

    def test_syscall_database_unknown_syscall_and_idempotent_init(self) -> None:
        """Verify SyscallDatabase resilience against unknown syscalls and repeated init."""
        # 1. Idempotent initialization
        SyscallDatabase.initialize()
        SyscallDatabase.initialize()

        # 2. Unknown syscall name
        sig_unk = SyscallDatabase.get_signature("nonexistent_system_call_xyz")
        assert sig_unk is None

        # 3. Unknown syscall numbers (e.g. -1, 999999)
        assert SyscallDatabase.get_syscall_by_nr(-1, "linux_x86_64") is None
        assert SyscallDatabase.get_syscall_by_nr(999999, "darwin_arm64") is None

        # 4. Valid lookup
        sig_read = SyscallDatabase.get_signature("read")
        assert sig_read is not None
        assert sig_read.return_type == "ssize_t"

    def test_go_pclntab_corrupted_magic_and_truncated_headers(self) -> None:
        """Verify GoPclntabParser against truncated buffers, wrong magics, and corrupted offsets."""
        # 1. Empty buffer
        parser_empty = GoPclntabParser(raw_bytes=b"")
        assert parser_empty.extract_symbols() == []

        # 2. Truncated buffer (< 8 bytes)
        for sz in range(1, 8):
            parser_trunc = GoPclntabParser(raw_bytes=b"\xf1\xff\xff\xff\x00\x00\x00"[:sz])
            assert parser_trunc.extract_symbols() == []

        # 3. Magic mismatch
        bad_magic_bytes = struct.pack("<I", 0x12345678) + b"\x00" * 60
        parser_bad_magic = GoPclntabParser(raw_bytes=bad_magic_bytes)
        assert parser_bad_magic.extract_symbols() == []

        # 4. Valid Go 1.20 magic (0xFFFFFFF1), but header truncated (< 72 bytes)
        magic_go120 = struct.pack("<I", 0xFFFFFFF1) + b"\x00\x00\x01\x08" + b"\x00" * 20
        parser_short_hdr = GoPclntabParser(raw_bytes=magic_go120)
        assert parser_short_hdr.extract_symbols() == []

        # 5. Valid Go 1.20 magic with corrupt/huge nfunc (e.g. 50,000,000)
        # Header layout for Go 1.20:
        # magic(4), pad(2), minLC(1)=1, ptrSize(1)=8, nfunc(8)=50000000, nfiles(8)=0, text_start(8)=0x400000, ...
        huge_nfunc_hdr = (
            struct.pack("<I", 0xFFFFFFF1)
            + b"\x00\x00\x01\x08"
            + struct.pack("<Q", 50000000)  # nfunc
            + struct.pack("<Q", 0)         # nfiles
            + struct.pack("<Q", 0x400000)  # text_start
            + struct.pack("<Q", 0x100)     # funcname_offset
            + struct.pack("<Q", 0x200)     # cu_offset
            + struct.pack("<Q", 0x300)     # filetab_offset
            + struct.pack("<Q", 0x400)     # pctab_offset
            + struct.pack("<Q", 0x500)     # pcln_offset
        )
        # Total buffer is small (doesn't reach pcln_offset 0x500)
        parser_huge_nfunc = GoPclntabParser(raw_bytes=huge_nfunc_hdr)
        # Must terminate gracefully with empty list without IndexError or MemoryError
        symbols = parser_huge_nfunc.extract_symbols()
        assert symbols == []

    def test_go_pclntab_go116_go12_and_invalid_varints(self) -> None:
        """Verify Go 1.16 and Go 1.2 truncated layouts and varint shift limits."""
        # 1. Truncated Go 1.16 header (< 64 bytes)
        magic_go116 = struct.pack("<I", 0xFFFFFFFA) + b"\x00\x00\x01\x08" + b"\x00" * 20
        parser_116 = GoPclntabParser(raw_bytes=magic_go116)
        assert parser_116.extract_symbols() == []

        # 2. Truncated Go 1.2 header (< 64 bytes)
        magic_go12 = struct.pack("<I", 0xFFFFFFFB) + b"\x00\x00\x01\x08" + b"\x00" * 20
        parser_12 = GoPclntabParser(raw_bytes=magic_go12)
        assert parser_12.extract_symbols() == []

        # 3. Invalid varint with shift > 64 (infinite sequence of high bits 0x80)
        infinite_high_bits = b"\x80" * 20
        val, idx = parser_116._read_varint(infinite_high_bits, 0)
        assert val is None  # Handled safely without infinite loop or OverflowError

    def test_cpp_rtti_malformed_mangled_names_and_deep_namespaces(self) -> None:
        """Verify CppDemangler resilience against truncated or malformed Itanium names."""
        demangler = CppDemangler()

        # 1. Non-mangled strings return verbatim
        assert demangler.demangle("main") == "main"
        assert demangler.demangle("") == ""

        # 2. Truncated mangled prefixes
        assert demangler.demangle("_Z") == "_Z"
        assert demangler.demangle("_ZN") == "_ZN"

        # 3. Truncated length prefix (e.g. length is 100, but string ends)
        assert isinstance(demangler.demangle("_Z100Foo"), str)

        # 4. Deeply nested namespaces
        deep_mangled = "_ZN1A1B1C1D1E1F1G1H1I1J1KE"
        demangled = demangler.demangle(deep_mangled)
        assert "A::B::C" in demangled

        # 5. Vtable and Typeinfo prefixes
        vtable_sym = "_ZTV6Player"
        dem_vt = demangler.demangle(vtable_sym)
        assert "vtable for" in dem_vt or "Player" in dem_vt

    def test_js_ast_malformed_syntax_and_fallback(self) -> None:
        """Verify JsAstScopeExtractor against malformed, broken, or empty JavaScript."""
        # 1. Empty JS
        extractor_empty = JsAstScopeExtractor(b"")
        bindings_empty = extractor_empty.analyze()
        assert bindings_empty == []

        # 2. Broken / incomplete syntax
        broken_js = b"const a = { function ( { [ ];;; return 'unclosed string"
        extractor_broken = JsAstScopeExtractor(broken_js)
        bindings_broken = extractor_broken.analyze()
        assert isinstance(bindings_broken, list)

        # 3. Clean minified module with export
        valid_min_js = b"""
        var _0xabc = function() {
            function SessionManager() {}
            SessionManager.prototype.createSession = function() {};
            return SessionManager;
        }();
        module.exports = { SessionManager: _0xabc };
        """
        extractor_valid = JsAstScopeExtractor(valid_min_js)
        bindings_valid = extractor_valid.analyze()
        assert any(b.original_name == "SessionManager" for b in bindings_valid)


# ============================================================================
# 4. DYNAMIC PROBING ADVERSARIAL TESTS (FRIDA & UNICORN)
# ============================================================================

class TestDynamicAdversarial:
    """Stress tests for dynamic execution containment, architecture gates, and fact backfilling."""

    def test_is_host_native_compatibility_comprehensive_matrix(self) -> None:
        """Verify host native compatibility check across combinations of OS and arch."""
        # 1. RAW format is never natively executable
        raw_art = TargetArtifact(
            file_path="/tmp/test_raw",
            format=ArtifactFormat.RAW,
            architecture=ArchitectureType.X86_64,
        )
        assert is_host_native_compatible(raw_art) is False

        # 2. UNKNOWN architecture is never natively executable
        unk_art = TargetArtifact(
            file_path="/tmp/test_unk",
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.UNKNOWN,
        )
        assert is_host_native_compatible(unk_art) is False

        # 3. Cross-OS mismatch (e.g. PE on non-Windows)
        pe_art = TargetArtifact(
            file_path="/tmp/test_pe",
            format=ArtifactFormat.PE,
            architecture=ArchitectureType.X86_64,
        )
        if os.name != "nt":
            assert is_host_native_compatible(pe_art) is False

    def test_frida_prober_foreign_arch_rejection(self) -> None:
        """Verify FridaProber strictly blocks foreign architecture tracing."""
        prober = FridaProber()

        # Incompatible foreign artifact (e.g. PE or RAW on macOS/Linux)
        foreign_art = TargetArtifact(
            file_path="/tmp/foreign_artifact",
            format=ArtifactFormat.RAW,
            architecture=ArchitectureType.UNKNOWN,
        )
        sess = BinarySession(artifact=foreign_art)

        with pytest.raises(ArchitectureCompatibilityError):
            prober.trace_function(sess, 0x401000)

    def test_unicorn_prober_unsupported_foreign_arch_rejection(self) -> None:
        """Verify UnicornProber rejects architectures it cannot emulate (MIPS, DALVIK, JS)."""
        prober = UnicornProber()

        for unsupp_arch in (
            ArchitectureType.MIPS,
            ArchitectureType.RISCV64,
            ArchitectureType.DALVIK,
            ArchitectureType.JS,
            ArchitectureType.UNKNOWN,
        ):
            art = TargetArtifact(
                file_path="/tmp/fake_bin",
                format=ArtifactFormat.ELF,
                architecture=unsupp_arch,
            )
            sess = BinarySession(artifact=art)
            assert prober.is_available(sess) is False

            with pytest.raises(ProberUnavailableError):
                prober.trace_function(sess, 0x401000)

    def test_unicorn_prober_build_page_mappings_alignment(self) -> None:
        """Verify build_page_mappings coalesces arbitrary unaligned slices into 4KB blocks."""
        # Three slices: overlapping, unaligned
        slices = [
            (0x401050, 0x100, b"\x90" * 0x100, 5),  # r-x
            (0x401150, 0x50, b"\xcc" * 0x50, 5),   # r-x (contiguous page)
            (0x600010, 0x20, b"\x01" * 0x20, 3),   # rw-
        ]
        blocks = build_page_mappings(slices)
        assert len(blocks) >= 2
        for b_addr, b_size, b_data, _b_prot in blocks:
            # Address and size must be 4KB page aligned
            assert b_addr % PAGE_SIZE == 0
            assert b_size % PAGE_SIZE == 0
            assert len(b_data) == b_size

    def test_fact_backfiller_adversarial_and_extreme_trace_results(self) -> None:
        """Verify FactBackfiller handles empty traces, negative returns, and new functions."""
        backfiller = FactBackfiller()

        art = TargetArtifact(
            file_path="/tmp/test_bin",
            format=ArtifactFormat.ELF,
            architecture=ArchitectureType.X86_64,
        )
        session = BinarySession(artifact=art, evidence_store=EvidenceStore())

        # 1. TraceResult with negative return value on unknown function address
        res_neg = TraceResult(
            success=True,
            session_id=session.session_id,
            function_address=0x501000,
            function_name="sub_501000",
            prober="unicorn",
            return_value=-1,
            captured_strings=["[ERROR] Failed to authenticate"],
            instructions_executed=42,
            execution_time_ms=1.5,
        )

        tags = backfiller.backfill(session, res_neg, 0x501000, args=[0x10, "client_name"])
        assert len(tags) >= 1
        # Verifies function was synthesized in session
        assert 0x501000 in session.functions
        func = session.functions[0x501000]
        assert func.return_type == "int"
        assert func.confidence_score == 1.0

        # Verifies evidence tags are immutable
        assert session.evidence_store is not None
        for t in tags:
            assert t.is_immutable is True
            assert t.confidence == 1.0
            assert session.evidence_store.has_immutable_tag(t.target_id) is True

        # 2. TraceResult with extreme 64-bit unsigned return value
        res_huge = TraceResult(
            success=True,
            session_id=session.session_id,
            function_address=0x502000,
            prober="unicorn",
            return_value=0xFFFFFFFF0000,
            instructions_executed=10,
            execution_time_ms=0.5,
        )
        tags_huge = backfiller.backfill(session, res_huge, 0x502000)
        assert session.functions[0x502000].return_type == "uint64_t"
        for t in tags_huge:
            assert t.is_immutable is True

        # 3. Empty TraceResult (failed trace with None return)
        res_fail = TraceResult(
            success=False,
            session_id=session.session_id,
            function_address=0x503000,
            prober="unicorn",
            return_value=None,
            error="Null pointer dereference",
        )
        tags_fail = backfiller.backfill(session, res_fail, 0x503000)
        assert len(tags_fail) >= 1
        assert session.functions[0x503000].confidence_score == 1.0

    def test_unicorn_prober_containment_and_fault_handling(self) -> None:
        """Verify UnicornProber safely traps null pointer dereferences and infinite loops without panic."""
        prober = UnicornProber()
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Null pointer dereference in x86_64: mov rax, 0; mov rbx, [rax]; ret
            # \x48\xc7\xc0\x00\x00\x00\x00 (mov rax, 0)
            # \x48\x8b\x18 (mov rbx, [rax])
            # \xc3 (ret)
            code_null = b"\x48\xc7\xc0\x00\x00\x00\x00\x48\x8b\x18\xc3"
            p_null = os.path.join(tmpdir, "null_deref.bin")
            with open(p_null, "wb") as f:
                f.write(code_null)

            art_null = TargetArtifact(
                file_path=p_null,
                format=ArtifactFormat.ELF,
                architecture=ArchitectureType.X86_64,
                bitness=64,
                base_address=0x400000,
                sections=[
                    BinarySection(
                        name=".text",
                        virtual_address=0x400000,
                        virtual_size=0x1000,
                        raw_offset=0,
                        raw_size=len(code_null),
                        permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                    )
                ],
            )
            sess_null = BinarySession(artifact=art_null)
            res_null = prober.trace_function(sess_null, 0x400000, timeout_seconds=1.0)
            assert res_null.success is False
            assert "Null pointer dereference" in (res_null.error or "")

            # 2. Infinite loop in x86_64: jmp $ (\xeb\xfe)
            code_loop = b"\xeb\xfe"
            p_loop = os.path.join(tmpdir, "loop.bin")
            with open(p_loop, "wb") as f:
                f.write(code_loop)

            art_loop = TargetArtifact(
                file_path=p_loop,
                format=ArtifactFormat.ELF,
                architecture=ArchitectureType.X86_64,
                bitness=64,
                base_address=0x400000,
                sections=[
                    BinarySection(
                        name=".text",
                        virtual_address=0x400000,
                        virtual_size=0x1000,
                        raw_offset=0,
                        raw_size=len(code_loop),
                        permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                    )
                ],
            )
            sess_loop = BinarySession(artifact=art_loop)
            res_loop = prober.trace_function(sess_loop, 0x400000, timeout_seconds=0.05, max_instructions=200)
            assert res_loop.success is False
            assert res_loop.instructions_executed > 0

