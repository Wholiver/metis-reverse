"""
Milestone 2 Adversarial Stress & Edge Case Test Suite.
Authored by Challenger M2-2.

Tests:
1. Immutability enforcement in EvidenceStore and FastMCP rename_symbol / update_variable_type.
2. Concurrent multithreaded read/write stress on EvidenceStore (RLock validation).
3. Corrupted Go pclntab headers, out-of-bounds offsets, single-function tables, and UnboundLocalError.
4. JavaScript AST scope extractor under deeply nested scopes, missing exports, and syntax noise.
5. C++ Itanium RTTI parser and demangler stress testing.
"""

from __future__ import annotations

import concurrent.futures
import random
import struct
from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

import metis_reverse.server as mr_server
from metis_reverse.core.evidence import EvidenceStore, ImmutableEvidenceError
from metis_reverse.core.models import (
    EvidenceSource,
    EvidenceTag,
    TargetType,
)
from metis_reverse.grounding.metadata.cpp_rtti import CppDemangler
from metis_reverse.grounding.metadata.go_pclntab import GoPclntabParser
from metis_reverse.grounding.metadata.js_ast import JsAstScopeExtractor

# ============================================================================
# Dimension 1: Immutability Enforcement & Mutation Checks
# ============================================================================

def test_evidence_store_forbids_overwriting_immutable_tag():
    """Verify EvidenceStore.add_tag rejects overwriting an immutable tag."""
    store = EvidenceStore()
    tag1 = EvidenceTag(
        tag_id="tag_immut_1",
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="target_func",
        source=EvidenceSource.GO_PCLNTAB,
        confidence=1.0,
        raw_anchor="pclntab",
        is_immutable=True,
    )
    store.add_tag(tag1)

    # Attempt to overwrite with lower confidence tag
    tag_bad = EvidenceTag(
        tag_id="tag_immut_1",
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="fake_func",
        source=EvidenceSource.HEURISTIC,
        confidence=0.1,
        raw_anchor="fake",
        is_immutable=False,
    )
    with pytest.raises(ImmutableEvidenceError, match="Cannot overwrite immutable evidence tag"):
        store.add_tag(tag_bad)


def test_evidence_store_forbids_deleting_immutable_tag():
    """Verify EvidenceStore.delete_tag rejects deleting an immutable tag."""
    store = EvidenceStore()
    tag1 = EvidenceTag(
        tag_id="tag_immut_del",
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="target_func",
        source=EvidenceSource.ASSERT_MACRO,
        confidence=1.0,
        raw_anchor="assert",
        is_immutable=True,
    )
    store.add_tag(tag1)

    with pytest.raises(ImmutableEvidenceError, match="Cannot delete immutable evidence tag"):
        store.delete_tag("tag_immut_del")


def test_evidence_store_secondary_index_stale_mapping_on_overwrite():
    """
    VULNERABILITY PROOF:
    When a mutable tag is overwritten with a new target_id, EvidenceStore
    fails to clean up secondary indices (_by_target, _by_source), causing
    queries for the old target to return the new (unrelated) tag.
    """
    store = EvidenceStore()
    tag_v1 = EvidenceTag(
        tag_id="tag_mutable",
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="func_401000",
        source=EvidenceSource.HEURISTIC,
        confidence=0.5,
        raw_anchor="xref1",
        is_immutable=False,
    )
    store.add_tag(tag_v1)

    # Overwrite mutable tag with target 0x402000
    tag_v2 = EvidenceTag(
        tag_id="tag_mutable",
        target_type=TargetType.FUNCTION,
        target_id="func:0x402000",
        suggested_name="func_402000",
        source=EvidenceSource.FORMAT_STRING,
        confidence=0.8,
        raw_anchor="fmt2",
        is_immutable=False,
    )
    store.add_tag(tag_v2)

    # Querying old target returns empty (stale secondary index properly cleaned up)
    res_old = store.query(target_id="func:0x401000")
    assert len(res_old) == 0, f"Expected 0 tags for old target, found: {res_old}"
    assert len(store.get_tags_for_target("func:0x401000")) == 0
    assert len(store.get_tags_for_address(0x401000)) == 0
    assert len(store.query(source=EvidenceSource.HEURISTIC)) == 0

    # Querying new target returns tag_v2
    res_new = store.query(target_id="func:0x402000")
    assert len(res_new) == 1
    assert res_new[0].tag_id == "tag_mutable"
    assert res_new[0].target_id == "func:0x402000"
    assert len(store.get_tags_for_target("func:0x402000")) == 1
    assert len(store.get_tags_for_address(0x402000)) == 1
    assert len(store.query(source=EvidenceSource.FORMAT_STRING)) == 1


def test_server_rename_symbol_blocks_immutable_evidence(c_service_stripped_path: Path):
    """Verify rename_symbol FastMCP tool blocks renaming symbols backed by immutable evidence."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]
    functions = mr_server.list_functions(session_id)
    assert len(functions) > 0

    first_addr = getattr(functions[0], "address", None) or functions[0].get("address")

    # 1. Stripped ungrounded functions can be cleanly renamed
    ren_res = mr_server.rename_symbol(
        session_id=session_id,
        address=first_addr,
        new_name="reconstructed_main_handler",
    )
    assert ren_res is not None
    success = getattr(ren_res, "success", None) if hasattr(ren_res, "success") else ren_res.get("success", True)
    assert success is True

    # 2. Attach authentic immutable evidence tag to lock function
    from metis_reverse.core.models import EvidenceSource, EvidenceTag, TargetType
    from metis_reverse.core.session import global_session_manager
    active_sess = global_session_manager.get_session(session_id)
    tag = EvidenceTag(
        tag_id="ev_assert_lock_function",
        target_type=TargetType.FUNCTION,
        target_id=f"func:0x{first_addr:x}",
        suggested_name="reconstructed_main_handler",
        source=EvidenceSource.ASSERT_MACRO,
        confidence=1.0,
        is_immutable=True,
    )
    active_sess.attach_evidence(tag)

    # 3. Attempting to rename a function with immutable evidence tags raises ToolError
    with pytest.raises(ToolError, match="locked by immutable evidence"):
        mr_server.rename_symbol(
            session_id=session_id,
            address=first_addr,
            new_name="malicious_overwrite",
        )


def test_server_update_variable_type_not_implemented():
    """Verify that update_variable_type is exposed on server (Milestone 4 scope implemented)."""
    assert hasattr(mr_server, "update_variable_type")


# ============================================================================
# Dimension 2: Concurrent Multi-Threaded Stress on EvidenceStore
# ============================================================================

def test_evidence_store_concurrent_stress_multithreaded():
    """Verify EvidenceStore thread-safety under heavy concurrent multithreaded operations."""
    store = EvidenceStore()
    errors: list[tuple[str, Exception]] = []

    def stress_worker(wid: int):
        for i in range(150):
            op = random.choice(["add", "delete", "query", "iter", "len", "get"])
            tid = f"tag_{wid}_{i % 15}"
            addr = 0x401000 + (i % 8) * 16
            target = f"func:0x{addr:x}"
            is_imm = (i % 4 == 0)

            try:
                if op == "add":
                    tag = EvidenceTag(
                        tag_id=tid,
                        target_type=TargetType.FUNCTION,
                        target_id=target,
                        suggested_name=f"fn_{wid}_{i}",
                        source=EvidenceSource.GO_PCLNTAB if is_imm else EvidenceSource.HEURISTIC,
                        confidence=1.0 if is_imm else 0.5,
                        raw_anchor=f"anchor_{wid}_{i}",
                        is_immutable=is_imm,
                    )
                    store.add_tag(tag)
                elif op == "delete":
                    store.delete_tag(tid)
                elif op == "query":
                    _ = store.query(target_id=target, min_confidence=0.4)
                elif op == "iter":
                    _ = list(store)
                elif op == "len":
                    _ = len(store)
                elif op == "get":
                    _ = store.get_tags_for_target(target)
                    _ = store.get_tags_for_address(addr)
                    _ = store.has_immutable_tag(target)
            except ImmutableEvidenceError:
                # Expected when trying to delete or overwrite an immutable tag
                pass
            except Exception as e:
                errors.append((op, e))

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
        futures = [executor.submit(stress_worker, w) for w in range(24)]
        concurrent.futures.wait(futures)

    assert len(errors) == 0, f"Thread safety violated with {len(errors)} errors: {errors[:5]}"


# ============================================================================
# Dimension 3: Corrupted Go pclntab Headers & Out-of-bounds Offsets
# ============================================================================

def test_go_pclntab_truncated_header_struct_error():
    """
    VULNERABILITY PROOF:
    A buffer with Go 1.20 magic and length between 32 and 71 bytes
    crashes _parse_go118_and_newer with an unhandled struct.error.
    """
    # 38 bytes buffer: has magic, minLC, ptrSize, but truncated before pcln_offset
    truncated_buf = struct.pack("<I", 0xFFFFFFF1) + b"\x00\x00\x01\x08" + b"\x00" * 30
    parser = GoPclntabParser(truncated_buf)
    symbols = parser.extract_symbols()
    assert symbols == []


def test_go_pclntab_unbound_local_error_single_function():
    """
    VULNERABILITY PROOF:
    In Go 1.18+, if next_entry_off <= entry_off (e.g. single function table,
    or non-monotonic offsets in corrupted binary), func_size is never bound,
    causing an UnboundLocalError when instantiating GoFunctionSymbol.
    """
    header = bytearray()
    header += struct.pack("<I", 0xFFFFFFF1)
    header += b"\x00\x00\x01\x08"
    header += struct.pack("<Q", 1)  # nfunc=1
    header += struct.pack("<Q", 1)  # nfiles=1
    header += struct.pack("<Q", 0x401000)  # textStart
    header += struct.pack("<Q", 72)  # funcnameOffset
    header += struct.pack("<Q", 120)  # cuOffset
    header += struct.pack("<Q", 128)  # filetabOffset
    header += struct.pack("<Q", 160)  # pctabOffset
    header += struct.pack("<Q", 100)  # pclnOffset

    header += b"\x00" * (72 - len(header))
    header += b"main.main\x00"

    # functab entry 0 at 100:
    header += b"\x00" * (100 - len(header))
    header += struct.pack("<II", 0, 8)  # entryOff=0, funcDataOff=8
    # func_record at 108 (28 bytes)
    header += struct.pack("<IiiIIII", 0, 0, 0, 0, 0, 0, 0)

    parser = GoPclntabParser(bytes(header), text_base_address=0x401000)
    symbols = parser.extract_symbols()
    assert len(symbols) == 1
    assert symbols[0].name == "main.main"


def test_go_pclntab_invalid_magic_and_corrupt_data():
    """Verify GoPclntabParser safely returns [] on invalid magic and random noise."""
    # Invalid magic
    noise = b"\xde\xad\xbe\xef" * 32
    parser = GoPclntabParser(noise)
    assert parser.extract_symbols() == []

    # Extremely short buffer (< 32 bytes)
    short_buf = b"\xf1\xff\xff\xff\x00\x00"
    parser_short = GoPclntabParser(short_buf)
    assert parser_short.extract_symbols() == []


def test_go_pclntab_out_of_bounds_string_and_file_offsets():
    """Verify GoPclntabParser handles out-of-bounds string and file offsets gracefully."""
    header = bytearray()
    header += struct.pack("<I", 0xFFFFFFF1)
    header += b"\x00\x00\x01\x08"
    header += struct.pack("<Q", 1)  # nfunc=1
    header += struct.pack("<Q", 1)  # nfiles=1
    header += struct.pack("<Q", 0x401000)  # textStart
    header += struct.pack("<Q", 0xFFFFFFF0)  # Out-of-bounds funcnameOffset
    header += struct.pack("<Q", 0xFFFFFFF0)  # Out-of-bounds cuOffset
    header += struct.pack("<Q", 0xFFFFFFF0)  # Out-of-bounds filetabOffset
    header += struct.pack("<Q", 0xFFFFFFF0)  # Out-of-bounds pctabOffset
    header += struct.pack("<Q", 200)  # pclnOffset

    header += b"\x00" * (200 - len(header))
    # functab entry 0
    header += struct.pack("<II", 0, 16)
    # dummy second entry to prevent next_entry_off crash
    header += struct.pack("<II", 64, 0)
    # func_record with out of bounds offsets
    header += struct.pack("<IiiIIII", 0, 99999, 0, 0, 0, 99999, 99999)

    parser = GoPclntabParser(bytes(header), text_base_address=0x401000)
    symbols = parser.extract_symbols()
    # Should safely return empty symbols without crashing
    assert symbols == []


# ============================================================================
# Dimension 4: Obfuscated JS Code (Deeply Nested & Missing Exports)
# ============================================================================

def test_js_ast_scope_extractor_deeply_nested_recursion_limit():
    """
    VULNERABILITY PROOF:
    JsAstScopeExtractor uses recursive AST walking (_find_exports, _find_classes,
    _find_cli_functions). When given deeply nested JS blocks (e.g. depth 1200),
    it exceeds Python's sys.getrecursionlimit() and crashes with RecursionError.
    """
    depth = 1200
    nested_js = "{" * depth + " function test() { return 1; } " + "}" * depth
    extractor = JsAstScopeExtractor(nested_js)
    bindings = extractor.analyze()
    assert isinstance(bindings, list)


def test_js_ast_scope_extractor_missing_exports_behavior():
    """Verify behavior of JsAstScopeExtractor when code has classes but no module.exports."""
    js_code = """
    class InternalCipher {
        encrypt(buf) { return buf; }
        decrypt(buf) { return buf; }
    }
    const cipher = new InternalCipher();
    function run() { console.log(cipher.encrypt("hello")); }
    run();
    """
    extractor = JsAstScopeExtractor(js_code)
    bindings = extractor.analyze()
    assert isinstance(bindings, list)
    orig_names = [b.original_name for b in bindings]
    # Verify fallback extracts methods or functions
    assert "encrypt" in orig_names or "decrypt" in orig_names or "run" in orig_names


def test_js_ast_scope_extractor_syntax_noise_and_malformed():
    """Verify JsAstScopeExtractor survives syntax errors and truncated scripts."""
    malformed_js = "function incomplete( { return 123 + ; class {"
    extractor = JsAstScopeExtractor(malformed_js)
    # Tree-sitter handles syntax errors with ERROR nodes; extractor must not crash
    bindings = extractor.analyze()
    assert isinstance(bindings, list)


# ============================================================================
# Dimension 5: C++ Demangler & RTTI Stress
# ============================================================================

def test_cpp_demangler_adversarial_inputs():
    """Verify CppDemangler handles extreme input lengths and malformed mangled strings."""
    # Extremely long string
    huge_str = "_Z" + "N" + "5metis" * 500 + "E"
    demangled = CppDemangler.demangle(huge_str)
    assert isinstance(demangled, str)

    # Malformed length prefixes
    bad_prefixes = [
        "_ZN99999999999999999999999E",
        "_ZN0E",
        "_ZTV",
        "_ZTI",
        "_Z",
        "",
        "   ",
        "_ZN3abc4def",  # Missing terminating E
    ]
    for bp in bad_prefixes:
        res = CppDemangler.demangle(bp)
        assert isinstance(res, str)
