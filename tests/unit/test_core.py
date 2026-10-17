"""
Unit tests for metis_reverse.core (models, validation, session management).
"""

from __future__ import annotations

import concurrent.futures

import pytest
from pydantic import ValidationError

from metis_reverse.core.evidence import EvidenceStore
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    EvidenceSource,
    EvidenceTag,
    Function,
    Instruction,
    Operand,
    OperandType,
    Symbol,
    SymbolType,
    TargetArtifact,
    TargetType,
)
from metis_reverse.core.session import (
    SessionManager,
    SessionNotFoundError,
)
from tests.unit.test_tier1_backend import SYNTHETIC_ELF_X86_64


def test_target_artifact_validation():
    """Verify TargetArtifact construction, bitness checks, and serialization."""
    artifact = TargetArtifact(
        artifact_id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_path="/tmp/test_binary",
        file_name="test_binary",
        file_size=1024,
        format=ArtifactFormat.ELF,
        architecture=ArchitectureType.X86_64,
        bitness=64,
        entry_point=0x401000,
    )
    assert artifact.bitness == 64
    assert artifact.format == ArtifactFormat.ELF

    # Test invalid bitness raises ValidationError
    with pytest.raises(ValidationError):
        TargetArtifact(
            artifact_id="abc",
            file_path="/tmp/x",
            file_name="x",
            file_size=10,
            format=ArtifactFormat.RAW,
            architecture=ArchitectureType.UNKNOWN,
            bitness=48,  # Invalid bitness
        )


def test_instruction_byte_coercion_and_serialization():
    """Verify Instruction raw_bytes coercion from hex string or bytes."""
    ins = Instruction(
        address=0x401000,
        size=4,
        mnemonic="mov",
        op_str="x0, #1",
        raw_bytes="200080d2",  # ARM64 hex string
        operands=[
            Operand(type=OperandType.REGISTER, value="x0", access="w"),
            Operand(type=OperandType.IMMEDIATE, value=1, access="r"),
        ],
    )
    assert ins.raw_bytes == b"\x20\x00\x80\xd2"
    json_data = ins.model_dump_json()
    assert '"raw_bytes":"200080d2"' in json_data

    # Deserialization check
    restored = Instruction.model_validate_json(json_data)
    assert restored.raw_bytes == b"\x20\x00\x80\xd2"
    assert restored.address == 0x401000


def test_evidence_tag_confidence_bounds_and_immutability():
    """Verify confidence validation and immutable flags."""
    tag = EvidenceTag(
        target_type=TargetType.FUNCTION,
        target_id="func:0x401120",
        suggested_name="main_handler",
        source=EvidenceSource.GO_PCLNTAB,
        confidence=1.0,
        raw_anchor="pclntab@0x401120",
        is_immutable=True,
    )
    assert tag.is_immutable is True
    assert tag.confidence == 1.0

    # Confidence exceeding 1.0 must fail
    with pytest.raises(ValidationError):
        EvidenceTag(
            target_type=TargetType.FUNCTION,
            target_id="func:0x401120",
            source=EvidenceSource.HEURISTIC,
            confidence=1.5,
            raw_anchor="none",
        )


def test_session_manager_lifecycle(tmp_path):
    """Verify session creation, lookup, and cleanup."""
    sample_file = tmp_path / "dummy_bin"
    sample_file.write_bytes(SYNTHETIC_ELF_X86_64)

    sm = SessionManager()
    session = sm.create_session(sample_file)
    assert session.session_id.startswith("sess_")
    assert session.artifact.format == ArtifactFormat.ELF

    # Fetch active session
    fetched = sm.get_session(session.session_id)
    assert fetched.session_id == session.session_id

    # Close session
    closed = sm.close_session(session.session_id)
    assert closed is True

    # Accessing closed session raises SessionNotFoundError
    with pytest.raises(SessionNotFoundError):
        sm.get_session(session.session_id)


def test_session_manager_artifact_caching(tmp_path):
    """Verify opening same binary file twice reuses cached TargetArtifact."""
    sample_file = tmp_path / "cached_bin"
    sample_file.write_bytes(SYNTHETIC_ELF_X86_64)

    sm = SessionManager()
    session1 = sm.create_session(sample_file)
    session2 = sm.create_session(sample_file)

    assert session1.session_id != session2.session_id
    assert session1.artifact.artifact_id == session2.artifact.artifact_id
    # Artifact object identity should match due to cache
    assert session1.artifact is session2.artifact


def test_session_manager_thread_safety(tmp_path):
    """Verify 10 concurrent threads manipulating sessions under lock."""
    sm = SessionManager()
    sample_files = []
    for i in range(5):
        p = tmp_path / f"bin_{i}"
        p.write_bytes(SYNTHETIC_ELF_X86_64 + bytes([i]))
        sample_files.append(p)

    def worker(idx: int) -> str:
        f = sample_files[idx % len(sample_files)]
        sess = sm.create_session(f)
        # Add a dummy symbol
        sess.add_symbol(
            Symbol(
                address=0x1000 + idx,
                name=f"sym_{idx}",
                type=SymbolType.FUNCTION,
            )
        )
        _ = sm.get_session(sess.session_id)
        if idx % 2 == 0:
            sm.close_session(sess.session_id)
            return "closed"
        return sess.session_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(worker, range(30)))

    assert len(results) == 30


def test_evidence_store_comprehensive():
    """Verify EvidenceStore queries, filtering, immutability, and iteration."""
    store = EvidenceStore()
    assert len(store) == 0

    tag1 = EvidenceTag(
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="init_crypto",
        source=EvidenceSource.ASSERT_MACRO,
        confidence=0.95,
        raw_anchor="assert(key != NULL)",
        is_immutable=True,
    )
    tag2 = EvidenceTag(
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="setup_keys",
        source=EvidenceSource.FORMAT_STRING,
        confidence=0.75,
        raw_anchor="%s: aes key loaded",
        is_immutable=False,
    )
    tag3 = EvidenceTag(
        target_type=TargetType.SYMBOL,
        target_id="sym:0x402000",
        suggested_name="g_buffer",
        source=EvidenceSource.HEURISTIC,
        confidence=0.40,
        raw_anchor="heuristic_xref",
        is_immutable=False,
    )

    id1 = store.add_tag(tag1)
    id2 = store.add_tag(tag2)
    id3 = store.add_tag(tag3)

    assert len(store) == 3
    assert store.get_tag(id1) == tag1
    assert store.get_tag(id2) == tag2
    assert store.get_tag(id3) == tag3
    assert store.get_tag("nonexistent") is None

    # Target lookup
    tags_401000 = store.get_tags_for_target("func:0x401000")
    assert len(tags_401000) == 2
    assert store.has_immutable_tag("func:0x401000") is True
    assert store.has_immutable_tag("sym:0x402000") is False

    # Query with confidence filter
    high_conf = store.query(min_confidence=0.8)
    assert len(high_conf) == 1
    assert high_conf[0].tag_id == id1

    # Query with source filter
    fmt_tags = store.query(source=EvidenceSource.FORMAT_STRING)
    assert len(fmt_tags) == 1
    assert fmt_tags[0].suggested_name == "setup_keys"

    # Query with both target and source
    exact = store.query(target_id="func:0x401000", source="ASSERT_MACRO")
    assert len(exact) == 1

    # Iteration
    all_tags = list(store)
    assert len(all_tags) == 3


def test_binary_session_bidirectional_symbols_and_evidence():
    """Verify BinarySession symbol lookup by name and address, plus evidence attachment."""
    art = TargetArtifact(
        artifact_id="test1234",
        file_path="/tmp/test",
        file_name="test",
        format=ArtifactFormat.ELF,
        architecture=ArchitectureType.X86_64,
        bitness=64,
    )
    from metis_reverse.core.models import BinarySession
    sess = BinarySession(artifact=art, evidence_store=EvidenceStore())

    # Add function
    f = Function(id="func_0x401000", address=0x401000, name="main")
    sess.functions[0x401000] = f
    assert sess.get_function(0x401000) == f
    assert sess.get_function(0x999999) is None

    # Add symbol
    sym = Symbol(address=0x401000, name="main", type=SymbolType.FUNCTION)
    sess.add_symbol(sym)
    assert sess.symbols["main"] == sym
    assert sess.symbols[0x401000] == sym
    assert sess.symbols_by_address[0x401000] == sym

    # Attach evidence
    tag = EvidenceTag(
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="main_renamed",
        source=EvidenceSource.ASSERT_MACRO,
        confidence=1.0,
        raw_anchor="main.c:10",
        is_immutable=True,
    )
    sess.attach_evidence(tag)
    assert tag.tag_id in sess.evidence_tags
    assert tag.tag_id in f.evidence_tag_ids
    assert sess.evidence_store.get_tag(tag.tag_id) is not None


def test_session_manager_list_and_clear(tmp_path):
    """Verify SessionManager list_sessions, clear_all, and get_backend."""
    p1 = tmp_path / "bin_1.elf"
    p1.write_bytes(SYNTHETIC_ELF_X86_64)
    p2 = tmp_path / "bin_2.elf"
    p2.write_bytes(SYNTHETIC_ELF_X86_64 + b"\x90")

    sm = SessionManager()
    s1 = sm.create_session(p1)
    s2 = sm.create_session(p2)

    summaries = sm.list_sessions()
    assert len(summaries) == 2
    session_ids = {s.session_id for s in summaries}
    assert s1.session_id in session_ids
    assert s2.session_id in session_ids

    # get_backend check
    b1 = sm.get_backend(s1.session_id)
    assert b1 is not None

    with pytest.raises(SessionNotFoundError):
        sm.get_backend("nonexistent_session")

    # Clear all
    sm.clear_all()
    assert len(sm.list_sessions()) == 0
