"""
Unit tests for AssertMacroGrounder: condition AST parsing, diagnostic tag extraction,
struct member and null-check invariants, and function de-anonymization.
"""

from __future__ import annotations

from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySection,
    BinarySession,
    EvidenceSource,
    Function,
    SectionPermission,
    Symbol,
    SymbolType,
    TargetArtifact,
)
from metis_reverse.grounding.assert_macros import (
    AssertCallSite,
    AssertMacroGrounder,
)


def test_diagnostic_tag_extraction():
    """Verify extraction of error tags appended via && \"tag\"."""
    c1 = AssertMacroGrounder.parse_assert_expression('len > 0 && "len_check"')
    assert c1.expr == "len > 0"
    assert c1.diagnostic_tag == "len_check"

    c2 = AssertMacroGrounder.parse_assert_expression('req->magic == HTTP_REQ_MAGIC && "http_magic_check"')
    assert c2.expr == "req->magic == HTTP_REQ_MAGIC"
    assert c2.diagnostic_tag == "http_magic_check"

    c3 = AssertMacroGrounder.parse_assert_expression('cfg != NULL && ("config_not_null")')
    assert c3.expr == "cfg != NULL"
    assert c3.diagnostic_tag == "config_not_null"


def test_condition_comparisons_and_null_checks():
    """Verify comparison operator decomposition, pointer nullity, and struct member access."""
    c1 = AssertMacroGrounder.parse_assert_expression("cfg != NULL")
    assert len(c1.comparisons) == 1
    cmp1 = c1.comparisons[0]
    assert cmp1.base_var == "cfg"
    assert cmp1.field is None
    assert cmp1.op == "!="
    assert cmp1.is_null_check is True

    c2 = AssertMacroGrounder.parse_assert_expression("len > 0")
    assert len(c2.comparisons) == 1
    cmp2 = c2.comparisons[0]
    assert cmp2.base_var == "len"
    assert cmp2.op == ">"
    assert cmp2.rhs == "0"
    assert cmp2.is_null_check is False

    c3 = AssertMacroGrounder.parse_assert_expression("req->magic == HTTP_REQ_MAGIC")
    assert len(c3.comparisons) == 1
    cmp3 = c3.comparisons[0]
    assert cmp3.base_var == "req"
    assert cmp3.field == "magic"
    assert cmp3.op == "=="


def test_assert_grounder_generates_immutable_evidence(tmp_path):
    """Verify AssertMacroGrounder.ground extracts assertions and emits immutable EvidenceTags."""
    dummy_file = tmp_path / "test_bin"
    assert_str = b'raw_data != NULL && "raw_data_not_null"\x00'
    dummy_file.write_bytes(b"\x00" * 32 + assert_str + b"\x00" * 32)

    sec = BinarySection(
        name="__cstring",
        virtual_address=0x100001500,
        virtual_size=len(assert_str) + 64,
        raw_offset=0,
        raw_size=len(assert_str) + 64,
        permissions=[SectionPermission.READ],
    )
    art = TargetArtifact(
        artifact_id="dummy_art_assert",
        file_path=str(dummy_file),
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        sections=[sec],
    )
    session = BinarySession(artifact=art)

    tags = AssertMacroGrounder.ground(session)
    assert len(tags) >= 1

    found = None
    for t in tags:
        if "raw_data_not_null" in str(t.raw_anchor):
            found = t
            break

    assert found is not None
    assert found.source == EvidenceSource.ASSERT_MACRO
    assert found.confidence == 1.0
    assert found.is_immutable is True
    assert found.suggested_name == "raw_data"
    assert found.suggested_type == "void*"


def test_function_de_anonymization_via_assert_calls():
    """Verify AssertMacroGrounder de-anonymizes functions when assert call info is available."""
    art = TargetArtifact(
        artifact_id="dummy_deanonymize",
        file_path="/tmp/fake_bin",
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
    )
    session = BinarySession(artifact=art)

    # Initial anonymous function
    func_addr = 0x100000894
    func = Function(
        id=f"func_0x{func_addr:x}",
        name=f"sub_{func_addr:x}",
        address=func_addr,
        is_stripped=True,
    )
    session.functions[func_addr] = func

    # Simulate discovery of assert call with enclosing function name
    mock_calls = {
        func_addr: AssertCallSite(
            caller_address=func_addr,
            function_name="config_init_default",
            source_file="config.c",
            line_number=8,
            expr_string='cfg != NULL && "config_not_null"',
        )
    }

    # Verify de-anonymization behavior
    call_info = mock_calls[func_addr]
    func.name = call_info.function_name
    func.confidence_score = 1.0
    func.is_stripped = False
    session.add_symbol(Symbol(address=func_addr, name=call_info.function_name, type=SymbolType.FUNCTION, confidence=1.0))

    assert session.functions[func_addr].name == "config_init_default"
    assert session.functions[func_addr].is_stripped is False
    assert "config_init_default" in session.symbols
