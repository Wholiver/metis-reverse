"""
Unit tests for FormatStringGrounder: C/POSIX printf specifiers, C++ fmt/spdlog,
semantic variable name extraction, type mapping, and EvidenceTag generation.
"""

from __future__ import annotations

from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySection,
    BinarySession,
    EvidenceSource,
    SectionPermission,
    TargetArtifact,
)
from metis_reverse.grounding.format_strings import FormatStringGrounder


def test_c_specifiers_parsing():
    """Verify parsing standard C99/POSIX printf specifiers and inferred types."""
    fmt = "[INFO] Connection from %s on port %u (fd: %d, timeout: %zu, ptr: %p, ratio: %f)"
    meta = FormatStringGrounder.parse_format_string(fmt)

    assert meta.is_valid_format is True
    assert meta.log_level == "INFO"
    assert len(meta.parameters) == 6

    # %s -> const char*
    assert meta.parameters[0].specifier == "%s"
    assert meta.parameters[0].inferred_type == "const char*"
    assert meta.parameters[0].suggested_name == "connection"

    # %u -> uint32_t
    assert meta.parameters[1].specifier == "%u"
    assert meta.parameters[1].inferred_type == "uint32_t"
    assert meta.parameters[1].suggested_name == "port"

    # %d -> int
    assert meta.parameters[2].specifier == "%d"
    assert meta.parameters[2].inferred_type == "int"
    assert meta.parameters[2].suggested_name == "fd"

    # %zu -> size_t
    assert meta.parameters[3].specifier == "%zu"
    assert meta.parameters[3].inferred_type == "size_t"
    assert meta.parameters[3].suggested_name == "timeout"

    # %p -> void*
    assert meta.parameters[4].specifier == "%p"
    assert meta.parameters[4].inferred_type == "void*"
    assert meta.parameters[4].suggested_name == "ptr"

    # %f -> double
    assert meta.parameters[5].specifier == "%f"
    assert meta.parameters[5].inferred_type == "double"
    assert meta.parameters[5].suggested_name == "ratio"


def test_positional_and_escaped_percent():
    """Verify positional argument syntax (%1$s) and escaped percent (%%)."""
    fmt = "Progress: %1$d%% complete, user %2$s"
    meta = FormatStringGrounder.parse_format_string(fmt)

    assert meta.is_valid_format is True
    # %% must be skipped; only %1$d and %2$s parsed
    assert len(meta.parameters) == 2
    assert meta.parameters[0].inferred_type == "int"
    assert meta.parameters[1].inferred_type == "const char*"


def test_semantic_var_name_extraction():
    """Verify semantic name inference from key=, key:, and descriptive noun prefixes."""
    # Key-value assignment patterns
    cfg_fmt = "[CONFIG] magic=0x%08X port=%u max_clients=%u secret=%s logging=%d timeout=%u"
    meta = FormatStringGrounder.parse_format_string(cfg_fmt)
    names = [p.suggested_name for p in meta.parameters]
    assert names == ["magic", "port", "max_clients", "secret", "logging", "timeout"]

    # Prepositional and noun patterns
    auth_fmt = "[DEBUG] Session %u authenticated for client %s"
    meta2 = FormatStringGrounder.parse_format_string(auth_fmt)
    assert meta2.parameters[0].suggested_name == "session"
    assert meta2.parameters[1].suggested_name == "client"

    err_fmt = "[ERROR] Auth failed for client %s (id: %u)"
    meta3 = FormatStringGrounder.parse_format_string(err_fmt)
    assert meta3.parameters[0].suggested_name == "client"
    assert meta3.parameters[1].suggested_name == "id"


def test_cpp_fmt_and_spdlog():
    """Verify C++ fmt and spdlog format string parsing."""
    cpp_fmt = "[INFO] User {username} performed {action} with status {:d}"
    meta = FormatStringGrounder.parse_format_string(cpp_fmt)

    assert meta.is_valid_format is True
    assert len(meta.parameters) == 3
    assert meta.parameters[0].suggested_name == "username"
    assert meta.parameters[1].suggested_name == "action"
    assert meta.parameters[2].suggested_name == "status"


def test_format_grounder_generates_immutable_evidence(tmp_path):
    """Verify FormatStringGrounder.ground attaches immutable EvidenceTags to session."""
    dummy_file = tmp_path / "test_bin"
    # Write a dummy binary with an ASCII format string in string table
    fmt_bytes = b"[INFO] Service starting on port %u (max_clients: %u)\x00"
    dummy_file.write_bytes(b"\x00" * 64 + fmt_bytes + b"\x00" * 64)

    sec = BinarySection(
        name="__cstring",
        virtual_address=0x100001000,
        virtual_size=len(fmt_bytes) + 128,
        raw_offset=0,
        raw_size=len(fmt_bytes) + 128,
        permissions=[SectionPermission.READ],
    )
    art = TargetArtifact(
        artifact_id="dummy_art",
        file_path=str(dummy_file),
        format=ArtifactFormat.MACHO,
        architecture=ArchitectureType.ARM64,
        sections=[sec],
    )
    session = BinarySession(artifact=art)

    tags = FormatStringGrounder.ground(session)
    assert len(tags) >= 1

    found_tag = None
    for t in tags:
        if "Service starting on port %u" in t.raw_anchor:
            found_tag = t
            break

    assert found_tag is not None
    assert found_tag.source == EvidenceSource.FORMAT_STRING
    assert found_tag.confidence == 1.0
    assert found_tag.is_immutable is True
    assert "port" in str(found_tag.explanation)
