"""
Unit tests for metis_reverse.server (FastMCP tools and protocol handling).
"""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from metis_reverse.core.models import (
    CallingConvention,
    EvidenceSource,
    EvidenceTag,
    Function,
    Symbol,
    SymbolType,
    TargetType,
)
from metis_reverse.core.session import global_session_manager
from metis_reverse.server import mcp, open_session, parse_int_address
from tests.unit.test_tier1_backend import SYNTHETIC_ELF_X86_64, SYNTHETIC_PE_X86_64


@pytest.fixture(autouse=True)
def clean_sessions():
    """Ensure session manager is wiped clean between tests."""
    global_session_manager.clear_all()
    yield
    global_session_manager.clear_all()


def test_parse_int_address():
    """Verify hex string and integer normalization."""
    assert parse_int_address(0x401000) == 4198400
    assert parse_int_address("0x401000") == 4198400
    assert parse_int_address("0X401000") == 4198400
    assert parse_int_address("4198400") == 4198400

    with pytest.raises(ToolError):
        parse_int_address("invalid_address_hex")


@pytest.mark.asyncio
async def test_tool_registration_list():
    """Verify all reverse engineering tools are registered in FastMCP server."""
    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    required_tools = [
        "open_session",
        "close_session",
        "list_functions",
        "disassemble",
        "decompile",
        "query_evidence",
        "rename_symbol",
    ]
    for req in required_tools:
        assert req in tool_names, f"Tool '{req}' is not registered in FastMCP"


@pytest.mark.asyncio
async def test_open_session_nonexistent_file():
    """Calling open_session on missing file must raise ToolError."""
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("open_session", {"file_path": "/nonexistent/binary/path.bin"})
    assert "Artifact not found" in str(exc_info.value)


@pytest.mark.asyncio
async def test_session_tool_workflow(tmp_path):
    """End-to-end verification of tool invocations via FastMCP."""
    bin_file = tmp_path / "mock.elf"
    bin_file.write_bytes(SYNTHETIC_ELF_X86_64)

    # 1. Open session
    res = await mcp.call_tool("open_session", {"file_path": str(bin_file)})
    session_id = res.structured_content["session_id"]
    assert session_id.startswith("sess_")

    # Manually populate session data for testing downstream tools
    session = global_session_manager.get_session(session_id)
    func_addr = 0x401100
    func = Function(
        id=f"func_{func_addr:x}",
        name="sub_401100",
        address=func_addr,
        size=32,
        calling_convention=CallingConvention.SYSTEM_V_AMD64,
        confidence_score=0.95,
    )
    session.functions[func_addr] = func

    # Attach immutable evidence tag
    tag = EvidenceTag(
        target_type=TargetType.FUNCTION,
        target_id=f"func:0x{func_addr:x}",
        suggested_name="calculateChecksum",
        source=EvidenceSource.ASSERT_MACRO,
        confidence=1.0,
        raw_anchor="assert(buf != NULL)",
        is_immutable=True,
    )
    session.attach_evidence(tag)

    # 2. List functions
    func_res = await mcp.call_tool("list_functions", {"session_id": session_id})
    funcs = (
        func_res.structured_content.get("result", func_res.structured_content)
        if isinstance(func_res.structured_content, dict)
        else func_res.structured_content
    )
    assert len(funcs) == 1
    assert funcs[0]["name"] == "sub_401100"

    # 3. Query evidence
    ev_res = await mcp.call_tool(
        "query_evidence",
        {"session_id": session_id, "symbol_or_addr": f"0x{func_addr:x}"},
    )
    evs = (
        ev_res.structured_content.get("result", ev_res.structured_content)
        if isinstance(ev_res.structured_content, dict)
        else ev_res.structured_content
    )
    assert len(evs) == 1
    assert evs[0]["raw_anchor"] == "assert(buf != NULL)"

    # 4. Attempt rename immutable symbol (should fail with ToolError)
    session.add_symbol(
        Symbol(
            address=func_addr,
            name="sub_401100",
            type=SymbolType.FUNCTION,
            evidence_tags=[tag],
        )
    )
    with pytest.raises(ToolError) as rename_exc:
        await mcp.call_tool(
            "rename_symbol",
            {
                "session_id": session_id,
                "address": f"0x{func_addr:x}",
                "new_name": "arbitraryName",
            },
        )
    assert "locked by immutable evidence" in str(rename_exc.value)

    # 5. Close session
    close_res = await mcp.call_tool("close_session", {"session_id": session_id})
    assert close_res.structured_content["closed"] is True


@pytest.mark.asyncio
async def test_server_invalid_session_errors():
    """Verify that MCP tools reject invalid or expired session IDs with ToolError."""
    fake_id = "sess_deadbeef0000"

    with pytest.raises(ToolError):
        await mcp.call_tool("list_functions", {"session_id": fake_id})

    with pytest.raises(ToolError):
        await mcp.call_tool("disassemble", {"session_id": fake_id, "address": "0x401000"})

    with pytest.raises(ToolError):
        await mcp.call_tool("decompile", {"session_id": fake_id, "function_address": "0x401000"})

    with pytest.raises(ToolError):
        await mcp.call_tool("query_evidence", {"session_id": fake_id, "symbol_or_addr": "main"})

    with pytest.raises(ToolError):
        await mcp.call_tool(
            "rename_symbol",
            {"session_id": fake_id, "address": "0x401000", "new_name": "renamed_fn"},
        )


@pytest.mark.asyncio
async def test_server_disassemble_and_decompile_mock(tmp_path):
    """Verify disassemble and decompile tools through mock backend."""
    bin_file = tmp_path / "mock_test.elf"
    bin_file.write_bytes(SYNTHETIC_ELF_X86_64)

    res = await mcp.call_tool("open_session", {"file_path": str(bin_file), "backend": "mock"})
    session_id = res.structured_content["session_id"]

    # Disassemble tool
    dis_res = await mcp.call_tool(
        "disassemble",
        {"session_id": session_id, "address": "0x401000", "size": 16},
    )
    assert dis_res.structured_content["instruction_count"] > 0
    assert len(dis_res.structured_content["instructions"]) > 0

    # Decompile tool on mock's default function at 0x401000
    dec_res = await mcp.call_tool(
        "decompile",
        {"session_id": session_id, "function_address": "0x401000"},
    )
    assert dec_res.structured_content["language"] == "c"
    assert "source_code" in dec_res.structured_content
    assert len(dec_res.structured_content["source_code"]) > 0

    # Close session
    close_res = await mcp.call_tool("close_session", {"session_id": session_id})
    assert close_res.structured_content["closed"] is True


# ============================================================================
# Regression Test Suite: Truncated & Malformed Binary Rejection
# ============================================================================


@pytest.mark.parametrize(
    "name,payload",
    [
        ("elf_magic_only_4b", b"\x7fELF"),
        ("elf_identity_16b", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8),
        ("elf_partial_ehdr_32b", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00" + b"\x00" * 12),
        ("elf_no_sections_no_segments_64b", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00\x01\x00\x00\x00" + b"\x00" * 44),
    ],
)
@pytest.mark.asyncio
async def test_open_session_rejects_truncated_elf_variants(tmp_path, name, payload):
    """Ensure truncated ELF headers are rejected at server and FastMCP tool levels."""
    bin_file = tmp_path / f"{name}.bin"
    bin_file.write_bytes(payload)

    # 1. Direct function call must raise ValueError
    with pytest.raises(ValueError) as exc_info:
        open_session(str(bin_file), backend="auto")
    assert "Unsupported binary" in str(exc_info.value) or "malformed" in str(exc_info.value)

    # 2. FastMCP tool invocation must raise ToolError
    with pytest.raises(ToolError):
        await mcp.call_tool("open_session", {"file_path": str(bin_file), "backend": "auto"})


@pytest.mark.parametrize(
    "name,payload",
    [
        ("macho_be32_4b", b"\xfe\xed\xfa\xce"),
        ("macho_le64_4b", b"\xcf\xfa\xed\xfe"),
        ("macho_truncated_header_8b", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01"),
        ("macho_truncated_header_16b", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x02\x00\x00\x00"),
        ("macho_partial_header_28b", b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x02\x00\x00\x00" + b"\x00" * 12),
        ("macho_no_load_commands_32b", b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00" + b"\x00" * 16),
    ],
)
@pytest.mark.asyncio
async def test_open_session_rejects_truncated_macho_variants(tmp_path, name, payload):
    """Ensure truncated Mach-O headers are rejected cleanly."""
    bin_file = tmp_path / f"{name}.bin"
    bin_file.write_bytes(payload)

    with pytest.raises(ValueError) as exc_info:
        open_session(str(bin_file), backend="auto")
    assert "Unsupported binary" in str(exc_info.value) or "malformed" in str(exc_info.value)

    with pytest.raises(ToolError):
        await mcp.call_tool("open_session", {"file_path": str(bin_file), "backend": "auto"})


@pytest.mark.parametrize(
    "name,payload",
    [
        ("pe_dos_magic_2b", b"MZ"),
        ("pe_dos_header_64b", b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"),
        ("pe_dos_and_pe_magic_68b", b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00"),
        ("wasm_magic_4b", b"\x00asm"),
        ("dex_magic_4b", b"dex\n"),
        ("random_noise_32b", b"\xde\xad\xbe\xef" * 8),
    ],
)
@pytest.mark.asyncio
async def test_open_session_rejects_other_truncated_formats(tmp_path, name, payload):
    """Ensure truncated PE, WASM, DEX, and random noise are rejected."""
    bin_file = tmp_path / f"{name}.bin"
    bin_file.write_bytes(payload)

    with pytest.raises(ValueError):
        open_session(str(bin_file), backend="auto")

    with pytest.raises(ToolError):
        await mcp.call_tool("open_session", {"file_path": str(bin_file), "backend": "auto"})


@pytest.mark.asyncio
async def test_open_session_valid_synthetic_binaries_pass(tmp_path):
    """Verify valid synthetic binaries (ELF and PE) succeed without false-positive rejection."""
    elf_file = tmp_path / "valid.elf"
    elf_file.write_bytes(SYNTHETIC_ELF_X86_64)

    res_elf = await mcp.call_tool("open_session", {"file_path": str(elf_file), "backend": "auto"})
    assert res_elf.structured_content["format"] == "ELF"
    assert res_elf.structured_content["architecture"] == "x86_64"
    assert res_elf.structured_content["session_id"].startswith("sess_")

    pe_file = tmp_path / "valid.exe"
    pe_file.write_bytes(SYNTHETIC_PE_X86_64)

    res_pe = await mcp.call_tool("open_session", {"file_path": str(pe_file), "backend": "auto"})
    assert res_pe.structured_content["format"] == "PE"
    assert res_pe.structured_content["architecture"] == "x86_64"
