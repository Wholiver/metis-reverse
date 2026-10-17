"""
Metis Reverse - FastMCP Server
Primary entry point exposing reverse engineering tools over MCP protocol.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from metis_reverse.backends.base import UnsupportedArtifactError
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    DecompiledCode,
    DecompiledFunctionResult,
    DifferentialResult,
    DisassemblyResult,
    EvidenceTag,
    FunctionSummary,
    Instruction,
    MutationResult,
    RecompileResult,
    SessionCloseResult,
    SessionInfo,
    TraceResult,
    extract_address_from_target_id,
)
from metis_reverse.core.session import (
    ArtifactNotFoundError,
    SessionNotFoundError,
    global_session_manager,
)

logger = logging.getLogger("metis_reverse.server")

# ============================================================================
# Server Initialization
# ============================================================================

mcp = FastMCP(
    name="Metis-Reverse",
    version="0.1.0",
    instructions=(
        "Metis Reverse: AI-native reverse engineering server. Provides deterministic, "
        "evidence-grounded decompilation, multi-source symbol de-anonymization, "
        "and interactive binary mutation tools."
    ),
)


# ============================================================================
# Helper Utilities
# ============================================================================

def parse_int_address(addr: int | str) -> int:
    """Normalize integer or hex string address into int."""
    if isinstance(addr, int):
        if addr < 0:
            raise ToolError(f"Address cannot be negative: {addr}")
        return addr
    if isinstance(addr, str):
        clean = addr.strip()
        if clean.lower().startswith("0x"):
            try:
                val = int(clean, 16)
                if val < 0:
                    raise ToolError(f"Address cannot be negative: {addr}")
                return val
            except ValueError as err:
                raise ToolError(f"Invalid memory address representation: '{addr}'") from err
        if clean.isdigit():
            val = int(clean, 10)
            if val < 0:
                raise ToolError(f"Address cannot be negative: {addr}")
            return val
        try:
            val = int(clean, 16)
            if val < 0:
                raise ToolError(f"Address cannot be negative: {addr}")
            return val
        except ValueError as err:
            raise ToolError(f"Invalid memory address representation: '{addr}'") from err
    raise ToolError(f"Address must be an integer or hex string, got {type(addr)}")


# ============================================================================
# FastMCP Tools
# ============================================================================

@mcp.tool()
def open_session(
    file_path: str,
    backend: str | None = "auto",
) -> SessionInfo:
    """
    Open an executable binary or script artifact and create an active analysis session.

    Args:
        file_path: Path to target file on disk (ELF, PE, Mach-O, DEX, or JS).
        backend: Preferred decompiler engine ("auto", "tier1_native", "ghidra", "ida", "mock").
    """
    try:
        session = global_session_manager.create_session(
            file_path=file_path,
            backend_name=backend,
            validate=True,
        )

        # Reject malformed raw/unknown binaries or native binaries without sections
        is_unknown_arch = (
            session.artifact.architecture == ArchitectureType.UNKNOWN
            or str(session.artifact.architecture).lower() in ("unknown", "architecturetype.unknown")
        )
        is_raw_format = (
            session.artifact.format == ArtifactFormat.RAW
            or str(session.artifact.format).lower() in ("raw", "artifactformat.raw")
        )
        is_native_format = session.artifact.format in (
            ArtifactFormat.ELF,
            ArtifactFormat.MACHO,
            ArtifactFormat.PE,
        ) or str(session.artifact.format).upper() in ("ELF", "MACHO", "PE")
        is_empty_sections = not bool(session.artifact.sections)

        if is_unknown_arch or is_raw_format or (is_native_format and is_empty_sections):
            global_session_manager.close_session(session.session_id)
            if hasattr(session.artifact, "artifact_id") and session.artifact.artifact_id:
                global_session_manager.purge_artifact_cache(session.artifact.artifact_id)
            raise ValueError(f"Unrecognized or malformed binary format for '{file_path}'")

        return SessionInfo(
            session_id=session.session_id,
            artifact_id=session.artifact.artifact_id,
            file_path=session.artifact.file_path,
            file_name=session.artifact.file_name,
            format=session.artifact.format.value if hasattr(session.artifact.format, "value") else str(session.artifact.format),
            architecture=session.artifact.architecture.value if hasattr(session.artifact.architecture, "value") else str(session.artifact.architecture),
            bitness=session.artifact.bitness,
            entry_point=f"0x{session.artifact.entry_point:x}",
            backend=session.backend_type,
            total_functions=len(session.functions),
            total_symbols=len(session.symbols),
            is_stripped=session.artifact.is_stripped,
            created_at=session.created_at.isoformat(),
            artifact=session.artifact,
        )
    except (ArtifactNotFoundError, FileNotFoundError) as e:
        raise FileNotFoundError(f"Artifact not found: {e}") from e
    except (UnsupportedArtifactError, ValueError) as e:
        raise ValueError(f"Unsupported binary: {e}") from e
    except Exception as e:
        raise ToolError(f"Failed to open session for '{file_path}': {e}") from e


@mcp.tool()
def close_session(session_id: str) -> SessionCloseResult:
    """
    Close and release an active reverse engineering session.

    Args:
        session_id: Active session identifier.
    """
    success = global_session_manager.close_session(session_id)
    return SessionCloseResult(
        session_id=session_id,
        closed=success,
        message="Session successfully terminated." if success else "Session was not found or already closed.",
    )


@mcp.tool()
def list_functions(
    session_id: str,
    filter_name: str | None = None,
    min_confidence: float = 0.0,
) -> list[FunctionSummary]:
    """
    List discovered functions in the active binary session.

    Args:
        session_id: Active session identifier.
        filter_name: Optional substring to filter function names.
        min_confidence: Minimum symbol confidence threshold (0.0 to 1.0).
    """
    try:
        session = global_session_manager.get_session(session_id)
        backend = global_session_manager.get_backend(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    # Query backend and cache functions if session.functions is empty
    if not session.functions and backend and hasattr(backend, "get_functions"):
        try:
            discovered = backend.get_functions(session)
            for f in discovered:
                session.functions[f.address] = f
        except Exception as e:
            logger.warning("Failed to recover functions from backend: %s", e)

    results: list[FunctionSummary] = []
    for func in session.functions.values():
        if filter_name and filter_name.lower() not in func.name.lower():
            continue
        if func.confidence_score < min_confidence:
            continue

        top_source = None
        if func.evidence_tag_ids and func.evidence_tag_ids[0] in session.evidence_tags:
            tag = session.evidence_tags[func.evidence_tag_ids[0]]
            top_source = tag.source.value if hasattr(tag.source, "value") else str(tag.source)

        results.append(
            FunctionSummary(
                address=func.address,
                address_int=func.address,
                address_hex=f"0x{func.address:x}",
                name=func.name,
                size=func.size,
                calling_convention=func.calling_convention.value if hasattr(func.calling_convention, "value") else str(func.calling_convention),
                parameter_count=len(func.parameters),
                basic_block_count=len(func.basic_blocks),
                is_stripped=func.is_stripped,
                has_decompiled_code=func.decompiled_code is not None,
                confidence=func.confidence_score,
                top_evidence_source=top_source,
            )
        )
    return results


@mcp.tool()
def disassemble_range(
    session_id: str,
    start_address: int | str,
    size: int = 64,
) -> list[Instruction]:
    """
    Disassemble machine instructions across a designated virtual address range.

    Args:
        session_id: Active session identifier.
        start_address: Start address as integer or hex string.
        size: Number of bytes to disassemble (default 64).
    """
    try:
        session = global_session_manager.get_session(session_id)
        backend = global_session_manager.get_backend(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    start_addr = parse_int_address(start_address)
    byte_count = size or 64

    instructions: list[Instruction] = []
    if backend and hasattr(backend, "disassemble_range"):
        try:
            instructions = backend.disassemble_range(session, start_addr, byte_count)
        except Exception as e:
            raise ToolError(f"Disassembly error at 0x{start_addr:x}: {e}") from e
    else:
        for f in session.functions.values():
            for bb in f.basic_blocks:
                for ins in bb.instructions:
                    if start_addr <= ins.address < start_addr + byte_count:
                        instructions.append(ins)

    return instructions


@mcp.tool()
def disassemble(
    session_id: str,
    address: int | str,
    size: int | None = 64,
) -> DisassemblyResult:
    """
    Disassemble machine instructions starting at a given address.

    Args:
        session_id: Active session identifier.
        address: Start address as integer or hex string (e.g. 0x401000 or "0x401000").
        size: Number of bytes to disassemble (default 64).
    """
    start_addr = parse_int_address(address)
    byte_count = size or 64
    instructions = disassemble_range(session_id, start_addr, byte_count)

    return DisassemblyResult(
        session_id=session_id,
        start_address=f"0x{start_addr:x}",
        instruction_count=len(instructions),
        instructions=instructions,
    )


@mcp.tool()
def get_cfg(
    session_id: str,
    function_address: int | str | None = None,
) -> dict[str, Any]:
    """
    Retrieve control flow graph (nodes and edges) for the whole binary or a specific function.

    Args:
        session_id: Active session identifier.
        function_address: Optional function address (int or hex string).
    """
    try:
        session = global_session_manager.get_session(session_id)
        backend = global_session_manager.get_backend(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    func_addr = parse_int_address(function_address) if function_address is not None else None

    if backend and hasattr(backend, "get_cfg"):
        try:
            return backend.get_cfg(session, func_addr)
        except Exception as e:
            raise ToolError(f"Failed to generate CFG: {e}") from e

    # Fallback from session functions if backend lacks get_cfg
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for fn in session.functions.values():
        if func_addr is not None and fn.address != func_addr:
            continue
        for bb in fn.basic_blocks:
            nodes.append({
                "id": bb.id,
                "address": bb.start_address,
                "size": bb.size,
            })
    return {"nodes": nodes, "edges": edges}


@mcp.tool()
def decompile(
    session_id: str,
    function_address: int | str,
) -> DecompiledFunctionResult:
    """
    Decompile a targeted function into structured high-level pseudocode with evidence annotations.

    Args:
        session_id: Active session identifier.
        function_address: Entry address of the function as integer or hex string.
    """
    try:
        session = global_session_manager.get_session(session_id)
        backend = global_session_manager.get_backend(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    func_addr = parse_int_address(function_address)
    func = session.functions.get(func_addr)

    # 1. Check existing decompiled cache
    if func and func.decompiled_code:
        if isinstance(func.decompiled_code, DecompiledCode):
            return DecompiledFunctionResult(
                session_id=session_id,
                function_address=f"0x{func_addr:x}",
                function_name=func.name,
                language=func.decompiled_code.language,
                source_code=func.decompiled_code.source_code,
                decompiled_code=func.decompiled_code.source_code,
                evidence_annotations=func.decompiled_code.evidence_annotations,
                confidence_score=func.confidence_score,
            )
        elif isinstance(func.decompiled_code, str):
            return DecompiledFunctionResult(
                session_id=session_id,
                function_address=f"0x{func_addr:x}",
                function_name=func.name,
                language="c",
                source_code=func.decompiled_code,
                decompiled_code=func.decompiled_code,
                evidence_annotations=[],
                confidence_score=func.confidence_score,
            )

    # 2. Invoke backend decompiler
    if backend and hasattr(backend, "decompile_function"):
        try:
            decomp = backend.decompile_function(session, func_addr)
            if decomp:
                if func:
                    func.decompiled_code = decomp
                return DecompiledFunctionResult(
                    session_id=session_id,
                    function_address=f"0x{func_addr:x}",
                    function_name=func.name if func else f"sub_{func_addr:x}",
                    language=decomp.language,
                    source_code=decomp.source_code,
                    decompiled_code=decomp.source_code,
                    evidence_annotations=decomp.evidence_annotations,
                    confidence_score=func.confidence_score if func else 0.5,
                )
        except Exception as e:
            raise ToolError(f"Decompilation engine failure at 0x{func_addr:x}: {e}") from e

    raise ToolError(f"Function at 0x{func_addr:x} not found or decompilation unavailable.")


@mcp.tool()
def query_evidence(
    session_id: str,
    symbol_or_addr: str = "all",
    source: str | None = None,
    min_confidence: float = 0.0,
) -> list[EvidenceTag]:
    """
    Query immutable provenance and evidence tags for a symbol, function, or address.

    Args:
        session_id: Active session identifier.
        symbol_or_addr: Symbol name (e.g. 'main.validate'), hex address ('0x401120'), or 'all'/'*' for all tags.
        source: Optional filter by EvidenceSource (e.g. 'GO_PCLNTAB', 'CPP_RTTI', 'FORMAT_STRING', 'syscall_propagation').
        min_confidence: Minimum confidence threshold (0.0 to 1.0).
    """
    try:
        session = global_session_manager.get_session(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    clean_query = symbol_or_addr.strip() if symbol_or_addr else "all"

    matched_tags: list[EvidenceTag] = []
    seen_tag_ids: set[str] = set()

    def add_tag(t: EvidenceTag) -> None:
        if t.tag_id not in seen_tag_ids:
            seen_tag_ids.add(t.tag_id)
            matched_tags.append(t)

    if clean_query.lower() in ("all", "*", ""):
        for t in session.evidence_tags.values():
            add_tag(t)
    else:
        addr_val: int | None = None
        with contextlib.suppress(Exception):
            addr_val = extract_address_from_target_id(clean_query)
        if addr_val is None:
            with contextlib.suppress(Exception):
                addr_val = parse_int_address(clean_query)

        query_lower = clean_query.lower()
        stripped_query = clean_query.split(":", 1)[-1].strip().lower() if ":" in clean_query else query_lower

        for tag in session.evidence_tags.values():
            if tag.tag_id == clean_query:
                add_tag(tag)
                continue
            if tag.target_id == clean_query or tag.target_id.lower() == query_lower:
                add_tag(tag)
                continue
            tag_addr = extract_address_from_target_id(tag.target_id)
            if addr_val is not None and tag_addr is not None and tag_addr == addr_val:
                add_tag(tag)
                continue
            if tag.suggested_name and (tag.suggested_name.lower() == query_lower or tag.suggested_name.lower() == stripped_query):
                add_tag(tag)
                continue
            target_name = tag.target_id.split(":", 1)[-1].strip().lower() if ":" in tag.target_id else tag.target_id.lower()
            if target_name in (query_lower, stripped_query):
                add_tag(tag)
                continue

        sym = session.symbols.get(clean_query) or session.symbols.get(stripped_query)
        if not sym and addr_val is not None and addr_val in session.symbols_by_address:
            sym = session.symbols_by_address[addr_val]
        if sym:
            for t in sym.evidence_tags:
                add_tag(t)
            for tid in sym.evidence_tag_ids:
                if tid in session.evidence_tags:
                    add_tag(session.evidence_tags[tid])

        if addr_val is not None and addr_val in session.functions:
            func = session.functions[addr_val]
            for tid in func.evidence_tag_ids:
                if tid in session.evidence_tags:
                    add_tag(session.evidence_tags[tid])

    # Filter by source if provided
    filtered_results: list[EvidenceTag] = []
    source_lower = source.lower().strip() if source else None

    for t in matched_tags:
        if min_confidence > 0.0 and t.confidence < min_confidence:
            continue
        if source_lower:
            src_val = t.source.value.lower() if hasattr(t.source, "value") else str(t.source).lower()
            src_name = t.source.name.lower() if hasattr(t.source, "name") else ""
            ev_type = str(t.evidence_type).lower() if t.evidence_type else ""
            match_set = {src_val, src_name, ev_type}
            if any(k in match_set for k in ("syscall_abi", "syscall_propagation", "syscall_inference")):
                match_set.update({"syscall_abi", "syscall_propagation", "syscall_inference"})
            if source_lower not in match_set:
                continue
        filtered_results.append(t)

    return sorted(filtered_results, key=lambda t: (t.confidence, t.is_immutable), reverse=True)


@mcp.tool()
def rename_symbol(
    session_id: str,
    address: int | str,
    new_name: str,
    reason: str | None = None,
) -> MutationResult:
    """
    Interactively rename a symbol in the session and underlying decompiler database.

    Args:
        session_id: Active session identifier.
        address: Target address of the symbol.
        new_name: New identifier name.
        reason: Optional justification for provenance tracking.
    """
    try:
        session = global_session_manager.get_session(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    from metis_reverse.equivalence.mutator import SessionMutator
    mutator = SessionMutator(global_session_manager)
    return mutator.rename_symbol(session=session, address=address, new_name=new_name, reason=reason)


@mcp.tool()
def update_variable_type(
    session_id: str,
    function_address: int | str,
    var_name: str,
    new_type: str,
    reason: str | None = None,
) -> MutationResult:
    """
    Update type of local variable or parameter in decompiler database and AST.

    Args:
        session_id: Active session identifier.
        function_address: Address of function containing variable.
        var_name: Name of target variable or parameter.
        new_type: New C type definition (e.g. 'uint32_t', 'ServiceConfig*').
        reason: Optional justification for provenance tracking.
    """
    try:
        session = global_session_manager.get_session(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    from metis_reverse.equivalence.mutator import SessionMutator
    mutator = SessionMutator(global_session_manager)
    return mutator.update_variable_type(
        session=session,
        function_address=function_address,
        var_name=var_name,
        new_type=new_type,
        reason=reason,
    )


@mcp.tool()
def define_struct(
    session_id: str,
    struct_name: str,
    fields: dict[str, str],
    is_packed: bool = False,
    reason: str | None = None,
) -> MutationResult:
    """
    Register custom composite struct definition with automatic offset & size calculation.

    Args:
        session_id: Active session identifier.
        struct_name: Struct name (e.g. 'ServiceConfig').
        fields: Mapping of field names to C types (e.g. {'magic': 'uint32_t', 'port': 'uint32_t'}).
        is_packed: Whether struct is __attribute__((packed)).
        reason: Optional justification for provenance tracking.
    """
    try:
        session = global_session_manager.get_session(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    from metis_reverse.equivalence.mutator import SessionMutator
    mutator = SessionMutator(global_session_manager)
    return mutator.define_struct(
        session=session,
        struct_name=struct_name,
        fields=fields,
        is_packed=is_packed,
        reason=reason,
    )


@mcp.tool()
def recompile_and_verify(
    session_id: str,
    reconstructed_source: str,
    compiler: str = "clang",
    test_vectors: list[dict[str, Any]] | None = None,
) -> RecompileResult:
    """
    Compile reconstructed C source code in an isolated sandbox and perform closed-loop verification.

    Args:
        session_id: Active session identifier.
        reconstructed_source: Complete C source code.
        compiler: Target compiler binary ("clang" or "gcc").
        test_vectors: Optional list of test vectors (cli_args, stdin_data, etc.).
    """
    from metis_reverse.equivalence.recompilation import (
        recompile_and_verify as _recompile_and_verify,
    )
    return _recompile_and_verify(
        session_id=session_id,
        reconstructed_source=reconstructed_source,
        compiler=compiler,
        test_vectors=test_vectors,
    )


@mcp.tool()
def run_differential_test(
    session_id: str,
    original_path: str,
    reconstructed_binary_path: str,
    test_vectors: list[dict[str, Any]],
    timeout_sec: float | None = None,
    sanitize_pattern: str | None = None,
) -> DifferentialResult:
    """
    Execute black-box differential testing comparing stdout, stderr, and exit codes.

    Args:
        session_id: Active session identifier.
        original_path: Path to original binary.
        reconstructed_binary_path: Path to reconstructed/recompiled binary.
        test_vectors: List of test vector dictionaries (cli_args, stdin_data, etc.).
        timeout_sec: Optional timeout per vector in seconds.
        sanitize_pattern: Optional extra regex pattern to mask in output.
    """
    if not os.path.exists(original_path):
        raise ToolError(f"Original binary not found: '{original_path}'")
    if not os.path.exists(reconstructed_binary_path):
        raise ToolError(f"Reconstructed binary not found: '{reconstructed_binary_path}'")

    from metis_reverse.equivalence.differential import DifferentialTester
    tester = DifferentialTester(timeout_seconds=timeout_sec or 5.0)

    try:
        return tester.run_differential_test(
            session_id=session_id,
            original_path=original_path,
            reconstructed_path=reconstructed_binary_path,
            test_vectors=test_vectors,
            timeout_sec=timeout_sec,
            sanitize_pattern=sanitize_pattern,
        )
    except Exception as e:
        raise ToolError(f"Differential testing error: {e}") from e


@mcp.tool()
def trace_function(
    session_id: str,
    function_address: int | str,
    args: list[Any] | None = None,
    prober: str = "auto",
    timeout_seconds: float = 5.0,
    max_instructions: int = 100000,
) -> TraceResult:
    """
    Execute dynamic tracing or micro-emulation on a targeted function.

    Captures runtime argument values, return values, memory access events,
    and dereferenced strings, and backfills concrete evidence tags into
    the session evidence store.

    Args:
        session_id: Active session identifier.
        function_address: Virtual address of the target function (integer or hex string).
        args: Concrete positional argument values to inject into registers/stack.
        prober: Prober backend engine: 'auto' (default), 'frida', or 'unicorn'.
    """
    try:
        session = global_session_manager.get_session(session_id)
    except SessionNotFoundError as e:
        raise ToolError(str(e)) from e

    func_addr = parse_int_address(function_address)
    arg_list = args or []
    prober_choice = (prober or "auto").strip().lower()

    # 1. Prober Resolution
    selected_prober: Any = None
    if prober_choice == "frida":
        try:
            from metis_reverse.dynamic.frida_prober import FridaProber
            selected_prober = FridaProber()
        except Exception as e:
            raise ToolError(f"FridaProber initialization failed: {e}") from e
    elif prober_choice == "unicorn":
        try:
            from metis_reverse.dynamic.unicorn_prober import UnicornProber
            selected_prober = UnicornProber()
        except Exception as e:
            raise ToolError(f"UnicornProber initialization failed: {e}") from e
    elif prober_choice == "auto":
        from metis_reverse.dynamic.prober_base import is_host_native_compatible
        is_native = is_host_native_compatible(session.artifact)

        if is_native:
            try:
                from metis_reverse.dynamic.frida_prober import FridaProber
                fp = FridaProber()
                if fp.is_available(session):
                    selected_prober = fp
            except Exception as e:
                logger.info("Frida prober unavailable in auto mode (%s); falling back to Unicorn", e)

        if selected_prober is None:
            try:
                from metis_reverse.dynamic.unicorn_prober import UnicornProber
                selected_prober = UnicornProber()
            except Exception as e:
                raise ToolError(f"Failed to initialize Unicorn fallback prober: {e}") from e
    else:
        raise ToolError(f"Unknown prober type '{prober}'. Supported: 'auto', 'frida', 'unicorn'.")

    # 2. Execute Trace
    try:
        result = selected_prober.trace_function(
            session,
            func_addr,
            args=arg_list,
            timeout_seconds=timeout_seconds,
            max_instructions=max_instructions,
        )
    except Exception as e:
        # If in auto mode and Frida failed at runtime, attempt Unicorn fallback
        if prober_choice == "auto" and getattr(selected_prober, "name", "") != "unicorn":
            logger.warning("Frida trace failed (%s); seamlessly falling back to UnicornProber", e)
            try:
                from metis_reverse.dynamic.unicorn_prober import UnicornProber
                unicorn_prober = UnicornProber()
                result = unicorn_prober.trace_function(
                    session,
                    func_addr,
                    args=arg_list,
                    timeout_seconds=timeout_seconds,
                    max_instructions=max_instructions,
                )
            except Exception as fallback_err:
                raise ToolError(f"Dynamic tracing failed on 0x{func_addr:x}: {fallback_err}") from fallback_err
        else:
            raise ToolError(f"Dynamic tracing failed on 0x{func_addr:x}: {e}") from e

    # 3. Dynamic-to-Static Fact Backfill
    if result and result.success:
        try:
            from metis_reverse.dynamic.backfiller import FactBackfiller
            backfiller = FactBackfiller()
            backfiller.backfill(session, result, func_addr, arg_list)
        except Exception as e:
            logger.warning("Fact backfilling encountered warning: %s", e)

    return result



# ============================================================================
# CLI & Server Runner
# ============================================================================

def main() -> None:
    """Server CLI entrypoint supporting stdio and SSE modes."""
    parser = argparse.ArgumentParser(
        description="Metis Reverse FastMCP Server",
        prog="metis-reverse",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="MCP communication transport (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP/SSE bind host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="HTTP/SSE bind port (default: 8000)",
    )

    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
