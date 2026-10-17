"""
metis_reverse.backends.tier1_native.backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unified Tier 1 Native Backend coordinating LIEF, Capstone, Angr, and Tree-sitter.
"""

from __future__ import annotations

import os
from typing import Any

from metis_reverse.backends.base import (
    BaseBackend,
    DecompilationError,
    UnsupportedArtifactError,
)
from metis_reverse.backends.tier1_native.ast_engine import TreeSitterAstEngine
from metis_reverse.backends.tier1_native.binary_parser import LiefBinaryParser
from metis_reverse.backends.tier1_native.decompiler import AngrDecompilerEngine
from metis_reverse.backends.tier1_native.disassembler import CapstoneDisassembler
from metis_reverse.core.evidence import EvidenceStore
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySession,
    DecompiledCode,
    Function,
    Instruction,
    Symbol,
    SymbolType,
    TargetArtifact,
)


class Tier1NativeBackend(BaseBackend):
    """
    Tier 1 Native Reverse Engineering Engine.
    Self-contained, cross-platform, zero external dependencies on Ghidra/IDA/JVM.
    """

    def __init__(self) -> None:
        self._parser = LiefBinaryParser()
        self._disassembler: CapstoneDisassembler | None = None
        self._decompiler: AngrDecompilerEngine | None = None
        self._ast_engine = TreeSitterAstEngine()
        self._active_session: BinarySession | None = None
        self._artifact: TargetArtifact | None = None

    @property
    def name(self) -> str:
        return "Tier1-Native-LIEF-Capstone-Angr"

    @property
    def tier(self) -> int:
        return 1

    def load_artifact(
        self, artifact_or_path: str | TargetArtifact
    ) -> tuple[TargetArtifact, BinarySession]:
        """Parse binary headers, sections, symbols, and initialize a new BinarySession."""
        if isinstance(artifact_or_path, TargetArtifact):
            artifact = artifact_or_path
            abs_path = artifact.file_path
            parsed_art, initial_symbols, strings = self._parser.parse(abs_path)
            if not artifact.sections:
                artifact.sections = parsed_art.sections
        else:
            abs_path = str(artifact_or_path)
            artifact, initial_symbols, strings = self._parser.parse(abs_path)

        # Defense-in-depth: reject native binaries with 0 sections or unknown architecture
        if (not artifact.sections or artifact.architecture == ArchitectureType.UNKNOWN) and artifact.format in (
            ArtifactFormat.ELF,
            ArtifactFormat.MACHO,
            ArtifactFormat.PE,
        ):
            raise UnsupportedArtifactError(
                f"Malformed binary has no valid sections or unknown architecture: {abs_path}"
            )

        self._artifact = artifact

        # Initialize Capstone disassembler
        self._disassembler = CapstoneDisassembler(
            arch=artifact.architecture, bitness=artifact.bitness
        )

        # Initialize Angr decompiler engine lazily
        self._decompiler = AngrDecompilerEngine(artifact.file_path)

        import uuid

        # Create session
        session = BinarySession(
            session_id=f"sess_{uuid.uuid4().hex[:12]}",
            artifact=artifact,
            backend_type=self.name,
            evidence_store=EvidenceStore(),
        )

        for sym in initial_symbols:
            session.add_symbol(sym)

        self._active_session = session
        return artifact, session

    def disassemble_range(
        self, session: BinarySession, start_addr: int, size: int
    ) -> list[Instruction]:
        """Perform linear sweep disassembly across a designated virtual address range."""
        if self._disassembler is None:
            self._disassembler = CapstoneDisassembler(
                arch=session.artifact.architecture, bitness=session.artifact.bitness
            )

        raw_bytes = self._read_bytes_at_va(session, start_addr, size)
        if not raw_bytes:
            # Fallback: read directly from binary file at start_addr or base offset
            try:
                with open(session.artifact.file_path, "rb") as f:
                    f.seek(max(0, start_addr - session.artifact.base_address))
                    raw_bytes = f.read(size)
            except Exception:
                pass

        return self._disassembler.disassemble_bytes(raw_bytes, start_addr)

    def disassemble_function(
        self, session: BinarySession, func_addr: int
    ) -> list[Instruction]:
        """Disassemble all basic blocks belonging to a recovered function."""
        func = self.get_function(session, func_addr)
        func_size = func.size if func and func.size > 0 else 64
        return self.disassemble_range(session, func_addr, func_size)

    def get_functions(self, session: BinarySession) -> list[Function]:
        """Enumerate all discovered functions in the binary."""
        if not session.functions:
            if self._decompiler is None and session.artifact:
                self._decompiler = AngrDecompilerEngine(session.artifact.file_path)

            if self._decompiler is not None:
                try:
                    recovered = self._decompiler.recover_functions()
                    for addr, f in recovered.items():
                        session.functions[addr] = f
                except Exception:
                    pass

        # Ensure discovered functions from symbols are included
        for sym in session.symbols.values():
            if (
                sym.type == SymbolType.FUNCTION
                and sym.address > 0
                and sym.address not in session.functions
            ):
                session.functions[sym.address] = Function(
                        id=f"func_0x{sym.address:x}",
                        name=sym.name,
                        address=sym.address,
                        size=sym.size,
                    )

        return list(session.functions.values())

    def close(self) -> None:
        """Release decompiler engine, disassembler, and active session references."""
        if self._decompiler is not None:
            self._decompiler.close()
            self._decompiler = None
        self._disassembler = None
        self._active_session = None
        self._artifact = None

    def get_function(self, session: BinarySession, address: int) -> Function | None:
        """Retrieve a specific function by address, including basic blocks and parameters."""
        if address in session.functions:
            return session.functions[address]

        self.get_functions(session)
        return session.functions.get(address)

    def get_cfg(
        self, session: BinarySession, func_addr: int | None = None
    ) -> dict[str, Any]:
        """Retrieve control flow graph (basic blocks and directional edges)."""
        if self._decompiler is None and session.artifact:
            self._decompiler = AngrDecompilerEngine(session.artifact.file_path)

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        if self._decompiler is not None:
            try:
                cfg_model = self._decompiler.cfg.model
                if func_addr is not None:
                    if func_addr in self._decompiler.cfg.kb.functions:
                        func = self._decompiler.cfg.kb.functions[func_addr]
                        for block in getattr(func, "blocks", []):
                            nodes.append({
                                "id": f"bb_0x{block.addr:x}",
                                "address": block.addr,
                                "size": block.size,
                                "instruction_count": getattr(block, "instructions", 0),
                            })
                        if hasattr(func, "graph") and func.graph:
                            for src, dst, data in func.graph.edges(data=True):
                                edges.append({
                                    "source": src.addr,
                                    "target": dst.addr,
                                    "type": str(data.get("type", "jump")),
                                })
                else:
                    for node in cfg_model.nodes():
                        nodes.append({
                            "id": f"bb_0x{node.addr:x}",
                            "address": node.addr,
                            "size": getattr(node, "size", 0),
                        })
            except Exception:
                pass

        if not nodes:
            # Fallback: build from session functions and basic blocks
            for fn in session.functions.values():
                for bb in fn.basic_blocks:
                    nodes.append({
                        "id": bb.id,
                        "address": bb.start_address,
                        "size": bb.size,
                    })

        return {"nodes": nodes, "edges": edges}

    def decompile_function(
        self, session: BinarySession, func_addr: int
    ) -> DecompiledCode:
        """Decompile a function into structured C pseudocode with AST mappings."""
        if self._decompiler is None and session.artifact:
            self._decompiler = AngrDecompilerEngine(session.artifact.file_path)

        if self._decompiler is None:
            raise DecompilationError("Decompiler not initialized.")

        dec_code = self._decompiler.decompile(func_addr)
        func = self.get_function(session, func_addr)
        if func:
            func.decompiled_code = dec_code

        return dec_code

    def get_xrefs(
        self, session: BinarySession, target_addr: int
    ) -> dict[str, list[int]]:
        """Retrieve code and data references to a given address."""
        if self._decompiler is None and session.artifact:
            self._decompiler = AngrDecompilerEngine(session.artifact.file_path)

        code_xrefs: list[int] = []
        data_xrefs: list[int] = []

        if self._decompiler is not None:
            try:
                cfg = self._decompiler.cfg
                if target_addr in cfg.model.nodes():
                    node = cfg.model.get_any_node(target_addr)
                    if node:
                        for pred in cfg.model.graph.predecessors(node):
                            code_xrefs.append(pred.addr)
            except Exception:
                pass

        return {"code_xrefs": code_xrefs, "data_xrefs": data_xrefs}

    def mutate_symbol(
        self, session: BinarySession, addr: int, new_name: str
    ) -> bool:
        """Rename a symbol in the backend and session symbol table."""
        old_name: str | None = None

        if addr in session.symbols_by_address:
            sym = session.symbols_by_address[addr]
            old_name = sym.name
            sym.original_name = sym.original_name or sym.name
            sym.name = new_name
            session.symbols.pop(old_name, None)
            session.symbols[new_name] = sym
            session.symbols[addr] = sym
            session.symbols_by_address[addr] = sym
        elif addr in session.symbols:
            sym = session.symbols[addr]
            old_name = sym.name
            sym.name = new_name
            session.symbols.pop(old_name, None)
            session.symbols[new_name] = sym
            session.symbols[addr] = sym
            session.symbols_by_address[addr] = sym
        else:
            sym = Symbol(
                address=addr,
                name=new_name,
                type=SymbolType.FUNCTION,
                size=32,
                confidence=1.0,
            )
            session.add_symbol(sym)
            session.symbols[addr] = sym

        if addr in session.functions:
            func = session.functions[addr]
            func.name = new_name
            if func.decompiled_code:
                if isinstance(func.decompiled_code, DecompiledCode):
                    if old_name:
                        func.decompiled_code.source_code = self._ast_engine.rename_identifier(
                            func.decompiled_code.source_code, old_name, new_name
                        )
                elif isinstance(func.decompiled_code, str) and old_name:
                    func.decompiled_code = self._ast_engine.rename_identifier(
                        func.decompiled_code, old_name, new_name
                    )

        return True

    def mutate_type(
        self, session: BinarySession, addr: int, new_type: str
    ) -> bool:
        """Update the type signature of a function, variable, or memory slot."""
        func = self.get_function(session, addr)
        if func:
            func.return_type = new_type
            return True
        return False

    def export_database(
        self, session: BinarySession, output_path: str
    ) -> bool:
        """Export session JSON state."""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(session.model_dump_json(indent=2))
        return True

    def _read_bytes_at_va(
        self, session: BinarySession, virtual_addr: int, size: int
    ) -> bytes:
        """Helper to map virtual address to raw file offset and read bytes."""
        artifact = session.artifact
        if not artifact or not os.path.exists(artifact.file_path):
            return b""

        # Locate section containing virtual_addr
        for sec in artifact.sections:
            if sec.virtual_address <= virtual_addr < sec.virtual_address + sec.virtual_size:
                delta = virtual_addr - sec.virtual_address
                file_offset = sec.raw_offset + delta
                try:
                    with open(artifact.file_path, "rb") as f:
                        f.seek(file_offset)
                        return f.read(size)
                except Exception:
                    pass

        # Fallback: try reading relative to image base
        try:
            with open(artifact.file_path, "rb") as f:
                f.seek(max(0, virtual_addr - artifact.base_address))
                return f.read(size)
        except Exception:
            return b""
