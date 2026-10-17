"""
metis_reverse.backends.tier1_native.decompiler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Angr-powered lazy CFG generation, variable recovery, and native C decompilation.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

import angr

from metis_reverse.backends.base import DecompilationError
from metis_reverse.core.models import (
    CallingConvention,
    DecompiledCode,
    Function,
)

# Silence verbose angr logs
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)


class AngrDecompilerEngine:
    """Manages angr Project, lazy CFGFast, variable recovery, and C decompilation."""

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path
        self._project: angr.Project | None = None
        self._cfg: Any | None = None
        self._decompiled_cache: dict[int, DecompiledCode] = {}

    @property
    def project(self) -> angr.Project:
        """Lazily initialize the angr Project."""
        if self._project is None:
            self._project = angr.Project(self.binary_path, auto_load_libs=False)
        return self._project

    @property
    def cfg(self) -> Any:
        """Lazily generate normalized CFGFast."""
        if self._cfg is None:
            self._cfg = self.project.analyses.CFGFast(normalize=True)
        return self._cfg

    def recover_functions(self) -> dict[int, Function]:
        """Enumerate all functions recovered by CFGFast."""
        functions: dict[int, Function] = {}

        try:
            kb_funcs = self.cfg.kb.functions
        except Exception:
            return functions

        for addr, afunc in kb_funcs.items():
            if getattr(afunc, "is_simprocedure", False) or getattr(afunc, "is_alignment", False):
                continue

            conv = CallingConvention.UNKNOWN
            if getattr(afunc, "calling_convention", None):
                conv_str = str(type(afunc.calling_convention)).lower()
                if "sysv" in conv_str or "amd64" in conv_str:
                    conv = CallingConvention.SYSTEM_V_AMD64
                elif "arm" in conv_str:
                    conv = CallingConvention.ARM64_AAPCS

            callers: list[int] = []
            callees: list[int] = []
            try:
                if hasattr(afunc, "transition_graph") and afunc.transition_graph:
                    if hasattr(afunc, "startpoint_node") and afunc.startpoint_node:
                        callers = [
                            node.addr
                            for node in afunc.transition_graph.predecessors(afunc.startpoint_node)
                            if hasattr(node, "addr")
                        ]
                    callees = [
                        edge[1].addr
                        for edge in afunc.transition_graph.edges()
                        if len(edge) > 1 and hasattr(edge[1], "addr")
                    ]
            except Exception:
                pass

            functions[addr] = Function(
                id=f"func_0x{addr:x}",
                name=afunc.name or f"sub_{addr:x}",
                address=addr,
                size=afunc.size or 0,
                calling_convention=conv,
                return_type="void" if not getattr(afunc, "has_return", True) else "uint64_t",
                parameters=[],
                local_variables=[],
                callers=callers,
                callees=callees,
            )

        return functions

    def decompile(self, func_addr: int) -> DecompiledCode:
        """
        Decompile target function into structured C pseudocode.

        Args:
            func_addr: Entry point address of function.

        Returns:
            DecompiledCode with source_code, line_to_address_map, and address_to_line_map.
        """
        if func_addr in self._decompiled_cache:
            return self._decompiled_cache[func_addr]

        if func_addr not in self.cfg.kb.functions:
            raise DecompilationError(f"Function 0x{func_addr:x} not found in binary CFG.")

        func = self.cfg.kb.functions[func_addr]

        try:
            # 1. Variable Recovery
            with contextlib.suppress(Exception):
                self.project.analyses.VariableRecoveryFast(func)

            # 2. Decompilation analysis
            dec = self.project.analyses.Decompiler(func, cfg=self.cfg.model)
            if not dec.codegen or not dec.codegen.text:
                raise DecompilationError(f"Decompiler produced empty code for function 0x{func_addr:x}")

            source_code = dec.codegen.text

            # 3. Build line <-> address mappings
            line_to_addr, addr_to_line = self._build_source_mappings(dec.codegen, source_code)

            # 4. Extract variable token map
            var_mapping: dict[str, str] = {}
            if hasattr(dec.codegen, "cfunc") and dec.codegen.cfunc:
                if hasattr(dec.codegen.cfunc, "arg_list"):
                    for arg in dec.codegen.cfunc.arg_list:
                        var = getattr(arg, "variable", None)
                        if var and hasattr(var, "name"):
                            var_mapping[var.name] = f"param_{var.name}"

                if hasattr(dec.codegen.cfunc, "unified_local_vars"):
                    for var in dec.codegen.cfunc.unified_local_vars:
                        if hasattr(var, "name"):
                            var_mapping[var.name] = f"var_{var.name}"

            result = DecompiledCode(
                function_address=func_addr,
                function_name=func.name or f"sub_{func_addr:x}",
                language="C",
                source_code=source_code,
                line_to_address_map=line_to_addr,
                address_to_line_map=addr_to_line,
                variable_mapping=var_mapping,
            )

            self._decompiled_cache[func_addr] = result
            return result

        except Exception as e:
            if isinstance(e, DecompilationError):
                raise
            raise DecompilationError(f"Failed to decompile function 0x{func_addr:x}: {e}") from e

    def _build_source_mappings(
        self, codegen: Any, source_code: str
    ) -> tuple[dict[int, list[int]], dict[int, int]]:
        """Compute line number <-> instruction address mapping from codegen posmap."""
        line_to_addr: dict[int, list[int]] = {}
        addr_to_line: dict[int, int] = {}

        line_offsets: list[int] = [0]
        for i, char in enumerate(source_code):
            if char == "\n":
                line_offsets.append(i + 1)

        def pos_to_line(pos: int) -> int:
            for line_idx in range(len(line_offsets) - 1, -1, -1):
                if pos >= line_offsets[line_idx]:
                    return line_idx + 1  # 1-indexed
            return 1

        if hasattr(codegen, "map_pos_to_addr") and codegen.map_pos_to_addr:
            for pos, node in codegen.map_pos_to_addr.items():
                line_num = pos_to_line(pos)
                addr = getattr(node, "addr", None)
                if addr is None and hasattr(node, "tags"):
                    addr = node.tags.get("ins_addr")

                if addr is not None and isinstance(addr, int):
                    if line_num not in line_to_addr:
                        line_to_addr[line_num] = []
                    if addr not in line_to_addr[line_num]:
                        line_to_addr[line_num].append(addr)
                    if addr not in addr_to_line:
                        addr_to_line[addr] = line_num

        return line_to_addr, addr_to_line

    def close(self) -> None:
        """Release Angr project resources, clear knowledge bases and caches."""
        self._decompiled_cache.clear()
        if self._cfg is not None:
            if hasattr(self._cfg, "kb") and self._cfg.kb is not None:
                with contextlib.suppress(Exception):
                    self._cfg.kb.functions.clear()
            self._cfg = None
        if self._project is not None:
            if hasattr(self._project, "kb") and self._project.kb is not None:
                with contextlib.suppress(Exception):
                    self._project.kb.functions.clear()
            if hasattr(self._project, "loader") and self._project.loader is not None:
                with contextlib.suppress(Exception):
                    self._project.loader.close()
            self._project = None

