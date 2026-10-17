"""
Metis Reverse - Interactive Decompiler Database Mutator
Coordinates interactive mutations (rename symbol, update variable type, define struct),
manages cascaded Tree-sitter AST pseudocode updates, and enforces strict anti-hallucination
immutability invariants.
"""

from __future__ import annotations

import contextlib
import logging
import re
from typing import Any

from fastmcp.exceptions import ToolError

from metis_reverse.backends.tier1_native.ast_engine import TreeSitterAstEngine
from metis_reverse.core.models import (
    BinarySession,
    DecompiledCode,
    EvidenceSource,
    EvidenceTag,
    Function,
    MutationResult,
    StructDefinition,
    StructField,
    Symbol,
    SymbolType,
    TargetType,
    extract_address_from_target_id,
)
from metis_reverse.core.session import global_session_manager

logger = logging.getLogger("metis_reverse.equivalence.mutator")


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


class TypeLayoutEngine:
    """Computes exact size, alignment, and field offsets for C data types under standard C ABI."""

    PRIMITIVES: dict[str, tuple[int, int]] = {  # (size, alignment)
        "char": (1, 1),
        "int8_t": (1, 1),
        "uint8_t": (1, 1),
        "bool": (1, 1),
        "unsigned char": (1, 1),
        "signed char": (1, 1),
        "short": (2, 2),
        "int16_t": (2, 2),
        "uint16_t": (2, 2),
        "unsigned short": (2, 2),
        "int": (4, 4),
        "uint32_t": (4, 4),
        "int32_t": (4, 4),
        "unsigned int": (4, 4),
        "float": (4, 4),
        "long": (8, 8),
        "unsigned long": (8, 8),
        "long long": (8, 8),
        "unsigned long long": (8, 8),
        "uint64_t": (8, 8),
        "int64_t": (8, 8),
        "double": (8, 8),
        "size_t": (8, 8),
        "ssize_t": (8, 8),
        "uintptr_t": (8, 8),
        "intptr_t": (8, 8),
        "pointer": (8, 8),
        "void*": (8, 8),
    }

    @classmethod
    def resolve_type(
        cls,
        type_str: str,
        bitness: int = 64,
        structs: dict[str, StructDefinition] | None = None,
    ) -> tuple[int, int, bool, int | None]:
        """
        Resolve type string to (size_bytes, alignment_bytes, is_pointer, array_count).
        """
        clean = type_str.strip()
        ptr_size = bitness // 8

        # Pointer check
        if clean.endswith("*") or clean == "pointer" or clean.startswith("void*"):
            return ptr_size, ptr_size, True, None

        # Array check: e.g. char[64], uint32_t[4]
        match = re.match(r"^(.*?)\s*\[(\d+)\]$", clean)
        if match:
            elem_type = match.group(1).strip()
            count = int(match.group(2))
            elem_sz, elem_align, is_ptr, _ = cls.resolve_type(elem_type, bitness, structs)
            return elem_sz * count, elem_align, is_ptr, count

        # Nested struct check
        clean_struct = clean.removeprefix("struct ").strip()
        if structs and clean_struct in structs:
            st = structs[clean_struct]
            return st.total_size, st.alignment, False, None

        # Primitive lookup
        if clean in cls.PRIMITIVES:
            sz, align = cls.PRIMITIVES[clean]
            if bitness == 32 and sz == 8 and clean in ("long", "size_t", "ssize_t", "uintptr_t", "intptr_t"):
                return 4, 4, False, None
            return sz, align, False, None

        # Fallback default: pointer-sized word
        return ptr_size, ptr_size, False, None

    @classmethod
    def compute_layout(
        cls,
        struct_name: str,
        fields_map: dict[str, str],
        bitness: int = 64,
        is_packed: bool = False,
        structs: dict[str, StructDefinition] | None = None,
    ) -> StructDefinition:
        """Calculate struct field offsets, padding, and total size according to C ABI."""
        fields: dict[str, Any] = {}
        curr_offset = 0
        max_align = 1
        offsets: dict[str, int] = {}

        for fname, ftype in fields_map.items():
            sz, align, is_ptr, arr_count = cls.resolve_type(ftype, bitness, structs)
            if not is_packed:
                if align > max_align:
                    max_align = align
                if curr_offset % align != 0:
                    curr_offset += align - (curr_offset % align)

            field = StructField(
                name=fname,
                type_name=ftype,
                offset=curr_offset,
                size=sz,
                alignment=1 if is_packed else align,
                is_pointer=is_ptr,
                array_count=arr_count,
            )
            fields[fname] = field
            offsets[fname] = curr_offset
            curr_offset += sz

        # Tail padding to multiple of max_align
        total_size = curr_offset
        if not is_packed and max_align > 1 and total_size % max_align != 0:
            total_size += max_align - (total_size % max_align)

        return StructDefinition(
            name=struct_name,
            fields=fields,
            size=total_size,
            alignment=1 if is_packed else max_align,
            field_offsets=offsets,
            is_packed=is_packed,
        )


class SessionMutator:
    """
    Central coordinator for interactive DB mutations, cascaded AST updates,
    backend synchronization, and strict immutability validation.
    """

    def __init__(self, session_manager: Any = None) -> None:
        self.session_manager = session_manager or global_session_manager
        self.ast_engine = TreeSitterAstEngine()

    def _get_backend(self, session: BinarySession) -> Any | None:
        if hasattr(self.session_manager, "get_backend"):
            with contextlib.suppress(Exception):
                return self.session_manager.get_backend(session.session_id)
        return None

    def rename_symbol(
        self,
        session: BinarySession,
        address: int | str,
        new_name: str,
        reason: str | None = None,
    ) -> MutationResult:
        """
        Rename function or data symbol across session, backend, and decompiled AST.
        Strictly enforces anti-hallucination immutability.
        """
        addr = parse_int_address(address)
        new_name_clean = new_name.strip()
        if not new_name_clean:
            raise ToolError("New symbol name cannot be empty.")

        sym = session.symbols_by_address.get(addr)
        func = session.functions.get(addr)
        old_name: str = sym.name if sym else (func.name if func else f"sub_{addr:x}")

        # 1. Assert symbol mutability under immutability rules
        self._assert_symbol_mutable(session, addr, sym, func, new_name_clean)

        # 2. Mutate backend if available
        backend = self._get_backend(session)
        backend_ok = True
        if backend and hasattr(backend, "mutate_symbol"):
            try:
                backend_ok = backend.mutate_symbol(session, addr, new_name_clean)
            except Exception as e:
                logger.warning("Backend mutate_symbol warning: %s", e)

        # 3. Mutate session models
        if sym:
            old_sym_name = sym.name
            sym.original_name = sym.original_name or sym.name
            sym.name = new_name_clean
            sym.is_user_mutated = True
            session.symbols.pop(old_sym_name, None)
            session.symbols[new_name_clean] = sym
            session.symbols[addr] = sym
            session.symbols_by_address[addr] = sym
        else:
            new_sym = Symbol(
                address=addr,
                name=new_name_clean,
                type=SymbolType.FUNCTION if func else SymbolType.DATA,
                confidence=0.90,
                is_user_mutated=True,
                original_name=old_name,
            )
            session.add_symbol(new_sym)

        if func:
            func.name = new_name_clean

        # 4. Cascaded AST rewrites across all decompiled functions
        self._cascade_symbol_rename_in_decompiled_code(session, old_name, new_name_clean)

        # 5. Provenance Evidence Tagging
        mutation_tag = EvidenceTag(
            target_type=TargetType.SYMBOL,
            target_id=f"sym:0x{addr:x}",
            suggested_name=new_name_clean,
            source=EvidenceSource.USER_AGENT,
            confidence=0.90,
            raw_anchor=f"user_agent_rename:{reason or 'manual_annotation'}",
            explanation=f"Renamed symbol from '{old_name}' to '{new_name_clean}'. Reason: {reason}",
            is_immutable=False,
        )
        session.attach_evidence(mutation_tag)

        return MutationResult(
            session_id=session.session_id,
            mutation_type="rename_symbol",
            target=f"0x{addr:x}",
            old_value=old_name,
            new_value=new_name_clean,
            success=backend_ok,
            message=f"Symbol at 0x{addr:x} successfully renamed to '{new_name_clean}'.",
        )

    def _assert_symbol_mutable(
        self,
        session: BinarySession,
        addr: int,
        sym: Symbol | None,
        func: Function | None,
        new_name: str,
    ) -> None:
        """Enforces immutability: grounded symbols and immutable suggested names cannot be overwritten."""
        # Sources that strictly lock symbol / function identity
        grounded_sources = {
            EvidenceSource.GO_PCLNTAB,
            EvidenceSource.CPP_RTTI,
            EvidenceSource.ASSERT_MACRO,
            EvidenceSource.DYNAMIC_PROBE,
        }

        # 1. Inspect all tags in session
        for tag in session.evidence_tags.values():
            if not tag.is_immutable:
                continue

            # Skip variable, parameter, and format string tags:
            # - Variable/parameter tags lock variables/parameters, NOT function symbols.
            # - Format string tags infer printf/log argument names/types, NOT function identities.
            if (
                tag.target_type in (TargetType.VARIABLE, TargetType.PARAMETER)
                or ":var:" in tag.target_id
                or ":param:" in tag.target_id
                or tag.source in (
                    EvidenceSource.FORMAT_STRING,
                    EvidenceSource.SYSCALL_ABI,
                    EvidenceSource.SYSCALL_INFERENCE,
                    EvidenceSource.SYSCALL_PROPAGATION,
                    EvidenceSource.LIBC_SEMANTICS,
                )
            ):
                continue

            tag_addr = extract_address_from_target_id(tag.target_id)
            is_target_addr = (tag_addr is not None and tag_addr == addr)

            sym_matches = False
            if sym and sym.name:
                sym_matches = bool(
                    tag.target_id in (sym.name, f"sym:{sym.name}", f"func:{sym.name}")
                    or (tag.suggested_name and tag.suggested_name == sym.name)
                )
            if func and func.name:
                sym_matches = bool(
                    sym_matches
                    or tag.target_id in (func.name, f"sym:{func.name}", f"func:{func.name}")
                    or (tag.suggested_name and tag.suggested_name == func.name)
                )

            if not (is_target_addr or sym_matches):
                continue

            tag_source_str = tag.source.value if hasattr(tag.source, "value") else str(tag.source)

            # Grounded compiler sources or explicit suggested names lock symbol
            is_grounded_source = (tag.source in grounded_sources)
            has_suggested_name = bool(tag.suggested_name)

            if is_grounded_source or has_suggested_name:
                if tag.suggested_name and new_name == tag.suggested_name:
                    continue
                raise ToolError(
                    f"Symbol at 0x{addr:x} is locked by immutable evidence ({tag_source_str}). Renaming forbidden."
                )

        # 2. Check direct tags on sym or func
        tags_to_check = []
        if sym:
            tags_to_check.extend(sym.evidence_tags)
            for tid in sym.evidence_tag_ids:
                if tid in session.evidence_tags:
                    tags_to_check.append(session.evidence_tags[tid])
        if func:
            for tid in func.evidence_tag_ids:
                if tid in session.evidence_tags:
                    tags_to_check.append(session.evidence_tags[tid])

        for t in tags_to_check:
            if not t.is_immutable:
                continue

            if (
                t.target_type in (TargetType.VARIABLE, TargetType.PARAMETER)
                or ":var:" in t.target_id
                or ":param:" in t.target_id
                or t.source in (
                    EvidenceSource.FORMAT_STRING,
                    EvidenceSource.SYSCALL_ABI,
                    EvidenceSource.SYSCALL_INFERENCE,
                    EvidenceSource.SYSCALL_PROPAGATION,
                    EvidenceSource.LIBC_SEMANTICS,
                )
            ):
                continue

            is_grounded = (t.source in grounded_sources)
            has_sugg = bool(t.suggested_name)
            if is_grounded or has_sugg:
                if t.suggested_name and new_name == t.suggested_name:
                    continue
                t_src = t.source.value if hasattr(t.source, "value") else str(t.source)
                raise ToolError(
                    f"Symbol at 0x{addr:x} is locked by immutable evidence ({t_src}). Renaming forbidden."
                )

    def _cascade_symbol_rename_in_decompiled_code(
        self,
        session: BinarySession,
        old_name: str,
        new_name: str,
    ) -> None:
        """Replace occurrences of old symbol name across all decompiled pseudocode."""
        if not old_name or old_name == new_name:
            return

        for func in session.functions.values():
            if not func.decompiled_code:
                continue

            # Support both string and DecompiledCode model
            if hasattr(func.decompiled_code, "code"):
                raw_code = getattr(func.decompiled_code, "code", "")
                code_text = str(raw_code) if raw_code is not None else ""
            else:
                code_text = str(func.decompiled_code or "")

            if not code_text or old_name not in code_text:
                continue

            try:
                updated_code = self.ast_engine.rename_identifier(
                    source_code=code_text,
                    old_name=old_name,
                    new_name=new_name,
                )
            except Exception as e:
                logger.warning("Tree-sitter rename failed, using fallback regex: %s", e)
                pattern = r"\b" + re.escape(old_name) + r"\b"
                updated_code = re.sub(pattern, new_name, code_text)

            if isinstance(func.decompiled_code, DecompiledCode):
                func.decompiled_code.code = updated_code
            else:
                func.decompiled_code = updated_code

    def update_variable_type(
        self,
        session: BinarySession,
        function_address: int | str,
        var_name: str,
        new_type: str,
        reason: str | None = None,
    ) -> MutationResult:
        """
        Update type of local variable or parameter in decompiler database and AST.
        """
        func_addr = parse_int_address(function_address)
        func = session.functions.get(func_addr)
        if not func:
            raise ToolError(f"Function at 0x{func_addr:x} not found in session")

        var_clean = var_name.strip()
        type_clean = new_type.strip()
        if not var_clean:
            raise ToolError("Variable name cannot be empty.")
        if not type_clean:
            raise ToolError("New type cannot be empty.")

        # 1. Immutability validation
        self._assert_variable_mutable(session, func_addr, var_clean, type_clean)

        # 2. Mutate backend
        backend = self._get_backend(session)
        backend_ok = True
        if backend and hasattr(backend, "mutate_type"):
            with contextlib.suppress(Exception):
                backend_ok = backend.mutate_type(session, func_addr, type_clean)

        # 3. Update Function parameters and local variables
        old_type = None
        for param in func.parameters:
            p_name = getattr(param, "name", None) or (param.get("name") if isinstance(param, dict) else None)
            if p_name == var_clean:
                if hasattr(param, "type_name"):
                    old_type = param.type_name
                    param.type_name = type_clean
                elif hasattr(param, "type"):
                    old_type = param.type
                    param.type = type_clean
                elif isinstance(param, dict):
                    old_type = param.get("type_name") or param.get("type")
                    param["type_name"] = type_clean
                    param["type"] = type_clean

        for local_var in func.local_variables:
            if local_var.name == var_clean:
                old_type = local_var.type_name
                local_var.type_name = type_clean

        # 4. Cascaded AST rewrites on decompiled code
        if func.decompiled_code:
            self._cascade_variable_type_in_decompiled_code(func, var_clean, type_clean)

        # 5. Provenance Evidence Tagging
        mutation_tag = EvidenceTag(
            target_type=TargetType.VARIABLE,
            target_id=f"func:0x{func_addr:x}:var:{var_clean}",
            suggested_name=var_clean,
            suggested_type=type_clean,
            source=EvidenceSource.USER_AGENT,
            confidence=0.90,
            raw_anchor=f"user_agent_update_type:{reason or 'manual_annotation'}",
            explanation=f"Updated type of '{var_clean}' at 0x{func_addr:x} to '{type_clean}'. Reason: {reason}",
            is_immutable=False,
        )
        session.attach_evidence(mutation_tag)

        return MutationResult(
            session_id=session.session_id,
            mutation_type="update_variable_type",
            target=f"0x{func_addr:x}:{var_clean}",
            old_value=old_type,
            new_value=type_clean,
            success=backend_ok,
            message=f"Variable '{var_clean}' in function 0x{func_addr:x} retyped to '{type_clean}'.",
        )

    def _assert_variable_mutable(
        self,
        session: BinarySession,
        func_addr: int,
        var_name: str,
        new_type: str,
    ) -> None:
        """Enforces immutability: variables locked by concrete format strings or ABI cannot be corrupted."""
        var_anchor = f"func:0x{func_addr:x}:var:{var_name}"
        param_anchor = f"func:0x{func_addr:x}:param:{var_name}"

        for tag in session.evidence_tags.values():
            if not tag.is_immutable:
                continue

            matches_var = (tag.target_id in (var_anchor, param_anchor)) or (
                tag.target_type in (TargetType.VARIABLE, TargetType.PARAMETER)
                and tag.suggested_name == var_name
                and extract_address_from_target_id(tag.target_id) == func_addr
            )

            if matches_var:
                tag_source_str = tag.source.value if hasattr(tag.source, "value") else str(tag.source)
                if not tag.suggested_type or tag.suggested_type != new_type:
                    raise ToolError(
                        f"Variable '{var_name}' at 0x{func_addr:x} is locked by immutable evidence ({tag_source_str}). Retyping forbidden."
                    )

    def _cascade_variable_type_in_decompiled_code(
        self,
        func: Function,
        var_name: str,
        new_type: str,
    ) -> None:
        """Rewrite variable or parameter type declarations in C code."""
        if hasattr(func.decompiled_code, "code"):
            raw_code = getattr(func.decompiled_code, "code", "")
            code_text = str(raw_code) if raw_code is not None else ""
        else:
            code_text = str(func.decompiled_code or "")

        if not code_text:
            return

        try:
            tree = self.ast_engine.parse_c_code(code_text)
            source_bytes = bytearray(code_text.encode("utf-8"))
            replacements: list[tuple[int, int, str]] = []

            def unwrap_declarator(node: Any) -> tuple[Any | None, bool, Any | None]:
                """Extract (ident_node, is_pointer, ptr_node) from declarator node."""
                is_ptr = False
                ptr_node = None
                curr = node
                while curr is not None:
                    if curr.type == "pointer_declarator":
                        is_ptr = True
                        if ptr_node is None:
                            ptr_node = curr
                        next_c = None
                        for c in curr.children:
                            if c.type in (
                                "pointer_declarator",
                                "identifier",
                                "array_declarator",
                                "parenthesized_declarator",
                            ):
                                next_c = c
                                break
                        curr = next_c
                    elif curr.type == "init_declarator":
                        next_c = None
                        for c in curr.children:
                            if c.type in (
                                "pointer_declarator",
                                "identifier",
                                "array_declarator",
                            ):
                                next_c = c
                                break
                        curr = next_c
                    elif curr.type == "identifier":
                        return curr, is_ptr, ptr_node
                    else:
                        break
                return None, is_ptr, ptr_node

            def walk(node: Any) -> None:
                if node.type in ("parameter_declaration", "declaration"):
                    type_nodes: list[Any] = []
                    declarators: list[tuple[Any, Any, bool, Any | None]] = []

                    for child in node.children:
                        if child.type in (
                            "primitive_type",
                            "type_identifier",
                            "sized_type_specifier",
                            "struct_specifier",
                            "union_specifier",
                            "enum_specifier",
                            "type_qualifier",
                        ):
                            type_nodes.append(child)
                        elif child.type in (
                            "identifier",
                            "pointer_declarator",
                            "init_declarator",
                            "declarator",
                        ):
                            ident, is_ptr, ptr_node = unwrap_declarator(child)
                            if ident:
                                declarators.append((child, ident, is_ptr, ptr_node))

                    if type_nodes and declarators:
                        first_type = type_nodes[0]
                        last_type = type_nodes[-1]
                        clean_new = new_type.strip()

                        for _decl_child, ident_node, is_ptr, ptr_node in declarators:
                            i_name = source_bytes[
                                ident_node.start_byte : ident_node.end_byte
                            ].decode("utf-8")
                            if i_name == var_name:
                                if clean_new.endswith("*"):
                                    if len(declarators) == 1:
                                        repl_str = (
                                            clean_new
                                            if clean_new.endswith(" ")
                                            else f"{clean_new} "
                                        )
                                        replacements.append(
                                            (first_type.start_byte, ident_node.start_byte, repl_str)
                                        )
                                    else:
                                        if is_ptr and ptr_node:
                                            replacements.append(
                                                (ptr_node.start_byte, ident_node.start_byte, "")
                                            )
                                        replacements.append(
                                            (first_type.start_byte, last_type.end_byte, clean_new.rstrip("*").strip())
                                        )
                                else:
                                    replacements.append(
                                        (first_type.start_byte, last_type.end_byte, clean_new)
                                    )

                for child in node.children:
                    walk(child)

            walk(tree.root_node)

            if replacements:
                replacements.sort(key=lambda r: r[0], reverse=True)
                for start_b, end_b, repl in replacements:
                    source_bytes[start_b:end_b] = repl.encode("utf-8")
                updated_code = source_bytes.decode("utf-8")
            else:
                # Regex fallback for declaration: e.g. "int port;" or "void *port;"
                pattern = r"(\b(?:unsigned\s+|signed\s+)?[a-zA-Z_][a-zA-Z0-9_]*\s*\*?\s*)(\b" + re.escape(var_name) + r"\b)"
                updated_code = re.sub(pattern, rf"{new_type} \2", code_text)

        except Exception as e:
            logger.warning("Tree-sitter type rewrite failed, using regex fallback: %s", e)
            pattern = r"(\b(?:unsigned\s+|signed\s+)?[a-zA-Z_][a-zA-Z0-9_]*\s*\*?\s*)(\b" + re.escape(var_name) + r"\b)"
            updated_code = re.sub(pattern, rf"{new_type} \2", code_text)

        if isinstance(func.decompiled_code, DecompiledCode):
            func.decompiled_code.code = updated_code
        else:
            func.decompiled_code = updated_code

    def define_struct(
        self,
        session: BinarySession,
        struct_name: str,
        fields: dict[str, str],
        is_packed: bool = False,
        reason: str | None = None,
    ) -> MutationResult:
        """
        Define custom composite struct layout, compute field offsets, and register in session.
        """
        clean_name = struct_name.strip()
        if not clean_name:
            raise ToolError("Struct name cannot be empty.")
        if not fields:
            raise ToolError("Struct definition must contain at least one field.")

        # 1. Assert mutability
        struct_anchor = f"struct:{clean_name}"
        for tag in session.evidence_tags.values():
            if tag.is_immutable and tag.target_id == struct_anchor:
                tag_source_str = tag.source.value if hasattr(tag.source, "value") else str(tag.source)
                raise ToolError(
                    f"Struct '{clean_name}' is locked by immutable evidence ({tag_source_str}). Redefinition forbidden."
                )

        # 2. Compute Layout
        bitness = session.artifact.bitness if session.artifact else 64
        struct_def = TypeLayoutEngine.compute_layout(
            struct_name=clean_name,
            fields_map=fields,
            bitness=bitness,
            is_packed=is_packed,
            structs=session.struct_definitions,
        )

        # 3. Register in Session
        session.define_struct(struct_def)

        # 4. Provenance Evidence Tagging
        mutation_tag = EvidenceTag(
            target_type=TargetType.TYPE,
            target_id=struct_anchor,
            suggested_name=clean_name,
            source=EvidenceSource.USER_AGENT,
            confidence=0.90,
            raw_anchor=f"user_agent_define_struct:size={struct_def.total_size}",
            explanation=f"Defined struct '{clean_name}' with {len(fields)} fields ({struct_def.total_size} bytes). Reason: {reason}",
            is_immutable=False,
        )
        session.attach_evidence(mutation_tag)

        return MutationResult(
            session_id=session.session_id,
            mutation_type="define_struct",
            target=clean_name,
            old_value=None,
            new_value=f"struct {clean_name} (size: {struct_def.total_size})",
            success=True,
            message=f"Struct '{clean_name}' successfully defined ({struct_def.total_size} bytes, alignment {struct_def.alignment}).",
        )
