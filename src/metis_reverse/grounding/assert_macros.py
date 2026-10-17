"""
metis_reverse.grounding.assert_macros
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Assert macro string extraction, condition AST parsing, variable recovery,
and deterministic function de-anonymization.
"""

from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass, field

from metis_reverse.backends.tier1_native.disassembler import CapstoneDisassembler
from metis_reverse.core.models import (
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    Symbol,
    SymbolType,
    TargetType,
)
from metis_reverse.grounding.format_strings import FormatStringGrounder

logger = logging.getLogger("metis_reverse.grounding.assert_macros")


@dataclass
class AssertComparison:
    lhs: str
    base_var: str
    field: str | None
    op: str
    rhs: str
    is_null_check: bool


@dataclass
class AssertCondition:
    raw_condition: str
    expr: str
    diagnostic_tag: str | None
    comparisons: list[AssertComparison] = field(default_factory=list)
    enclosing_function_name: str | None = None
    source_file: str | None = None
    line_number: int | None = None


@dataclass
class AssertCallSite:
    caller_address: int
    function_name: str | None = None
    source_file: str | None = None
    line_number: int | None = None
    expr_string: str | None = None


class AssertMacroGrounder:
    """Mines assert macro conditions, extracts variable boundaries, and de-anonymizes functions."""

    ASSERT_TAG_REGEX = re.compile(
        r'^(?P<expr>.*?)(?:\s*&&\s*[\"\(]*(?P<msg>[A-Za-z0-9_\-\s]+)[\"\)]*)\s*$'
    )

    COND_CMP_REGEX = re.compile(
        r'(?P<lhs>[A-Za-z_][A-Za-z0-9_\->\.]*)\s*(?P<op>==|!=|<=|>=|<|>)\s*(?P<rhs>[A-Za-z0-9_]+)'
    )

    FIELD_ACCESS_REGEX = re.compile(
        r'([A-Za-z_][A-Za-z0-9_]*)(?:->|\.)([A-Za-z_][A-Za-z0-9_]*)'
    )

    ASSERT_STUB_NAMES = (
        '__assert_rtn', '___assert_rtn', '__assert_fail', '___assert_fail',
        'assert', '_assert', '_wassert', '__assert',
    )

    @classmethod
    def parse_assert_expression(cls, raw_assert: str) -> AssertCondition:
        """Parse assert string into structured condition, comparisons, and diagnostic tag."""
        clean = raw_assert.strip()
        expr = clean
        diagnostic_tag = None

        m = cls.ASSERT_TAG_REGEX.match(clean)
        if m:
            expr = m.group('expr').strip()
            diagnostic_tag = m.group('msg').strip()

        comparisons: list[AssertComparison] = []
        for cm in cls.COND_CMP_REGEX.finditer(expr):
            lhs = cm.group('lhs')
            op = cm.group('op')
            rhs = cm.group('rhs')

            field_match = cls.FIELD_ACCESS_REGEX.match(lhs)
            if field_match:
                base_var = field_match.group(1)
                fld = field_match.group(2)
            else:
                base_var = lhs
                fld = None

            is_null = rhs.upper() in ('NULL', '0', 'NIL', 'NULLPTR') and op in ('!=', '==')
            comparisons.append(
                AssertComparison(
                    lhs=lhs,
                    base_var=base_var,
                    field=fld,
                    op=op,
                    rhs=rhs,
                    is_null_check=is_null,
                )
            )

        return AssertCondition(
            raw_condition=raw_assert,
            expr=expr,
            diagnostic_tag=diagnostic_tag,
            comparisons=comparisons,
        )

    @classmethod
    def _discover_assert_calls(
        cls, session: BinarySession, strings: list[tuple[int, str, str]]
    ) -> dict[int, AssertCallSite]:
        """
        Disassembles instructions to find assert stub calls and resolve function name,
        file path, line number, and assert expression string arguments.
        """
        call_sites: dict[int, AssertCallSite] = {}
        str_map = {va: s for va, s, _sec in strings}
        if not str_map:
            return call_sites

        # Find assert stubs/imports in session symbols
        assert_targets: set[int] = set()
        for sym in session.symbols.values():
            clean_sym = sym.name.lstrip('_').split('@')[0]
            if any(name.lstrip('_') == clean_sym for name in cls.ASSERT_STUB_NAMES):
                assert_targets.add(sym.address)

        arch = session.artifact.architecture
        bitness = session.artifact.bitness
        try:
            disasm = CapstoneDisassembler(arch=arch, bitness=bitness)
        except Exception:
            return call_sites

        # Scan each function
        for func_addr, func in list(session.functions.items()):
            func_size = func.size if func.size > 0 else 1024
            raw_bytes = FormatStringGrounder._read_bytes(session, func_addr, func_size)
            if not raw_bytes:
                continue

            insns = disasm.disassemble_bytes(raw_bytes, func_addr)
            reg_values: dict[str, int] = {}
            last_adrp: dict[str, int] = {}

            for ins in insns:
                # ARM64 tracking
                if ins.mnemonic == 'adrp':
                    parts = ins.op_str.split(',')
                    if len(parts) == 2:
                        reg = parts[0].strip()
                        val_str = parts[1].strip().lstrip('#')
                        with contextlib.suppress(ValueError):
                            last_adrp[reg] = int(val_str, 16 if '0x' in val_str else 10)
                elif ins.mnemonic in ('add', 'ldr', 'adr'):
                    parts = [p.strip() for p in ins.op_str.split(',')]
                    if ins.mnemonic == 'adr' and len(parts) >= 2:
                        reg = parts[0]
                        val_str = parts[1].lstrip('#').strip()
                        with contextlib.suppress(ValueError):
                            reg_values[reg] = int(val_str, 16 if '0x' in val_str else 10)
                    elif len(parts) >= 3 and parts[1] in last_adrp:
                        reg = parts[0]
                        base_reg = parts[1]
                        val_str = parts[2].lstrip('#').strip()
                        with contextlib.suppress(ValueError):
                            offset = int(val_str, 16 if '0x' in val_str else 10)
                            reg_values[reg] = last_adrp[base_reg] + offset
                elif ins.mnemonic == 'mov':
                    parts = [p.strip() for p in ins.op_str.split(',')]
                    if len(parts) == 2:
                        reg = parts[0]
                        val_str = parts[1].lstrip('#').strip()
                        with contextlib.suppress(ValueError):
                            reg_values[reg] = int(val_str, 16 if '0x' in val_str else 10)
                # x86_64 tracking: lea reg, [rip + disp]
                elif 'rip' in ins.op_str.lower() and 'lea' in ins.mnemonic:
                    parts = [p.strip() for p in ins.op_str.split(',')]
                    if len(parts) >= 2:
                        reg = parts[0].lower()
                        disp_match = re.search(r'rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)', parts[1], re.IGNORECASE)
                        if disp_match:
                            sign = 1 if disp_match.group(1) == '+' else -1
                            disp_val = int(disp_match.group(2), 16 if '0x' in disp_match.group(2) else 10)
                            reg_values[reg] = ins.address + ins.size + (sign * disp_val)

                # Check for call / branch
                is_call = ins.mnemonic in ('bl', 'call')
                target_val = None
                if is_call:
                    clean_op = ins.op_str.lstrip('#').strip()
                    with contextlib.suppress(ValueError):
                        target_val = int(clean_op, 16 if '0x' in clean_op else 10)

                is_assert_call = (
                    (target_val is not None and target_val in assert_targets)
                    or any(name in ins.op_str for name in cls.ASSERT_STUB_NAMES)
                )

                if is_assert_call:
                    # Resolve parameters based on calling convention
                    # Darwin ARM64 AAPCS: x0=func, x1=file, w2=line, x3=expr
                    func_name = None
                    file_name = None
                    line_no = reg_values.get('w2') or reg_values.get('x2')
                    expr_str = None

                    if 'x0' in reg_values and reg_values['x0'] in str_map:
                        func_name = str_map[reg_values['x0']]
                    if 'x1' in reg_values and reg_values['x1'] in str_map:
                        file_name = str_map[reg_values['x1']]
                    if 'x3' in reg_values and reg_values['x3'] in str_map:
                        expr_str = str_map[reg_values['x3']]

                    # Linux SysV x86_64: rdi=expr, rsi=file, edx=line, rcx=func
                    if 'rcx' in reg_values and reg_values['rcx'] in str_map:
                        func_name = func_name or str_map[reg_values['rcx']]
                    if 'rdi' in reg_values and reg_values['rdi'] in str_map:
                        expr_str = expr_str or str_map[reg_values['rdi']]
                    if 'rsi' in reg_values and reg_values['rsi'] in str_map:
                        file_name = file_name or str_map[reg_values['rsi']]

                    call_sites[func_addr] = AssertCallSite(
                        caller_address=func_addr,
                        function_name=func_name,
                        source_file=file_name,
                        line_number=line_no,
                        expr_string=expr_str,
                    )

        # Fallback: if caller functions are small out-of-line assert blocks branching to stubs,
        # trace caller functions that branch to these out-of-line blocks.
        return call_sites

    @classmethod
    def ground(cls, session: BinarySession) -> list[EvidenceTag]:
        """Ground assert macros, de-anonymize stripped functions, and emit EvidenceTags."""
        tags: list[EvidenceTag] = []
        strings = FormatStringGrounder.harvest_strings(session)
        assert_calls = cls._discover_assert_calls(session, strings)

        # 1. De-anonymize discovered functions
        for caller_addr, call_info in assert_calls.items():
            if call_info.function_name and caller_addr in session.functions:
                func = session.functions[caller_addr]
                old_name = func.name
                func.name = call_info.function_name
                func.confidence_score = 1.0
                func.is_stripped = False

                # Update session symbol table
                session.symbols.pop(old_name, None)
                sym = Symbol(
                    address=caller_addr,
                    name=call_info.function_name,
                    type=SymbolType.FUNCTION,
                    confidence=1.0,
                )
                session.add_symbol(sym)

        # 2. Match assert strings in read-only data sections
        for va, s, _sec in strings:
            is_assert = (
                any(op in s for op in ('!=', '==', '>', '<', '<=', '>='))
                and any(kw in s for kw in ('NULL', '0', 'check', 'not_null', 'magic', 'len'))
            ) or ('&& "' in s) or ('&& (' in s)

            if not is_assert:
                continue

            cond = cls.parse_assert_expression(s)
            primary_var = cond.comparisons[0].base_var if cond.comparisons else None
            inferred_type = 'void*' if cond.comparisons and cond.comparisons[0].is_null_check else None

            # Associate with target function if xref exists
            target_id = f"sym:0x{va:x}"
            target_type = TargetType.SYMBOL
            for c_addr, c_info in assert_calls.items():
                if (
                    (c_info.expr_string and c_info.expr_string == s)
                    or (cond.diagnostic_tag and c_info.expr_string and cond.diagnostic_tag in str(c_info.expr_string))
                ):
                    target_id = f"func:0x{c_addr:x}"
                    target_type = TargetType.FUNCTION
                    break

            explanation = (
                f"Assert condition '{cond.expr}' proving invariant on '{primary_var}'"
            )
            if cond.diagnostic_tag:
                explanation += f" (diagnostic tag: '{cond.diagnostic_tag}')"

            tag = EvidenceTag(
                tag_id=f"assert_0x{va:x}",
                target_type=target_type,
                target_id=target_id,
                suggested_name=primary_var,
                suggested_type=inferred_type,
                source=EvidenceSource.ASSERT_MACRO,
                evidence_type="ASSERT_MACRO",
                confidence=1.0,
                raw_anchor=s,
                explanation=explanation,
                is_immutable=True,
            )
            session.attach_evidence(tag)
            tags.append(tag)

        return tags
