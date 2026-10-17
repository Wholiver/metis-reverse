"""
Metis Reverse - Dynamic Fact Backfiller
Reconciles concrete runtime values, return types, parameter values, and strings
into the static session symbol table and immutable evidence store.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from metis_reverse.core.models import (
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    Function,
    FunctionParameter,
    TargetType,
    TraceResult,
)

logger = logging.getLogger("metis_reverse.dynamic.backfiller")


class FactBackfiller:
    """
    Reconciles concrete dynamic trace results into static binary analysis sessions.
    """

    def backfill(
        self,
        session: BinarySession,
        trace_result: TraceResult,
        function_address: int,
        args: list[Any] | None = None,
    ) -> list[EvidenceTag]:
        """
        Reconcile dynamic trace observations into the session's symbol table,
        function metadata, and EvidenceStore.
        """
        created_tags: list[EvidenceTag] = []
        args_list = args or []

        # 1. Retrieve or synthesize function in session
        func = session.functions.get(function_address)
        if func is None:
            func = Function(
                id=f"func_0x{function_address:x}",
                name=f"sub_{function_address:x}",
                address=function_address,
                is_stripped=session.artifact.is_stripped,
            )
            session.functions[function_address] = func

        # 2. Determine concrete return type
        inferred_return_type = trace_result.return_type
        if not inferred_return_type and trace_result.return_value is not None:
            ret_val = trace_result.return_value
            if ret_val in (0, 1):
                inferred_return_type = "int"
            elif isinstance(ret_val, int) and ret_val > 0x10000 and self._is_pointer_address(session, ret_val):
                inferred_return_type = "void*"
            elif isinstance(ret_val, int) and ret_val < 0:
                inferred_return_type = "int"
            else:
                inferred_return_type = "uint64_t" if isinstance(ret_val, int) and ret_val > 0xFFFFFFFF else "int"

        if inferred_return_type:
            func.return_type = inferred_return_type

        # 3. Create Function-level EvidenceTag
        func_tag_id = f"dyn_func_0x{function_address:x}_{uuid.uuid4().hex[:8]}"
        func_tag = EvidenceTag(
            tag_id=func_tag_id,
            target_type=TargetType.FUNCTION,
            target_id=f"function:0x{function_address:x}",
            suggested_name=func.name,
            suggested_type=func.return_type,
            source=EvidenceSource.DYNAMIC_PROBE,
            evidence_type="DYNAMIC_PROBE",
            confidence=1.0,
            is_immutable=True,
            raw_anchor=(
                f"Observed return_value={trace_result.return_value} "
                f"with args={args_list}, runtime strings={trace_result.captured_strings}"
            ),
            explanation=(
                f"Dynamic execution probe at 0x{function_address:x} observed concrete "
                f"execution returning {trace_result.return_value}."
            ),
        )
        session.attach_evidence(func_tag)
        created_tags.append(func_tag)

        if func_tag.tag_id not in func.evidence_tag_ids:
            func.evidence_tag_ids.append(func_tag.tag_id)
        func.confidence_score = 1.0

        # Also attach to symbol if exists
        sym = session.symbols_by_address.get(function_address)
        if sym:
            sym.confidence = 1.0
            if func_tag.tag_id not in sym.evidence_tag_ids:
                sym.evidence_tag_ids.append(func_tag.tag_id)
            if not any(t.tag_id == func_tag.tag_id for t in sym.evidence_tags):
                sym.evidence_tags.append(func_tag)

        # 4. Reconcile Parameter types and values
        for idx, arg in enumerate(args_list):
            param_type = self._infer_arg_type(session, arg)
            param_tag_id = f"dyn_param_0x{function_address:x}_{idx}_{uuid.uuid4().hex[:8]}"
            param_tag = EvidenceTag(
                tag_id=param_tag_id,
                target_type=TargetType.PARAMETER,
                target_id=f"param:0x{function_address:x}:{idx}",
                suggested_type=param_type,
                source=EvidenceSource.DYNAMIC_PROBE,
                evidence_type="DYNAMIC_PROBE",
                confidence=1.0,
                is_immutable=True,
                raw_anchor=f"Observed arg[{idx}]={arg!r} during dynamic probe trace",
                explanation=f"Runtime argument {idx} verified as concrete value {arg!r}.",
            )
            session.attach_evidence(param_tag)
            created_tags.append(param_tag)

            # Update or append FunctionParameter
            if idx < len(func.parameters):
                p = func.parameters[idx]
                if isinstance(p, FunctionParameter):
                    p.type_name = param_type
                    if param_tag.tag_id not in p.evidence_tag_ids:
                        p.evidence_tag_ids.append(param_tag.tag_id)
            else:
                func.parameters.append(
                    FunctionParameter(
                        index=idx,
                        name=f"arg_{idx}",
                        type_name=param_type,
                        evidence_tag_ids=[param_tag.tag_id],
                    )
                )

        # 5. Reconcile Captured Runtime Strings
        for str_val in trace_result.captured_strings:
            clean_str = str_val.strip()
            if not clean_str:
                continue
            str_tag_id = f"dyn_str_{uuid.uuid4().hex[:8]}"
            str_tag = EvidenceTag(
                tag_id=str_tag_id,
                target_type=TargetType.SYMBOL,
                target_id=f"func:0x{function_address:x}:string",
                suggested_name=clean_str[:32],
                suggested_type="const char*",
                source=EvidenceSource.DYNAMIC_PROBE,
                evidence_type="DYNAMIC_PROBE",
                confidence=1.0,
                is_immutable=True,
                raw_anchor=f"Captured runtime string literal: {clean_str!r}",
                explanation="Inspected in memory buffer during function execution probe.",
            )
            session.attach_evidence(str_tag)
            created_tags.append(str_tag)

        return created_tags

    def _infer_arg_type(self, session: BinarySession, arg: Any) -> str:
        """Infer C type for an argument value."""
        if isinstance(arg, str):
            return "const char*"
        if isinstance(arg, int):
            if self._is_pointer_address(session, arg):
                return "void*"
            if arg < 0:
                return "int"
            return "int" if arg <= 0xFFFFFFFF else "uint64_t"
        if isinstance(arg, (bytes, bytearray)):
            return "const void*"
        return "void*"

    def _is_pointer_address(self, session: BinarySession, val: int) -> bool:
        """Check if an integer value resides in mapped binary sections."""
        if val <= 0x1000:
            return False
        for sec in session.artifact.sections:
            if sec.virtual_address <= val < sec.virtual_address + sec.virtual_size:
                return True
        return False
