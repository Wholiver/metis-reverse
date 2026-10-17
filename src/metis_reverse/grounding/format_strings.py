"""
metis_reverse.grounding.format_strings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Reverse inference of parameter types, variable names, and semantic context
from printf, spdlog, and fmt format strings.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
from dataclasses import dataclass, field

from metis_reverse.backends.tier1_native.disassembler import CapstoneDisassembler
from metis_reverse.core.models import (
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    TargetType,
)

logger = logging.getLogger("metis_reverse.grounding.format_strings")


@dataclass
class FormatParameter:
    index: int
    specifier: str
    length_modifier: str | None
    inferred_type: str
    suggested_name: str
    confidence: float
    prefix: str


@dataclass
class FormatStringMetadata:
    raw_string: str
    parameters: list[FormatParameter] = field(default_factory=list)
    log_level: str | None = None
    is_valid_format: bool = False


class FormatStringGrounder:
    """Mines binary format strings to reconstruct parameter types and semantic names."""

    # POSIX / C99 printf regex
    C_FORMAT_REGEX = re.compile(
        r'%(?:(?P<param>\d+)\$)?'
        r'(?P<flags>[-+0 #\'])*'
        r'(?P<width>\*|\d+)?'
        r'(?:\.(?P<prec>\*|\d+))?'
        r'(?P<length>hh|h|ll|l|j|z|t|L)?'
        r'(?P<spec>[diuoxXfFeEgGaAcspn%])'
    )

    # C++ fmt / spdlog regex
    CPP_FMT_REGEX = re.compile(
        r'\{(?P<arg>[A-Za-z0-9_]*)(?:\:(?P<spec>[^\}]+))?\}'
    )

    TYPE_MAP: dict[tuple[str, str | None], str] = {
        ('d', None): 'int', ('d', 'l'): 'long', ('d', 'll'): 'int64_t',
        ('d', 'h'): 'int16_t', ('d', 'hh'): 'int8_t', ('d', 'z'): 'ssize_t',
        ('i', None): 'int', ('i', 'l'): 'long', ('i', 'll'): 'int64_t',
        ('i', 'h'): 'int16_t', ('i', 'hh'): 'int8_t', ('i', 'z'): 'ssize_t',
        ('u', None): 'uint32_t', ('u', 'l'): 'uint64_t', ('u', 'll'): 'uint64_t', ('u', 'z'): 'size_t',
        ('x', None): 'uint32_t', ('x', 'l'): 'uint64_t', ('x', 'll'): 'uint64_t',
        ('X', None): 'uint32_t', ('X', 'l'): 'uint64_t', ('X', 'll'): 'uint64_t',
        ('f', None): 'double', ('f', 'L'): 'long double',
        ('F', None): 'double', ('F', 'L'): 'long double',
        ('s', None): 'const char*', ('s', 'l'): 'const wchar_t*',
        ('p', None): 'void*',
        ('c', None): 'char',
        ('z', None): 'size_t',
    }

    LOG_LEVEL_PREFIXES = ('[INFO]', '[DEBUG]', '[ERROR]', '[WARN]', '[WARNING]', '[CONFIG]', '[TRACE]', '[FATAL]')

    @classmethod
    def parse_format_string(cls, fmt_str: str) -> FormatStringMetadata:
        """Parse a format string and extract parameters and semantic names."""
        clean = fmt_str.strip()
        log_level = None
        for pfx in cls.LOG_LEVEL_PREFIXES:
            if clean.upper().startswith(pfx):
                log_level = pfx.strip('[]')
                break

        params: list[FormatParameter] = []
        last_end = 0

        for match in cls.C_FORMAT_REGEX.finditer(clean):
            spec = match.group('spec')
            if spec == '%':
                continue
            length = match.group('length')
            var_type = cls.TYPE_MAP.get((spec, length), cls.TYPE_MAP.get((spec, None), 'uint64_t'))

            prefix = clean[last_end:match.start()]
            last_end = match.end()

            suggested_name = cls._extract_semantic_var_name(prefix, len(params))
            params.append(
                FormatParameter(
                    index=len(params),
                    specifier=match.group(0),
                    length_modifier=length,
                    inferred_type=var_type,
                    suggested_name=suggested_name,
                    confidence=1.0,
                    prefix=prefix,
                )
            )

        # C++ fmt handling if no C format matches
        if not params:
            last_end = 0
            for match in cls.CPP_FMT_REGEX.finditer(clean):
                arg_name = match.group('arg')
                prefix = clean[last_end:match.start()]
                last_end = match.end()
                name = arg_name if arg_name else cls._extract_semantic_var_name(prefix, len(params))
                params.append(
                    FormatParameter(
                        index=len(params),
                        specifier=match.group(0),
                        length_modifier=None,
                        inferred_type='auto',
                        suggested_name=name,
                        confidence=1.0,
                        prefix=prefix,
                    )
                )

        return FormatStringMetadata(
            raw_string=fmt_str,
            parameters=params,
            log_level=log_level,
            is_valid_format=len(params) > 0,
        )

    @classmethod
    def _extract_semantic_var_name(cls, prefix: str, param_idx: int) -> str:
        """Extract a semantic variable name from prefix context."""
        cleaned = re.sub(r'0[xX]$', '', prefix.strip())

        # Pattern A: key= or key:
        kv = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*$', cleaned)
        if kv:
            candidate = kv.group(1).lower()
            if candidate not in {'status', 'code', 'error', 'failed', 'level'}:
                return candidate
            return candidate

        # Pattern B: descriptive nouns preceding specifier
        words = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', cleaned)
        stopwords = {
            'on', 'for', 'in', 'at', 'with', 'by', 'from', 'to', 'of', 'and', 'the', 'a', 'an',
            'is', 'are', 'was', 'were', 'starting', 'started', 'handling', 'handled', 'running',
            'info', 'debug', 'error', 'warn', 'config', 'trace', 'fatal',
        }
        while words and words[-1].lower() in stopwords:
            words.pop()

        if words:
            candidate = words[-1].lower()
            return candidate

        return f'arg_{param_idx}'

    @classmethod
    def harvest_strings(cls, session: BinarySession) -> list[tuple[int, str, str]]:
        """Harvest ASCII / UTF-8 strings from binary read-only sections."""
        results: list[tuple[int, str, str]] = []
        artifact = session.artifact
        if not artifact or not os.path.exists(artifact.file_path):
            return results

        target_sections = (
            ".rodata", ".rdata", "__cstring", "__const", ".data", ".text", "__data",
        )

        min_len = 4
        try:
            with open(artifact.file_path, "rb") as f:
                content = f.read()

            for sec in artifact.sections:
                sec_name = sec.name.lower()
                if not any(ts in sec_name for ts in target_sections):
                    continue

                raw_start = sec.raw_offset
                raw_size = sec.raw_size
                if raw_start < 0 or raw_start + raw_size > len(content):
                    continue

                sec_bytes = content[raw_start:raw_start + raw_size]
                current = bytearray()
                start_idx = 0

                for i, b in enumerate(sec_bytes):
                    if 0x20 <= b <= 0x7E:
                        if not current:
                            start_idx = i
                        current.append(b)
                    else:
                        if len(current) >= min_len:
                            try:
                                s = current.decode('utf-8')
                                results.append((sec.virtual_address + start_idx, s, sec.name))
                            except UnicodeDecodeError:
                                pass
                        current.clear()

                if len(current) >= min_len:
                    try:
                        s = current.decode('utf-8')
                        results.append((sec.virtual_address + start_idx, s, sec.name))
                    except UnicodeDecodeError:
                        pass
        except Exception as e:
            logger.warning("Failed to harvest strings from %s: %s", artifact.file_path, e)

        return results

    @classmethod
    def _find_string_xrefs(
        cls, session: BinarySession, strings: list[tuple[int, str, str]]
    ) -> dict[int, int]:
        """
        Map string virtual addresses to enclosing function virtual addresses using
        instruction tracing.
        """
        xrefs: dict[int, int] = {}
        str_addrs = {s[0] for s in strings}
        if not str_addrs:
            return xrefs

        arch = session.artifact.architecture
        bitness = session.artifact.bitness
        try:
            disasm = CapstoneDisassembler(arch=arch, bitness=bitness)
        except Exception:
            return xrefs

        # Search each discovered function
        for func_addr, func in session.functions.items():
            func_size = func.size if func.size > 0 else 512
            raw_bytes = cls._read_bytes(session, func_addr, func_size)
            if not raw_bytes:
                continue

            insns = disasm.disassemble_bytes(raw_bytes, func_addr)
            # Track ARM64 adrp page calculations
            last_adrp: dict[str, int] = {}

            for ins in insns:
                # ARM64 tracking
                if ins.mnemonic == 'adrp':
                    # e.g., adrp x0, #0x100001000
                    parts = ins.op_str.split(',')
                    if len(parts) == 2:
                        reg = parts[0].strip()
                        val_str = parts[1].strip().lstrip('#')
                        with contextlib.suppress(ValueError):
                            last_adrp[reg] = int(val_str, 16 if '0x' in val_str else 10)
                elif ins.mnemonic in ('add', 'ldr'):
                    # e.g., add x0, x0, #0x446
                    parts = [p.strip() for p in ins.op_str.split(',')]
                    if len(parts) >= 3 and parts[1] in last_adrp:
                        reg = parts[1]
                        val_str = parts[2].lstrip('#').strip()
                        try:
                            offset = int(val_str, 16 if '0x' in val_str else 10)
                            target_va = last_adrp[reg] + offset
                            if target_va in str_addrs:
                                xrefs[target_va] = func_addr
                        except ValueError:
                            pass
                # x86_64 RIP-relative tracking: lea rdi, [rip + disp]
                elif 'rip' in ins.op_str.lower() and ('lea' in ins.mnemonic or 'mov' in ins.mnemonic):
                    disp_match = re.search(r'rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)', ins.op_str, re.IGNORECASE)
                    if disp_match:
                        sign = 1 if disp_match.group(1) == '+' else -1
                        disp_val = int(disp_match.group(2), 16 if '0x' in disp_match.group(2) else 10)
                        target_va = ins.address + ins.size + (sign * disp_val)
                        if target_va in str_addrs:
                            xrefs[target_va] = func_addr

        return xrefs

    @classmethod
    def _read_bytes(cls, session: BinarySession, va: int, size: int) -> bytes:
        """Helper to read bytes at virtual address."""
        artifact = session.artifact
        if not artifact or not os.path.exists(artifact.file_path):
            return b""

        for sec in artifact.sections:
            if sec.virtual_address <= va < sec.virtual_address + sec.virtual_size:
                offset = sec.raw_offset + (va - sec.virtual_address)
                try:
                    with open(artifact.file_path, "rb") as f:
                        f.seek(offset)
                        return f.read(size)
                except Exception:
                    pass

        try:
            with open(artifact.file_path, "rb") as f:
                f.seek(max(0, va - artifact.base_address))
                return f.read(size)
        except Exception:
            return b""

    @classmethod
    def ground(cls, session: BinarySession) -> list[EvidenceTag]:
        """Ground all format strings in session, generate EvidenceTags, and bind to functions."""
        tags: list[EvidenceTag] = []
        strings = cls.harvest_strings(session)
        xrefs = cls._find_string_xrefs(session, strings)

        for va, s, _sec in strings:
            metadata = cls.parse_format_string(s)
            if not metadata.is_valid_format:
                continue

            target_func_addr = xrefs.get(va)
            target_id = f"func:0x{target_func_addr:x}" if target_func_addr else f"sym:0x{va:x}"
            target_type = TargetType.FUNCTION if target_func_addr else TargetType.SYMBOL

            explanation_parts = [
                f"{p.suggested_name}: {p.inferred_type} ({p.specifier})"
                for p in metadata.parameters
            ]
            explanation = (
                f"Format string at 0x{va:x} passed to logger/printf. "
                f"Inferred parameters: [{', '.join(explanation_parts)}]"
            )

            tag = EvidenceTag(
                tag_id=f"fmt_0x{va:x}",
                target_type=target_type,
                target_id=target_id,
                suggested_name=metadata.parameters[0].suggested_name if metadata.parameters else None,
                suggested_type=metadata.parameters[0].inferred_type if metadata.parameters else None,
                source=EvidenceSource.FORMAT_STRING,
                evidence_type="FORMAT_STRING",
                confidence=1.0,
                raw_anchor=s,
                explanation=explanation,
                is_immutable=True,
            )
            session.attach_evidence(tag)
            tags.append(tag)

        return tags
