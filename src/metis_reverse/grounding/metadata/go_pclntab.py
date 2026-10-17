"""
metis_reverse.grounding.metadata.go_pclntab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deep Go runtime pclntab parser supporting Go 1.2, 1.16, 1.18, and 1.20+ releases.
Recovers exact function symbols, source file paths, and line number mappings
from stripped Go binaries (-ldflags="-s -w").
"""

from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass

from metis_reverse.core.models import (
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    Function,
    Symbol,
    SymbolType,
    TargetType,
)

logger = logging.getLogger("metis_reverse.grounding.metadata.go_pclntab")


@dataclass
class GoFunctionSymbol:
    name: str
    address: int
    size: int
    source_file: str | None = None
    line_number: int | None = None
    line_table: list[tuple[int, int, int]] | None = None  # (start_pc, end_pc, line)


class GoPclntabParser:
    """Parses Go pclntab from memory or sections across Go 1.2 through 1.23+."""

    MAGIC_GO120 = 0xFFFFFFF1
    MAGIC_GO118 = 0xFFFFFFF0
    MAGIC_GO116 = 0xFFFFFFFA
    MAGIC_GO12 = 0xFFFFFFFB

    def __init__(self, raw_bytes: bytes, text_base_address: int = 0, pclntab_va: int = 0):
        self.raw_bytes = raw_bytes
        self.text_base = text_base_address
        self.pclntab_va = pclntab_va

    @classmethod
    def from_session(cls, session: BinarySession) -> GoPclntabParser | None:
        """Attempt to locate pclntab section or scan memory in session artifact."""
        artifact = session.artifact
        if not artifact or not os.path.exists(artifact.file_path):
            return None

        try:
            with open(artifact.file_path, "rb") as f:
                content = f.read()
        except Exception:
            return None

        # 1. Search for named section
        for sec in artifact.sections:
            sec_lower = sec.name.lower()
            if "gopclntab" in sec_lower:
                start = sec.raw_offset
                size = sec.raw_size
                if 0 <= start < len(content):
                    sec_bytes = content[start:start + size]
                    return cls(
                        raw_bytes=sec_bytes,
                        text_base_address=artifact.base_address,
                        pclntab_va=sec.virtual_address,
                    )

        # 2. Fallback memory scan for magic values
        magics = (
            b"\xf1\xff\xff\xff",  # 1.20+
            b"\xf0\xff\xff\xff",  # 1.18
            b"\xfa\xff\xff\xff",  # 1.16
            b"\xfb\xff\xff\xff",  # 1.2
        )
        for magic in magics:
            idx = content.find(magic)
            if idx != -1 and idx + 64 <= len(content):
                # Verify header characteristics: minLC in (1, 2, 4), ptrSize in (4, 8)
                min_lc = content[idx + 6]
                ptr_size = content[idx + 7]
                if min_lc in (1, 2, 4) and ptr_size in (4, 8):
                    return cls(
                        raw_bytes=content[idx:],
                        text_base_address=artifact.base_address,
                        pclntab_va=artifact.base_address + idx,
                    )

        return None

    def extract_symbols(self) -> list[GoFunctionSymbol]:
        """Locates and parses pclntab, returning all function symbols and file/line anchors."""
        if len(self.raw_bytes) < 8:
            return []

        try:
            magic = struct.unpack_from("<I", self.raw_bytes, 0)[0]
            if magic in (self.MAGIC_GO118, self.MAGIC_GO120):
                return self._parse_go118_and_newer()
            elif magic == self.MAGIC_GO116:
                return self._parse_go116()
            elif magic == self.MAGIC_GO12:
                return self._parse_go12()
        except (struct.error, IndexError, ValueError) as exc:
            logger.debug("Failed to parse pclntab: %s", exc)
            return []

        return []

    def _parse_go118_and_newer(self) -> list[GoFunctionSymbol]:
        """Parse Go 1.18 and Go 1.20+ pclntab layout."""
        symbols: list[GoFunctionSymbol] = []
        data = self.raw_bytes

        if len(data) < 8:
            return []

        _min_lc = data[6]
        ptr_size = data[7]
        if ptr_size not in (4, 8):
            return []

        # Validate minimum header size for Go 1.18+: 8 header bytes + 8 pointer fields
        min_header_size = 8 + (8 * ptr_size)
        if len(data) < min_header_size:
            return []

        unpack_ptr = "<Q" if ptr_size == 8 else "<I"

        offset = 8
        nfunc = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        _nfiles = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        text_start = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        funcname_offset = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        cu_offset = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        filetab_offset = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        pctab_offset = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        pcln_offset = struct.unpack_from(unpack_ptr, data, offset)[0]

        # Use text_start if valid, otherwise fallback to text_base
        base_pc = text_start if text_start != 0 else self.text_base

        functab_ptr = pcln_offset
        if functab_ptr < 0 or functab_ptr >= len(data):
            return symbols

        for i in range(nfunc):
            entry_ptr = functab_ptr + (i * 8)
            if entry_ptr + 8 > len(data):
                break

            entry_off = struct.unpack_from("<I", data, entry_ptr)[0]
            func_data_off = struct.unpack_from("<I", data, entry_ptr + 4)[0]

            func_pc = base_pc + entry_off
            func_record_ptr = pcln_offset + func_data_off
            if func_record_ptr < 0 or func_record_ptr + 28 > len(data):
                continue

            name_off = struct.unpack_from("<i", data, func_record_ptr + 4)[0]
            func_name = self._read_cstring(data, funcname_offset + name_off)
            if not func_name:
                continue

            pcfile_off = struct.unpack_from("<I", data, func_record_ptr + 20)[0]
            pcln_off = struct.unpack_from("<I", data, func_record_ptr + 24)[0]

            # Parse line number and file
            line_no = self._decode_first_line(data, pctab_offset + pcln_off)
            src_file = self._decode_file_path(data, cu_offset, filetab_offset, pctab_offset + pcfile_off)

            # Determine function size by checking next function entry if available
            func_size = 32
            if i + 1 <= nfunc and entry_ptr + 12 <= len(data):
                next_entry_off = struct.unpack_from("<I", data, entry_ptr + 8)[0]
                if next_entry_off > entry_off:
                    func_size = next_entry_off - entry_off

            symbols.append(
                GoFunctionSymbol(
                    name=func_name,
                    address=func_pc,
                    size=func_size,
                    source_file=src_file,
                    line_number=line_no,
                )
            )

        return symbols

    def _parse_go116(self) -> list[GoFunctionSymbol]:
        """Parse Go 1.16 pclntab layout."""
        symbols: list[GoFunctionSymbol] = []
        data = self.raw_bytes

        if len(data) < 8:
            return []

        ptr_size = data[7]
        if ptr_size not in (4, 8):
            return []

        # Validate minimum header size for Go 1.16: 8 header bytes + 7 pointer fields
        min_header_size = 8 + (7 * ptr_size)
        if len(data) < min_header_size:
            return []

        unpack_ptr = "<Q" if ptr_size == 8 else "<I"

        offset = 8
        nfunc = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        _nfiles = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        funcname_offset = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        _cu_offset = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        _filetab_offset = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        _pctab_offset = struct.unpack_from(unpack_ptr, data, offset)[0]
        offset += ptr_size
        pcln_offset = struct.unpack_from(unpack_ptr, data, offset)[0]

        step = ptr_size * 2
        for i in range(nfunc):
            pos = pcln_offset + (i * step)
            if pos + step > len(data):
                break
            func_pc = struct.unpack_from(unpack_ptr, data, pos)[0]
            func_data_off = struct.unpack_from(unpack_ptr, data, pos + ptr_size)[0]

            func_rec = pcln_offset + func_data_off
            if func_rec < 0 or func_rec + 16 > len(data):
                continue
            name_off = struct.unpack_from("<i", data, func_rec + ptr_size)[0]
            func_name = self._read_cstring(data, funcname_offset + name_off)
            if not func_name:
                continue

            symbols.append(
                GoFunctionSymbol(
                    name=func_name,
                    address=func_pc,
                    size=32,
                    source_file=None,
                    line_number=None,
                )
            )
        return symbols

    def _parse_go12(self) -> list[GoFunctionSymbol]:
        """Parse Go 1.2 - 1.15 legacy pclntab layout."""
        symbols: list[GoFunctionSymbol] = []
        data = self.raw_bytes

        if len(data) < 8:
            return []

        ptr_size = data[7]
        if ptr_size not in (4, 8):
            return []

        min_header_size = 8 + ptr_size
        if len(data) < min_header_size:
            return []

        unpack_ptr = "<Q" if ptr_size == 8 else "<I"

        nfunc = struct.unpack_from(unpack_ptr, data, 8)[0]
        step = ptr_size * 2
        functab_start = 8 + ptr_size

        for i in range(nfunc):
            pos = functab_start + (i * step)
            if pos + step > len(data):
                break
            func_pc = struct.unpack_from(unpack_ptr, data, pos)[0]
            func_off = struct.unpack_from(unpack_ptr, data, pos + ptr_size)[0]

            func_rec = func_off
            if func_rec < 0 or func_rec + 16 > len(data):
                continue
            name_off = struct.unpack_from("<i", data, func_rec + ptr_size)[0]
            func_name = self._read_cstring(data, name_off)
            if not func_name:
                continue

            symbols.append(
                GoFunctionSymbol(
                    name=func_name,
                    address=func_pc,
                    size=32,
                    source_file=None,
                    line_number=None,
                )
            )
        return symbols

    def _read_cstring(self, data: bytes, offset: int) -> str | None:
        if offset < 0 or offset >= len(data):
            return None
        end = data.find(b"\x00", offset)
        if end == -1:
            end = min(len(data), offset + 256)
        try:
            return data[offset:end].decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _decode_first_line(self, data: bytes, offset: int) -> int | None:
        """Decode first line delta from pctab using varint zigzag decoding."""
        if offset < 0 or offset >= len(data):
            return None

        idx = offset
        line = 0

        # Read zigzag varint for delta
        val, idx = self._read_varint(data, idx)
        if val is None or val == 0:
            return None

        val_delta = ~(val >> 1) if (val & 1) else (val >> 1)
        line += val_delta
        return line if line > 0 else None

    def _decode_file_path(self, data: bytes, cu_offset: int, filetab_offset: int, offset: int) -> str | None:
        """Decode file path string from filetab."""
        if filetab_offset <= 0 or filetab_offset >= len(data):
            return None

        # In Go 1.18+, pctab contains file delta index
        val, _ = self._read_varint(data, offset)
        if val is None:
            return None

        # Resolve index in filetab
        file_idx = val >> 1 if not (val & 1) else ~(val >> 1)
        if file_idx <= 0:
            return None

        # Read null-terminated string at filetab_offset
        str_ptr = filetab_offset
        for _ in range(file_idx):
            end = data.find(b"\x00", str_ptr)
            if end == -1:
                return None
            str_ptr = end + 1

        end = data.find(b"\x00", str_ptr)
        if end != -1:
            try:
                return data[str_ptr:end].decode("utf-8")
            except UnicodeDecodeError:
                pass
        return None

    def _read_varint(self, data: bytes, offset: int) -> tuple[int | None, int]:
        """Read variable-length unsigned integer."""
        if offset < 0 or offset >= len(data):
            return None, offset
        res = 0
        shift = 0
        idx = offset
        while idx < len(data):
            b = data[idx]
            idx += 1
            res |= (b & 0x7F) << shift
            if not (b & 0x80):
                return res, idx
            shift += 7
            if shift > 64:
                return None, idx
        return None, idx

    def generate_evidence_tags(self, symbols: list[GoFunctionSymbol]) -> list[EvidenceTag]:
        """Converts GoFunctionSymbols into immutable EvidenceTags with confidence 1.0."""
        tags: list[EvidenceTag] = []
        for sym in symbols:
            anchor_parts = [f".gopclntab:0x{sym.address:x}"]
            if sym.source_file:
                anchor_parts.append(f"({sym.source_file}:{sym.line_number or '?'})")

            tag = EvidenceTag(
                tag_id=f"ev_pcln_0x{sym.address:x}",
                target_type=TargetType.FUNCTION,
                target_id=f"func:0x{sym.address:x}",
                suggested_name=sym.name,
                suggested_type="go_func",
                source=EvidenceSource.GO_PCLNTAB,
                evidence_type="GO_PCLNTAB",
                confidence=1.0,
                raw_anchor=" ".join(anchor_parts),
                explanation=f"Exact Go function recovered from runtime pclntab ({sym.name})",
                is_immutable=True,
            )
            tags.append(tag)
        return tags

    @classmethod
    def ground(cls, session: BinarySession) -> list[EvidenceTag]:
        """Run Go pclntab parser on session, attach symbols, de-anonymize functions, and emit tags."""
        parser = cls.from_session(session)
        if not parser:
            return []

        symbols = parser.extract_symbols()
        if not symbols:
            return []

        tags = parser.generate_evidence_tags(symbols)

        # De-anonymize functions in session
        for sym in symbols:
            # Update or create function in session.functions
            func = session.functions.get(sym.address)
            if func is None:
                func = Function(
                    id=f"func_0x{sym.address:x}",
                    name=sym.name,
                    address=sym.address,
                    size=sym.size,
                    confidence_score=1.0,
                    is_stripped=False,
                )
                session.functions[sym.address] = func
            else:
                old_name = func.name
                func.name = sym.name
                func.confidence_score = 1.0
                func.is_stripped = False
                session.symbols.pop(old_name, None)

            # Register in symbols
            session_sym = Symbol(
                address=sym.address,
                name=sym.name,
                type=SymbolType.FUNCTION,
                size=sym.size,
                confidence=1.0,
            )
            session.add_symbol(session_sym)

        # Attach all evidence tags
        for t in tags:
            session.attach_evidence(t)

        return tags
