"""
metis_reverse.backends.tier1_native.binary_parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LIEF-powered binary header, section, and format normalization parser.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from typing import Any

import lief

from metis_reverse.backends.base import UnsupportedArtifactError
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySection,
    Endianness,
    SectionPermission,
    Symbol,
    SymbolType,
    TargetArtifact,
)


class LiefBinaryParser:
    """Parses ELF, PE, and Mach-O binaries using LIEF without external dependencies."""

    @classmethod
    def parse(
        cls, file_path: str, target_arch: str | None = None
    ) -> tuple[TargetArtifact, list[Symbol], list[tuple[int, str, str]]]:
        """
        Parse binary file and produce TargetArtifact, initial symbols, and extracted strings.

        Args:
            file_path: Absolute or relative path to binary.
            target_arch: Optional architecture preference for FAT Mach-O binaries.

        Returns:
            Tuple of:
              - TargetArtifact: Normalized metadata and sections.
              - List[Symbol]: Initial discovered symbols (imports, exports, locals).
              - List[Tuple[int, str, str]]: Discovered strings (virtual_addr, string_value, section_name).
        """
        abs_path = os.path.abspath(file_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Binary file not found: {abs_path}")

        file_size = os.path.getsize(abs_path)
        with open(abs_path, "rb") as f:
            raw_bytes = f.read()
            artifact_id = hashlib.sha256(raw_bytes).hexdigest()

        # Parse with LIEF
        parsed: Any
        try:
            if lief.MachO.is_fat(abs_path):
                parsed = lief.MachO.parse(abs_path)
            else:
                parsed = lief.parse(abs_path)
        except Exception as e:
            raise UnsupportedArtifactError(f"LIEF failed to parse binary: {abs_path}: {e}") from e

        if parsed is None:
            raise UnsupportedArtifactError(f"LIEF failed to parse binary: {abs_path}")

        # Handle Mach-O Fat Binary
        binary: Any
        if isinstance(parsed, lief.MachO.FatBinary):
            binary = cls._select_macho_slice(parsed, target_arch)
        elif isinstance(parsed, (lief.ELF.Binary, lief.PE.Binary, lief.MachO.Binary)):
            binary = parsed
        else:
            raise UnsupportedArtifactError(f"Unsupported binary object type: {type(parsed)}")

        # Format classification
        fmt = cls._detect_format(binary)
        arch, bitness, endian = cls._detect_arch(binary, fmt)
        entry_point = cls._extract_entry_point(binary)
        entry_points = cls._extract_entrypoints(binary)
        base_address = cls._extract_base_address(binary)
        sections = cls._extract_sections(binary)
        is_pie = cls._detect_pie(binary)
        symbols = cls._extract_symbols(binary)
        strings = cls._extract_strings(binary)

        # Reject malformed binaries with 0 sections or unknown/invalid architecture
        if (not sections or arch == ArchitectureType.UNKNOWN) and fmt in (
            ArtifactFormat.ELF,
            ArtifactFormat.MACHO,
            ArtifactFormat.PE,
        ):
            raise UnsupportedArtifactError(
                f"Malformed binary has no valid sections or unknown architecture: {abs_path}"
            )

        artifact = TargetArtifact(
            artifact_id=artifact_id,
            file_path=abs_path,
            file_name=os.path.basename(abs_path),
            file_size=file_size,
            format=fmt,
            architecture=arch,
            bitness=bitness,
            endianness=endian,
            base_address=base_address,
            entry_point=entry_point,
            entry_points=entry_points,
            sections=sections,
            is_pie=is_pie,
            is_stripped=(len(symbols) == 0 or all(s.name.startswith("sub_") for s in symbols)),
        )

        return artifact, symbols, strings

    @classmethod
    def _select_macho_slice(
        cls, fat_binary: lief.MachO.FatBinary, target_arch: str | None
    ) -> lief.MachO.Binary:
        """Select best slice from FAT Mach-O (prefer host arch ARM64 or requested)."""
        slices = list(fat_binary)
        if not slices:
            raise UnsupportedArtifactError("Mach-O FAT binary contains no slices.")

        if target_arch:
            for s in slices:
                if target_arch.lower() in str(s.header.cpu_type).lower():
                    return s

        # Host preference: ARM64 then X86_64
        for s in slices:
            if s.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
                return s
        for s in slices:
            if s.header.cpu_type == lief.MachO.Header.CPU_TYPE.X86_64:
                return s

        return slices[0]

    @classmethod
    def _detect_format(cls, binary: Any) -> ArtifactFormat:
        if isinstance(binary, lief.ELF.Binary):
            return ArtifactFormat.ELF
        if isinstance(binary, lief.MachO.Binary):
            return ArtifactFormat.MACHO
        if isinstance(binary, lief.PE.Binary):
            return ArtifactFormat.PE
        return ArtifactFormat.RAW

    @classmethod
    def _detect_arch(
        cls, binary: Any, fmt: ArtifactFormat
    ) -> tuple[ArchitectureType, int, Endianness]:
        endian = Endianness.LITTLE
        bitness = 64

        if fmt == ArtifactFormat.ELF:
            elf_arch = binary.header.machine_type
            bitness = 64 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32
            endian = (
                Endianness.LITTLE
                if binary.header.identity_data == lief.ELF.Header.ELF_DATA.LSB
                else Endianness.BIG
            )
            if elf_arch in (lief.ELF.ARCH.AARCH64, lief.ELF.ARCH.ARM):
                return (ArchitectureType.ARM64 if bitness == 64 else ArchitectureType.ARM), bitness, endian
            if elf_arch == lief.ELF.ARCH.X86_64:
                return ArchitectureType.X86_64, 64, endian
            if elf_arch == lief.ELF.ARCH.I386:
                return ArchitectureType.X86, 32, endian

        elif fmt == ArtifactFormat.MACHO:
            cpu = binary.header.cpu_type
            if cpu == lief.MachO.Header.CPU_TYPE.ARM64:
                return ArchitectureType.ARM64, 64, Endianness.LITTLE
            if cpu == lief.MachO.Header.CPU_TYPE.ARM:
                return ArchitectureType.ARM, 32, Endianness.LITTLE
            if cpu == lief.MachO.Header.CPU_TYPE.X86_64:
                return ArchitectureType.X86_64, 64, Endianness.LITTLE
            if cpu == lief.MachO.Header.CPU_TYPE.X86:
                return ArchitectureType.X86, 32, Endianness.LITTLE

        elif fmt == ArtifactFormat.PE:
            machine = binary.header.machine
            if machine == lief.PE.Header.MACHINE_TYPES.AMD64:
                return ArchitectureType.X86_64, 64, Endianness.LITTLE
            if machine == lief.PE.Header.MACHINE_TYPES.I386:
                return ArchitectureType.X86, 32, Endianness.LITTLE
            if machine in (lief.PE.Header.MACHINE_TYPES.ARM64,):
                return ArchitectureType.ARM64, 64, Endianness.LITTLE

        return ArchitectureType.UNKNOWN, bitness, endian

    @classmethod
    def _extract_entry_point(cls, binary: Any) -> int:
        """Extract primary entry point address for Mach-O, ELF, and PE."""
        entry = getattr(binary, "entrypoint", None)
        if entry is not None and int(entry) > 0:
            return int(entry)
        if hasattr(binary, "main_command") and binary.main_command:
            base = int(getattr(binary, "imagebase", 0) or 0)
            return base + int(binary.main_command.entrypoint)
        return 0

    @classmethod
    def _extract_entrypoints(cls, binary: Any) -> list[int]:
        ep = cls._extract_entry_point(binary)
        return [ep] if ep > 0 else []

    @classmethod
    def _extract_base_address(cls, binary: Any) -> int:
        return int(getattr(binary, "imagebase", 0) or 0)

    @classmethod
    def _extract_sections(cls, binary: Any) -> list[BinarySection]:
        sections: list[BinarySection] = []
        for s in binary.sections:
            perms: list[SectionPermission] = []
            if isinstance(binary, lief.ELF.Binary):
                flags = int(s.flags)
                if flags & int(lief.ELF.Section.FLAGS.ALLOC):
                    perms.append(SectionPermission.READ)
                if flags & int(lief.ELF.Section.FLAGS.WRITE):
                    perms.append(SectionPermission.WRITE)
                if flags & int(lief.ELF.Section.FLAGS.EXECINSTR):
                    perms.append(SectionPermission.EXECUTE)
            elif isinstance(binary, lief.MachO.Binary):
                perms = [SectionPermission.READ]
                prot = 0
                if hasattr(s, "segment") and s.segment:
                    prot = int(getattr(s.segment, "init_protection", 0))
                if (prot & 2) or any(k in s.name.lower() for k in ("data", "got", "bss", "common")):
                    perms.append(SectionPermission.WRITE)
                has_instructions = False
                if hasattr(s, "flags"):
                    s_flags = int(s.flags)
                    if s_flags & (0x80000000 | 0x400):
                        has_instructions = True
                if (prot & 4 and has_instructions) or any(k in s.name.lower() for k in ("text", "stub")):
                    perms.append(SectionPermission.EXECUTE)
            elif isinstance(binary, lief.PE.Binary):
                chars = int(s.characteristics)
                if chars & int(lief.PE.Section.CHARACTERISTICS.MEM_READ):
                    perms.append(SectionPermission.READ)
                if chars & int(lief.PE.Section.CHARACTERISTICS.MEM_WRITE):
                    perms.append(SectionPermission.WRITE)
                if chars & int(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
                    perms.append(SectionPermission.EXECUTE)

            if not perms:
                perms = [SectionPermission.READ]

            content_len = len(s.content) if s.content is not None else s.size
            sections.append(
                BinarySection(
                    name=str(s.name or ""),
                    virtual_address=int(s.virtual_address),
                    virtual_size=int(s.size),
                    raw_offset=int(s.offset),
                    raw_size=int(content_len),
                    permissions=perms,
                    entropy=float(s.entropy) if hasattr(s, "entropy") else 0.0,
                )
            )

        # Fallback for stripped ELF/Mach-O binaries with segment headers but no section table
        if not sections and hasattr(binary, "segments"):
            for i, seg in enumerate(binary.segments):
                if isinstance(binary, lief.ELF.Binary):
                    if seg.type != lief.ELF.Segment.TYPE.LOAD:
                        continue
                    perms = []
                    flags = int(seg.flags)
                    if flags & int(lief.ELF.Segment.FLAGS.R):
                        perms.append(SectionPermission.READ)
                    if flags & int(lief.ELF.Segment.FLAGS.W):
                        perms.append(SectionPermission.WRITE)
                    if flags & int(lief.ELF.Segment.FLAGS.X):
                        perms.append(SectionPermission.EXECUTE)
                    if not perms:
                        perms = [SectionPermission.READ]
                    content_len = len(seg.content) if seg.content is not None else int(seg.physical_size)
                    sections.append(
                        BinarySection(
                            name=f"LOAD_{i}",
                            virtual_address=int(seg.virtual_address),
                            virtual_size=int(seg.virtual_size),
                            raw_offset=int(seg.file_offset),
                            raw_size=int(content_len),
                            permissions=perms,
                            entropy=0.0,
                        )
                    )
                elif isinstance(binary, lief.MachO.Binary):
                    seg_name = getattr(seg, "name", "")
                    if seg_name in ("__PAGEZERO",):
                        continue
                    perms = [SectionPermission.READ]
                    init_prot = int(getattr(seg, "init_protection", 0))
                    if init_prot & 2:
                        perms.append(SectionPermission.WRITE)
                    if init_prot & 4:
                        perms.append(SectionPermission.EXECUTE)
                    content_len = len(seg.content) if seg.content is not None else int(seg.file_size)
                    sections.append(
                        BinarySection(
                            name=str(seg_name or f"SEG_{i}"),
                            virtual_address=int(seg.virtual_address),
                            virtual_size=int(seg.virtual_size),
                            raw_offset=int(seg.file_offset),
                            raw_size=int(content_len),
                            permissions=perms,
                            entropy=0.0,
                        )
                    )

        return sections

    @classmethod
    def _detect_pie(cls, binary: Any) -> bool:
        if hasattr(binary, "is_pie"):
            return bool(binary.is_pie)
        return False

    @classmethod
    def _extract_symbols(cls, binary: Any) -> list[Symbol]:
        symbols: list[Symbol] = []
        for sym in getattr(binary, "symbols", []):
            name = sym.name
            if not name:
                continue
            addr = int(sym.value)
            sym_type = SymbolType.VARIABLE
            if isinstance(binary, lief.ELF.Binary):
                if hasattr(sym, "type") and sym.type == lief.ELF.Symbol.TYPE.FUNC:
                    sym_type = SymbolType.FUNCTION
            elif isinstance(binary, lief.MachO.Binary):
                if hasattr(sym, "type"):
                    type_val = getattr(sym.type, "value", sym.type)
                    try:
                        if (int(type_val) & 0x0E == 0x0E) and sym.name != "__mh_execute_header":
                            sym_type = SymbolType.FUNCTION
                    except (ValueError, TypeError):
                        pass
            elif isinstance(binary, lief.PE.Binary) and hasattr(sym, "complex_type"):
                with contextlib.suppress(Exception):
                    if "FUNCTION" in str(sym.complex_type):
                        sym_type = SymbolType.FUNCTION

            symbols.append(
                Symbol(
                    name=name,
                    address=addr,
                    size=int(getattr(sym, "size", 0)),
                    type=sym_type,
                    is_imported=bool(getattr(sym, "is_imported", False)),
                    is_exported=bool(getattr(sym, "is_exported", False)),
                )
            )

        # Include Mach-O function starts if symbols are stripped
        if isinstance(binary, lief.MachO.Binary) and hasattr(binary, "function_starts"):
            imagebase = int(binary.imagebase or 0)
            fn_starts = getattr(binary.function_starts, "functions", [])
            for func_offset in fn_starts:
                func_va = imagebase + int(func_offset)
                if not any(s.address == func_va for s in symbols):
                    symbols.append(
                        Symbol(
                            name=f"sub_{func_va:x}",
                            address=func_va,
                            size=0,
                            type=SymbolType.FUNCTION,
                            is_imported=False,
                            is_exported=False,
                        )
                    )
        return symbols

    @classmethod
    def _extract_strings(
        cls, binary: Any, min_length: int = 4
    ) -> list[tuple[int, str, str]]:
        """
        Extract readable ASCII / UTF-8 strings from read-only data sections.
        Returns list of (virtual_address, string_value, section_name).
        """
        results: list[tuple[int, str, str]] = []
        target_sections = (".rodata", ".rdata", "__cstring", "__const", ".data", ".text")

        for sec in binary.sections:
            if not any(ts in sec.name.lower() for ts in target_sections):
                continue

            content = bytes(sec.content) if sec.content is not None else b""
            if not content:
                continue

            base_va = int(sec.virtual_address)
            current_bytes = bytearray()
            start_offset = 0

            for i, b in enumerate(content):
                if 0x20 <= b <= 0x7E:  # Printable ASCII
                    if not current_bytes:
                        start_offset = i
                    current_bytes.append(b)
                else:
                    if len(current_bytes) >= min_length:
                        try:
                            s = current_bytes.decode("utf-8")
                            results.append((base_va + start_offset, s, str(sec.name)))
                        except UnicodeDecodeError:
                            pass
                    current_bytes.clear()

            if len(current_bytes) >= min_length:
                try:
                    s = current_bytes.decode("utf-8")
                    results.append((base_va + start_offset, s, str(sec.name)))
                except UnicodeDecodeError:
                    pass

        return results
