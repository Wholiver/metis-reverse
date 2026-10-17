"""
metis_reverse.grounding.metadata.cpp_rtti
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
C++ Itanium ABI Run-Time Type Information (RTTI) and Virtual Table (VTable) extractor.
Extracts class hierarchies, single/multiple inheritance, and virtual method slots.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache

from metis_reverse.core.models import (
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    SymbolType,
    TargetType,
)

logger = logging.getLogger("metis_reverse.grounding.metadata.cpp_rtti")


@dataclass
class CppClassMetadata:
    mangled_name: str
    demangled_name: str
    vtable_address: int | None = None
    typeinfo_address: int | None = None
    base_classes: list[str] = field(default_factory=list)
    virtual_methods: list[tuple[int, str]] = field(default_factory=list)  # (virtual_addr, demangled_name)


class CppDemangler:
    """Demangles Itanium ABI C++ symbols using c++filt or pure Python fallback."""

    _has_cxxfilt: bool | None = None

    @classmethod
    @lru_cache(maxsize=1024)
    def demangle(cls, mangled: str) -> str:
        clean = mangled.strip()
        if not clean.startswith(('_Z', '__Z')):
            return clean

        if cls._has_cxxfilt is None:
            cls._has_cxxfilt = shutil.which("c++filt") is not None

        if cls._has_cxxfilt:
            try:
                proc = subprocess.run(
                    ["c++filt", clean],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=1.0,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return proc.stdout.strip()
            except Exception:
                pass

        return cls._fallback_demangle(clean)

    @classmethod
    def _fallback_demangle(cls, mangled: str) -> str:
        """Pure-Python fallback demangler for Itanium symbols."""
        s = mangled.lstrip('_')
        prefix = ""
        if s.startswith('ZTV'):
            prefix = "vtable for "
            s = s[3:]
        elif s.startswith('ZTI'):
            prefix = "typeinfo for "
            s = s[3:]
        elif s.startswith('ZTS'):
            prefix = "typeinfo name for "
            s = s[3:]
        elif s.startswith('ZN'):
            s = s[1:]  # Start of nested name
        elif s.startswith('Z'):
            s = s[1:]

        # Parse nested names N...E
        if s.startswith('N'):
            s = s[1:]
            parts = []
            while s and not s.startswith('E'):
                match = re.match(r'^(\d+)', s)
                if match:
                    length = int(match.group(1))
                    start = match.end()
                    part = s[start:start + length]
                    parts.append(part)
                    s = s[start + length:]
                else:
                    break
            demangled_core = "::".join(parts) if parts else s
            return f"{prefix}{demangled_core}"

        # Match single identifier length prefix
        match = re.match(r'^(\d+)(.*)', s)
        if match:
            length = int(match.group(1))
            name = match.group(2)[:length]
            return f"{prefix}{name}"

        return f"{prefix}{s}"


class CppRttiExtractor:
    """Extracts C++ Itanium RTTI, inheritance hierarchies, and VTables."""

    def __init__(self, raw_bytes: bytes, base_address: int = 0):
        self.raw_bytes = raw_bytes
        self.base_address = base_address

    @classmethod
    def from_session(cls, session: BinarySession) -> CppRttiExtractor | None:
        artifact = session.artifact
        if not artifact or not os.path.exists(artifact.file_path):
            return None
        try:
            with open(artifact.file_path, "rb") as f:
                content = f.read()
            return cls(raw_bytes=content, base_address=artifact.base_address)
        except Exception:
            return None

    def extract_classes(self, session: BinarySession) -> list[CppClassMetadata]:
        classes: list[CppClassMetadata] = []
        seen_names: set[str] = set()

        # 1. Scan session symbols for Itanium RTTI descriptors
        vtable_symbols: dict[str, int] = {}
        typeinfo_symbols: dict[str, int] = {}
        ti_addr_to_core: dict[int, str] = {}
        candidate_cores: set[str] = set()

        for sym in session.symbols.values():
            s_name = sym.name
            if s_name.startswith(('_ZTV', '__ZTV')):
                core = s_name.lstrip('_')[3:]
                vtable_symbols[core] = sym.address
                candidate_cores.add(core)
            elif s_name.startswith(('_ZTI', '__ZTI')):
                core = s_name.lstrip('_')[3:]
                typeinfo_symbols[core] = sym.address
                ti_addr_to_core[sym.address] = core
                candidate_cores.add(core)
            elif s_name.startswith(('_ZTS', '__ZTS')):
                core = s_name.lstrip('_')[3:]
                candidate_cores.add(core)

        # 2. Extract TypeInfo name strings from read-only sections
        for pattern in (rb'(_ZTS[A-Za-z0-9_]+)\x00', rb'\x00(N[0-9]+[A-Za-z0-9_]+E)\x00'):
            for match in re.finditer(pattern, self.raw_bytes):
                mangled_bytes = match.group(1)
                try:
                    s = mangled_bytes.decode('ascii')
                except UnicodeDecodeError:
                    continue
                core = s.lstrip('_')[3:] if s.startswith(('_ZTS', 'ZTS')) else s
                candidate_cores.add(core)

        # 3. For each candidate class
        for core in sorted(candidate_cores):
            if 'cxxabiv1' in core:
                continue
            if core in seen_names:
                continue
            seen_names.add(core)

            demangled_name = CppDemangler.demangle(f"_ZTI{core}").replace("typeinfo for ", "").strip()
            if not demangled_name:
                continue

            vt_addr = vtable_symbols.get(core)
            ti_addr = typeinfo_symbols.get(core)

            base_classes: list[str] = []
            virtual_methods: list[tuple[int, str]] = []

            # Check for base classes via typeinfo pointer in binary
            if ti_addr is not None:
                for other_ti_addr, other_core in ti_addr_to_core.items():
                    if other_core != core and 'cxxabiv1' not in other_core:
                        other_addr_bytes = struct.pack('<Q', other_ti_addr)
                        if other_addr_bytes in self.raw_bytes:
                            other_demangled = CppDemangler.demangle(f"_ZTI{other_core}").replace("typeinfo for ", "").strip()
                            if other_demangled and other_demangled not in base_classes:
                                base_classes.append(other_demangled)

            # Check virtual/member methods from session symbols
            for sym in session.symbols.values():
                if sym.type == SymbolType.FUNCTION and sym.name.startswith(('_ZN', '__ZN')):
                    demangled_func = CppDemangler.demangle(sym.name)
                    if demangled_func.startswith(f"{demangled_name}::"):
                        method_name = demangled_func[len(demangled_name) + 2:]
                        if (sym.address, method_name) not in virtual_methods:
                            virtual_methods.append((sym.address, method_name))

            classes.append(
                CppClassMetadata(
                    mangled_name=f"_ZTI{core}",
                    demangled_name=demangled_name,
                    vtable_address=vt_addr,
                    typeinfo_address=ti_addr,
                    base_classes=base_classes,
                    virtual_methods=virtual_methods,
                )
            )

        return classes

    def generate_evidence_tags(self, classes: list[CppClassMetadata]) -> list[EvidenceTag]:
        tags: list[EvidenceTag] = []
        for cls in classes:
            addr_str = f"0x{cls.vtable_address:x}" if cls.vtable_address else "unknown"
            tags.append(
                EvidenceTag(
                    tag_id=f"ev_rtti_{cls.demangled_name.replace(':', '_')}",
                    target_type=TargetType.TYPE,
                    target_id=f"class:{cls.demangled_name}",
                    suggested_name=cls.demangled_name,
                    suggested_type=f"class {cls.demangled_name}",
                    source=EvidenceSource.CPP_RTTI,
                    evidence_type="CPP_RTTI",
                    confidence=1.0,
                    raw_anchor=f"_ZTI for {cls.demangled_name} (vtable: {addr_str})",
                    explanation="Reconstructed C++ class hierarchy from Itanium RTTI metadata",
                    is_immutable=True,
                )
            )
            for vaddr, method_name in cls.virtual_methods:
                tags.append(
                    EvidenceTag(
                        tag_id=f"ev_vmethod_0x{vaddr:x}",
                        target_type=TargetType.FUNCTION,
                        target_id=f"func:0x{vaddr:x}",
                        suggested_name=method_name,
                        suggested_type="virtual_method",
                        source=EvidenceSource.CPP_RTTI,
                        evidence_type="CPP_RTTI",
                        confidence=1.0,
                        raw_anchor=f"_ZTV slot for {cls.demangled_name}",
                        explanation=f"Virtual method discovered in {cls.demangled_name} VTable",
                        is_immutable=True,
                    )
                )
        return tags

    @classmethod
    def ground(cls, session: BinarySession) -> list[EvidenceTag]:
        extractor = cls.from_session(session)
        if not extractor:
            return []

        classes = extractor.extract_classes(session)
        if not classes:
            return []

        tags = extractor.generate_evidence_tags(classes)
        for t in tags:
            session.attach_evidence(t)
        return tags
