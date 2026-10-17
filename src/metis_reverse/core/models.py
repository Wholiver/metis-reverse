"""
Metis Reverse - Core Domain Models
Canonical Pydantic v2 schemas for binary sessions, artifacts, control-flow structures,
symbols, decompiled code, and evidence grounding.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

# ============================================================================
# Helper Utilities
# ============================================================================

def extract_address_from_target_id(target_id: str | None) -> int | None:
    """Extract numerical virtual address from target_id string (hex or dec)."""
    if not target_id:
        return None
    clean = target_id.strip()
    match = re.search(r"(?:^|[:_])0x([0-9a-fA-F]+)\b", clean, re.IGNORECASE)
    if match:
        try:
            return int(match.group(1), 16)
        except ValueError:
            pass
    parts = clean.split(":")
    last_part = parts[-1].strip()
    if last_part.isdigit():
        try:
            return int(last_part, 10)
        except ValueError:
            pass
    return None


# ============================================================================
# Enums
# ============================================================================

class ArtifactFormat(StrEnum):
    """Supported binary and script formats."""
    ELF = "ELF"
    MACHO = "MACHO"
    PE = "PE"
    WASM = "WASM"
    DEX = "DEX"
    APK = "APK"
    JAVASCRIPT = "JAVASCRIPT"
    RAW = "RAW"


class ArchitectureType(StrEnum):
    """Target hardware and runtime architectures."""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    AARCH64 = "arm64"  # Canonical alias
    MIPS = "mips"
    RISCV64 = "riscv64"
    WASM = "wasm"
    DALVIK = "dalvik"
    JS = "js"
    UNKNOWN = "unknown"


class Endianness(StrEnum):
    """Byte ordering."""
    LITTLE = "little"
    BIG = "big"


class SectionPermission(StrEnum):
    """Memory protection flags."""
    READ = "r"
    WRITE = "w"
    EXECUTE = "x"


class OperandType(StrEnum):
    """Instruction operand classifications."""
    REGISTER = "register"
    IMMEDIATE = "immediate"
    MEMORY = "memory"
    FP_IMMEDIATE = "fp_immediate"


class BranchType(StrEnum):
    """Control flow transfer classifications."""
    FALLTHROUGH = "fallthrough"
    CONDITIONAL = "conditional"
    UNCONDITIONAL = "unconditional"
    CALL = "call"
    RETURN = "return"
    INDIRECT = "indirect"
    TRAP = "trap"


class CallingConvention(StrEnum):
    """ABI calling conventions."""
    SYSTEM_V_AMD64 = "sysv_amd64"
    MICROSOFT_X64 = "ms_x64"
    ARM64_AAPCS = "arm64_aapcs"
    CDECL = "cdecl"
    STDCALL = "stdcall"
    FASTCALL = "fastcall"
    GO_INTERNAL = "go_internal"
    UNKNOWN = "unknown"


class SymbolType(StrEnum):
    """Symbol classification."""
    FUNCTION = "function"
    FUNC = "function"  # Alias
    DATA = "data"
    IMPORT = "import"
    EXPORT = "export"
    VARIABLE = "variable"
    SECTION = "section"
    STRING_LITERAL = "string_literal"
    RTTI = "rtti"
    VTABLE = "vtable"


class EvidenceSource(StrEnum):
    """Provenance sources for deterministic symbol recovery."""
    GO_PCLNTAB = "GO_PCLNTAB"
    CPP_RTTI = "CPP_RTTI"
    ASSERT_MACRO = "ASSERT_MACRO"
    FORMAT_STRING = "FORMAT_STRING"
    SYSCALL_ABI = "SYSCALL_ABI"
    SYSCALL_INFERENCE = "SYSCALL_INFERENCE"
    SYSCALL_PROPAGATION = "syscall_propagation"
    LIBC_SEMANTICS = "LIBC_SEMANTICS"
    DEX_METADATA = "DEX_METADATA"
    JS_AST_PROPAGATION = "JS_AST_PROPAGATION"
    DYNAMIC_PROBE = "DYNAMIC_PROBE"
    USER_AGENT = "USER_AGENT"
    HEURISTIC = "HEURISTIC"


# Alias for compatibility with PROJECT.md and explorer survey reports
EvidenceType = EvidenceSource


class TargetType(StrEnum):
    """Target entity type for evidence grounding."""
    SYMBOL = "symbol"
    FUNCTION = "function"
    VARIABLE = "variable"
    PARAMETER = "parameter"
    STRUCT_FIELD = "struct_field"
    TYPE = "type"
    STRUCTURE = "type"  # Alias for composite structures


class ParameterLocation(StrEnum):
    """Parameter storage location."""
    REGISTER = "register"
    STACK = "stack"


# ============================================================================
# Core Domain Models
# ============================================================================

class BinarySection(BaseModel):
    """Represents a discrete memory section in an executable or object file."""
    model_config = ConfigDict(frozen=True, validate_assignment=True)

    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    permissions: list[SectionPermission] = Field(default_factory=list)
    entropy: float = Field(default=0.0, ge=0.0, le=8.0)


class TargetArtifact(BaseModel):
    """Parsed metadata describing the binary or script being analyzed."""
    model_config = ConfigDict(validate_assignment=True)

    artifact_id: str = Field(default="", description="SHA-256 hex digest of the artifact")
    file_path: str = Field(default="", description="Absolute path to target file")
    path: str | None = Field(default=None, description="Alias for file_path")
    file_name: str = Field(default="")
    file_size: int = Field(default=0, ge=0)
    size: int | None = Field(default=None, description="Alias for file_size")
    format: ArtifactFormat | str
    architecture: ArchitectureType | str
    bitness: int = Field(default=64, description="Target bitness: 16, 32, or 64")
    endianness: Endianness = Endianness.LITTLE
    base_address: int = 0
    entry_point: int = 0
    entry_points: list[int] = Field(default_factory=list)
    sections: list[BinarySection] = Field(default_factory=list)
    is_pie: bool = True
    is_stripped: bool = False
    compiler_fingerprint: str | None = None
    language_hint: str | None = None

    @field_validator("bitness")
    @classmethod
    def validate_bitness(cls, v: int) -> int:
        if v not in (16, 32, 64):
            raise ValueError(f"Invalid bitness: {v}. Must be 16, 32, or 64.")
        return v

    @field_validator("format", mode="before")
    @classmethod
    def coerce_format(cls, v: Any) -> ArtifactFormat:
        if isinstance(v, ArtifactFormat):
            return v
        if isinstance(v, str):
            clean = v.strip().upper()
            if clean in ArtifactFormat.__members__:
                return ArtifactFormat[clean]
            for member in ArtifactFormat:
                if member.value == clean:
                    return member
            return ArtifactFormat.RAW
        return ArtifactFormat.RAW

    @field_validator("architecture", mode="before")
    @classmethod
    def coerce_arch(cls, v: Any) -> ArchitectureType:
        if isinstance(v, ArchitectureType):
            return v
        if isinstance(v, str):
            clean = v.strip().lower()
            if clean in ("aarch64", "arm64"):
                return ArchitectureType.ARM64
            if clean in ("x86_64", "amd64", "x64"):
                return ArchitectureType.X86_64
            if clean in ("x86", "i386", "i686"):
                return ArchitectureType.X86
            if clean == "arm":
                return ArchitectureType.ARM
            for member in ArchitectureType:
                if member.value == clean:
                    return member
            return ArchitectureType.UNKNOWN
        return ArchitectureType.UNKNOWN

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Sync file_path / path
        file_path = data.get("file_path") or data.get("path") or ""
        data["file_path"] = file_path
        data["path"] = file_path

        # Sync file_size / size
        file_size = data.get("file_size") if data.get("file_size") is not None else data.get("size", 0)
        data["file_size"] = file_size
        data["size"] = file_size

        # File name
        if not data.get("file_name") and file_path:
            data["file_name"] = os.path.basename(file_path)

        # Artifact ID default
        if not data.get("artifact_id"):
            if file_path:
                data["artifact_id"] = hashlib.sha256(file_path.encode()).hexdigest()
            else:
                data["artifact_id"] = uuid.uuid4().hex

        # Sync entry_point / entry_points
        ep = data.get("entry_point", 0)
        eps = data.get("entry_points") or []
        if ep == 0 and eps:
            data["entry_point"] = eps[0]
        elif ep != 0 and not eps:
            data["entry_points"] = [ep]

        return data


class MemoryOperand(BaseModel):
    """Details for indirect or memory-dereference operands."""
    model_config = ConfigDict(frozen=True)

    base_register: str | None = None
    index_register: str | None = None
    scale: int = 1
    displacement: int = 0
    segment: str | None = None


class Operand(BaseModel):
    """Single instruction operand."""
    model_config = ConfigDict(frozen=True)

    type: OperandType
    value: str | int | float | MemoryOperand
    size_bytes: int = 0
    access: str = Field(default="r", description="'r' (read), 'w' (write), or 'rw' (read/write)")


class Instruction(BaseModel):
    """Decoded machine instruction."""
    model_config = ConfigDict(validate_assignment=True)

    address: int
    size: int = Field(default=4, gt=0)
    mnemonic: str
    op_str: str = ""
    raw_bytes: bytes = b""
    operands: list[Operand] = Field(default_factory=list)
    registers_read: list[str] = Field(default_factory=list)
    registers_written: list[str] = Field(default_factory=list)
    is_call: bool = False
    is_branch: bool = False
    is_ret: bool = False
    is_syscall: bool = False
    target_address: int | None = None
    evidence_tag_ids: list[str] = Field(default_factory=list)

    @field_validator("raw_bytes", mode="before")
    @classmethod
    def coerce_bytes(cls, v: Any) -> bytes:
        if isinstance(v, bytes):
            return v
        if isinstance(v, str):
            clean = v.strip().lower()
            if clean.startswith("0x"):
                clean = clean[2:]
            return bytes.fromhex(clean)
        if isinstance(v, list):
            return bytes(v)
        if v is None:
            return b""
        raise ValueError(f"Cannot coerce {type(v)} to bytes")

    @field_serializer("raw_bytes")
    def serialize_raw_bytes(self, v: bytes) -> str:
        return v.hex()


class BasicBlock(BaseModel):
    """Contiguous block of instructions with a single entry and single exit."""
    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default="")
    start_address: int
    end_address: int
    size: int = 0
    instructions: list[Instruction] = Field(default_factory=list)
    predecessors: list[int] = Field(default_factory=list)
    successors: list[int] = Field(default_factory=list)
    jump_targets: list[int] = Field(default_factory=list)
    terminator_type: BranchType = BranchType.FALLTHROUGH

    @model_validator(mode="before")
    @classmethod
    def sync_block_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        start = data.get("start_address", 0)
        end = data.get("end_address", 0)
        if not data.get("id"):
            data["id"] = f"bb_0x{start:x}"
        if not data.get("size") and end >= start:
            data["size"] = end - start
        if not data.get("successors") and data.get("jump_targets"):
            data["successors"] = data["jump_targets"]
        elif not data.get("jump_targets") and data.get("successors"):
            data["jump_targets"] = data["successors"]
        return data


class EvidenceTag(BaseModel):
    """Immutable proof anchor validating a symbol, variable name, or type."""
    model_config = ConfigDict(validate_assignment=True)

    tag_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:16],
        description="Deterministic or unique tag identifier",
    )
    target_type: TargetType = TargetType.FUNCTION
    target_id: str = Field(
        default="",
        description="Target identifier, e.g. 'func:0x401000' or 'sym:g_config'",
    )
    suggested_name: str | None = None
    suggested_type: str | None = None
    source: EvidenceSource = EvidenceSource.HEURISTIC
    evidence_type: str | None = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    raw_anchor: str = Field(
        default="",
        description="Verifiable factual proof",
    )
    explanation: str = ""
    context_snippet: str | None = None
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    is_immutable: bool = Field(
        default=False,
        description="True if proven by binary metadata (cannot be overwritten by agent)",
    )

    @model_validator(mode="before")
    @classmethod
    def sync_source_and_type(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        ev_type = data.get("evidence_type")
        source = data.get("source")

        def _match_source(val: Any) -> EvidenceSource | None:
            if isinstance(val, EvidenceSource):
                return val
            if not isinstance(val, str):
                return None
            clean = val.strip()
            try:
                return EvidenceSource(clean)
            except ValueError:
                pass
            clean_lower = clean.lower()
            for s in EvidenceSource:
                if s.value.lower() == clean_lower or s.name.lower() == clean_lower:
                    return s
            return None

        matched_source = _match_source(source) or _match_source(ev_type)
        if matched_source is not None:
            data["source"] = matched_source
            if not ev_type:
                data["evidence_type"] = matched_source.value
            else:
                data["evidence_type"] = str(ev_type)
        else:
            if not source and ev_type:
                data["source"] = EvidenceSource.HEURISTIC
                data["evidence_type"] = str(ev_type)
            elif source and not ev_type:
                data["evidence_type"] = source.value if isinstance(source, EvidenceSource) else str(source)
        return data

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime) -> str:
        return dt.isoformat()


class Variable(BaseModel):
    """Generic representation of a typed parameter or variable."""
    model_config = ConfigDict(validate_assignment=True)

    name: str
    type: str = "void*"
    location: str | None = None


class FunctionParameter(BaseModel):
    """Parameter definition for a disassembled/decompiled function."""
    model_config = ConfigDict(validate_assignment=True)

    index: int = 0
    name: str
    type_name: str = "void*"
    location: str = "register"  # "register" or "stack"
    register_or_offset: str = ""
    evidence_tag_ids: list[str] = Field(default_factory=list)


class LocalVariable(BaseModel):
    """Local stack or register variable within a function scope."""
    model_config = ConfigDict(validate_assignment=True)

    id: str
    name: str
    type_name: str = "uint64_t"
    storage_offset: int = 0
    scope_start: int = 0
    scope_end: int = 0
    evidence_tag_ids: list[str] = Field(default_factory=list)


class Symbol(BaseModel):
    """Named entry in the binary symbol table."""
    model_config = ConfigDict(validate_assignment=True)

    address: int
    name: str
    type: SymbolType = SymbolType.FUNCTION
    size: int = 0
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    demangled_name: str | None = None
    is_imported: bool = False
    is_exported: bool = False
    evidence_tags: list[EvidenceTag] = Field(default_factory=list)
    evidence_tag_ids: list[str] = Field(default_factory=list)
    is_user_mutated: bool = False
    original_name: str | None = None


class DecompiledCode(BaseModel):
    """Structured high-level representation (C/Go/JS) of a decompiled function."""
    model_config = ConfigDict(validate_assignment=True)

    function_address: int
    function_name: str | None = None
    language: str = "c"
    source_code: str = ""
    code: str | None = None
    line_to_address_map: dict[int, list[int]] = Field(default_factory=dict)
    address_to_line_map: dict[int, int] = Field(default_factory=dict)
    variable_mapping: dict[str, str] = Field(default_factory=dict)
    evidence_annotations: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def sync_code_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        sc = data.get("source_code")
        c = data.get("code")
        if c and not sc:
            data["source_code"] = c
            data["code"] = c
        elif sc and not c:
            data["code"] = sc
            data["source_code"] = sc
        return data


class Function(BaseModel):
    """Comprehensive representation of a function."""
    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default="")
    name: str
    address: int
    size: int = 0
    is_stripped: bool = False
    calling_convention: CallingConvention = CallingConvention.UNKNOWN
    return_type: str = "void"
    parameters: list[Any] = Field(default_factory=list)
    local_variables: list[LocalVariable] = Field(default_factory=list)
    basic_blocks: list[BasicBlock] = Field(default_factory=list)
    callers: list[int] = Field(default_factory=list)
    callees: list[int] = Field(default_factory=list)
    decompiled_code: str | DecompiledCode | None = None
    evidence_tag_ids: list[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @model_validator(mode="before")
    @classmethod
    def init_id(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if not data.get("id"):
            addr = data.get("address", 0)
            data["id"] = f"func_0x{addr:x}"
        return data


# ============================================================================
# Milestone 4 Composite Structure Models
# ============================================================================

class StructField(BaseModel):
    """Discrete field within a user-defined or recovered struct layout."""
    model_config = ConfigDict(validate_assignment=True)

    name: str
    type_name: str
    offset: int = Field(default=0, ge=0)
    size: int = Field(default=0, ge=0)
    alignment: int = Field(default=1, ge=1)
    is_pointer: bool = False
    array_count: int | None = None
    description: str | None = None

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


class StructDefinition(BaseModel):
    """Complete layout definition of a composite C/C++ struct."""
    model_config = ConfigDict(validate_assignment=True)

    name: str
    fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Field mapping from identifier to C type or StructField",
    )
    size: int = Field(default=0, ge=0)
    alignment: int = Field(default=1, ge=1)
    field_offsets: dict[str, int] = Field(default_factory=dict)
    is_packed: bool = False
    evidence_tag_ids: list[str] = Field(default_factory=list)

    @property
    def total_size(self) -> int:
        return self.size

    @total_size.setter
    def total_size(self, val: int) -> None:
        self.size = val

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> StructDefinition:
            return self
        return _identity().__await__()

    @classmethod
    def calculate_layout(
        cls,
        fields: dict[str, str | StructField],
        is_packed: bool = False,
        bitness: int = 64,
    ) -> tuple[int, int, dict[str, int]]:
        """Calculate field offsets, overall size, and alignment following C ABI rules."""
        type_sizes: dict[str, tuple[int, int]] = {
            "char": (1, 1), "int8_t": (1, 1), "uint8_t": (1, 1), "bool": (1, 1), "unsigned char": (1, 1),
            "short": (2, 2), "int16_t": (2, 2), "uint16_t": (2, 2), "unsigned short": (2, 2),
            "int": (4, 4), "uint32_t": (4, 4), "int32_t": (4, 4), "unsigned int": (4, 4), "float": (4, 4),
            "long": (8, 8), "unsigned long": (8, 8), "long long": (8, 8), "uint64_t": (8, 8), "int64_t": (8, 8),
            "double": (8, 8), "size_t": (8, 8), "ssize_t": (8, 8), "uintptr_t": (8, 8), "intptr_t": (8, 8),
            "pointer": (8, 8),
        }
        ptr_size = bitness // 8
        current_offset = 0
        max_align = 1
        offsets: dict[str, int] = {}

        for field_name, f_val in fields.items():
            type_str = f_val.type_name if isinstance(f_val, StructField) else str(f_val).strip()
            clean = type_str.strip()

            arr_match = re.match(r"^(.*?)\s*\[(\d+)\]$", clean)
            if clean.endswith("*") or clean.startswith("void*"):
                f_size, f_align = ptr_size, ptr_size
            elif arr_match:
                elem_type = arr_match.group(1).strip()
                count = int(arr_match.group(2))
                elem_size, elem_align = type_sizes.get(elem_type, (ptr_size, ptr_size))
                f_size = elem_size * count
                f_align = 1 if is_packed else elem_align
            else:
                f_size, f_align = type_sizes.get(clean, (ptr_size, ptr_size))

            if is_packed:
                f_align = 1

            if not is_packed and f_align > 1:
                if current_offset % f_align != 0:
                    current_offset += f_align - (current_offset % f_align)
                max_align = max(max_align, f_align)

            offsets[field_name] = current_offset
            current_offset += f_size

        if not is_packed and max_align > 1 and current_offset % max_align != 0:
            current_offset += max_align - (current_offset % max_align)

        return current_offset, (1 if is_packed else max_align), offsets


class BinarySession(BaseModel):
    """Complete in-memory analysis session state."""
    model_config = ConfigDict(validate_assignment=True)

    session_id: str = Field(
        default_factory=lambda: f"sess_{uuid.uuid4().hex[:12]}",
        description="Unique session identifier",
    )
    artifact: TargetArtifact
    backend_type: str = "tier1_native"
    functions: dict[int, Function] = Field(default_factory=dict)
    symbols: dict[Any, Symbol] = Field(default_factory=dict)
    symbols_by_address: dict[int, Symbol] = Field(default_factory=dict)
    struct_definitions: dict[str, StructDefinition] = Field(default_factory=dict)
    evidence_tags: dict[str, EvidenceTag] = Field(default_factory=dict)
    evidence_store: Any | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_accessed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def define_struct(self, struct_def: StructDefinition) -> None:
        """Register a user-defined or recovered struct definition."""
        self.struct_definitions[struct_def.name] = struct_def

    def add_struct_definition(self, struct_def: StructDefinition) -> None:
        """Register a struct definition."""
        self.struct_definitions[struct_def.name] = struct_def

    def get_struct_definition(self, name: str) -> StructDefinition | None:
        """Lookup struct definition by name."""
        return self.struct_definitions.get(name)

    def add_symbol(self, symbol: Symbol) -> None:
        """Register a symbol with bidirectional lookup and bind existing evidence."""
        self.symbols[symbol.name] = symbol
        self.symbols[symbol.address] = symbol
        self.symbols_by_address[symbol.address] = symbol

        # Synchronize any pre-existing evidence tags targeting this symbol
        for tag in self.evidence_tags.values():
            tag_addr = extract_address_from_target_id(tag.target_id)
            cand_names = {tag.target_id}
            if ":" in tag.target_id:
                cand_names.add(tag.target_id.split(":", 1)[-1].strip())
            if tag.suggested_name:
                cand_names.add(tag.suggested_name.strip())

            if (
                (tag_addr is not None and tag_addr == symbol.address)
                or (symbol.name in cand_names)
                or (symbol.demangled_name and symbol.demangled_name in cand_names)
            ):
                if tag.tag_id not in symbol.evidence_tag_ids:
                    symbol.evidence_tag_ids.append(tag.tag_id)
                if not any(t.tag_id == tag.tag_id for t in symbol.evidence_tags):
                    symbol.evidence_tags.append(tag)

    def get_function(self, address: int) -> Function | None:
        """Lookup function by entry address."""
        return self.functions.get(address)

    def attach_evidence(self, tag: EvidenceTag) -> None:
        """Register an evidence tag and bind it to the target entity."""
        self.evidence_tags[tag.tag_id] = tag
        if self.evidence_store is not None and hasattr(self.evidence_store, "add_tag"):
            with contextlib.suppress(Exception):
                self.evidence_store.add_tag(tag)

        tag_addr = extract_address_from_target_id(tag.target_id)
        cand_names: set[str] = set()
        if tag.target_id:
            cand_names.add(tag.target_id.strip())
            if ":" in tag.target_id:
                cand_names.add(tag.target_id.split(":", 1)[-1].strip())
        if tag.suggested_name:
            cand_names.add(tag.suggested_name.strip())

        # Bind to matching symbols (keyed by address to avoid unhashable Symbol)
        matched_syms: dict[int, Symbol] = {}
        if tag_addr is not None and tag_addr in self.symbols_by_address:
            sym = self.symbols_by_address[tag_addr]
            matched_syms[sym.address] = sym
        for name in cand_names:
            if name and name in self.symbols:
                sym = self.symbols[name]
                matched_syms[sym.address] = sym
        if tag.target_type == TargetType.SYMBOL:
            for sym in self.symbols_by_address.values():
                if (
                    (tag_addr is not None and sym.address == tag_addr)
                    or (sym.name in cand_names)
                    or (sym.demangled_name and sym.demangled_name in cand_names)
                ):
                    matched_syms[sym.address] = sym

        for sym in matched_syms.values():
            if tag.tag_id not in sym.evidence_tag_ids:
                sym.evidence_tag_ids.append(tag.tag_id)
            if not any(t.tag_id == tag.tag_id for t in sym.evidence_tags):
                sym.evidence_tags.append(tag)

        # Bind to matching functions
        if (
            tag_addr is not None
            and tag_addr in self.functions
            and tag.tag_id not in self.functions[tag_addr].evidence_tag_ids
        ):
            self.functions[tag_addr].evidence_tag_ids.append(tag.tag_id)
        for name in cand_names:
            if name:
                for func in self.functions.values():
                    if func.name == name and tag.tag_id not in func.evidence_tag_ids:
                        func.evidence_tag_ids.append(tag.tag_id)


# ============================================================================
# MCP Response DTOs
# ============================================================================

class SessionInfo(BaseModel):
    """MCP summary returned upon opening or querying a session."""
    session_id: str
    artifact_id: str
    file_path: str
    file_name: str
    format: str
    architecture: str
    bitness: int
    entry_point: str
    backend: str
    total_functions: int
    total_symbols: int
    is_stripped: bool
    created_at: str
    artifact: TargetArtifact | dict[str, Any] | None = None

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> SessionInfo:
            return self
        return _identity().__await__()


class FunctionSummary(BaseModel):
    """Brief function metadata for tool listings."""
    address: int
    name: str
    size: int = 0
    address_int: int | None = None
    address_hex: str | None = None
    calling_convention: str = "cdecl"
    parameter_count: int = 0
    basic_block_count: int = 0
    is_stripped: bool = False
    has_decompiled_code: bool = False
    confidence: float = 0.0
    top_evidence_source: str | None = None

    @field_validator("address", mode="before")
    @classmethod
    def coerce_address(cls, v: Any) -> int:
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            clean = v.strip()
            return int(clean, 16 if clean.lower().startswith("0x") else 10)
        return int(v)

    @model_validator(mode="after")
    def sync_address_aliases(self) -> FunctionSummary:
        if self.address_int is None:
            self.address_int = self.address
        if self.address_hex is None:
            self.address_hex = f"0x{self.address:x}"
        return self

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


class DisassemblyResult(BaseModel):
    """Result of disassembling a range of bytes or a function."""
    session_id: str
    start_address: str
    instruction_count: int
    instructions: list[Instruction]

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> DisassemblyResult:
            return self
        return _identity().__await__()


class DecompiledFunctionResult(BaseModel):
    """High-level decompiled code result for MCP clients."""
    session_id: str
    function_address: str
    function_name: str
    language: str
    source_code: str
    decompiled_code: str | None = None
    evidence_annotations: list[dict[str, Any]] = Field(default_factory=list)
    confidence_score: float = 0.0

    @model_validator(mode="after")
    def sync_decompiled_code(self) -> DecompiledFunctionResult:
        if self.decompiled_code is None:
            self.decompiled_code = self.source_code
        return self

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> DecompiledFunctionResult:
            return self
        return _identity().__await__()


class SessionCloseResult(BaseModel):
    """Response when a session is terminated."""
    session_id: str
    closed: bool
    message: str

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> SessionCloseResult:
            return self
        return _identity().__await__()


class MutationResult(BaseModel):
    """Response when mutating symbols, types, or structures."""
    session_id: str
    mutation_type: str
    target: str
    old_value: str | None = None
    new_value: str
    success: bool
    message: str

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> MutationResult:
            return self
        return _identity().__await__()


# ============================================================================
# Dynamic Tracing & Memory Probing Models
# ============================================================================

class TraceEventType(StrEnum):
    """Classification of dynamic execution and memory events."""
    CALL = "CALL"
    ENTER = "ENTER"
    LEAVE = "LEAVE"
    RET = "RET"
    MEM_READ = "MEM_READ"
    MEM_WRITE = "MEM_WRITE"
    SYSCALL = "SYSCALL"
    INSTRUCTION = "INSTRUCTION"
    EXEC = "EXEC"
    BRANCH = "BRANCH"
    BLOCK = "BLOCK"
    EXCEPTION = "EXCEPTION"


class TraceEvent(BaseModel):
    """Discrete runtime execution observation during dynamic tracing."""
    model_config = ConfigDict(validate_assignment=True)

    step: int = 0
    timestamp: float | str | None = None
    event_type: TraceEventType | str = TraceEventType.INSTRUCTION
    address: int | str = 0
    caller: str | None = None
    target_address: int | None = None
    arguments: list[Any] = Field(default_factory=list)
    return_value: Any | None = None
    captured_strings: list[str] = Field(default_factory=list)
    memory_dumps: dict[str, str] = Field(default_factory=dict)
    registers: dict[str, Any] = Field(default_factory=dict)
    memory_access: dict[str, Any] | None = None
    thread_id: int | None = None
    depth: int = 0
    details: dict[str, Any] | str = Field(default_factory=dict)

    @field_validator("event_type", mode="before")
    @classmethod
    def coerce_event_type(cls, v: Any) -> TraceEventType | str:
        if isinstance(v, TraceEventType):
            return v
        if isinstance(v, str):
            clean = v.strip().upper()
            if clean in TraceEventType.__members__:
                return TraceEventType[clean]
            for m in TraceEventType:
                if m.value.upper() == clean:
                    return m
            return clean
        return str(v)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


class TraceResult(BaseModel):
    """Comprehensive dynamic trace execution output."""
    model_config = ConfigDict(validate_assignment=True)

    success: bool = True
    session_id: str = Field(default="")
    function_address: int | str = Field(default=0)
    function_name: str | None = None
    prober: str = "auto"
    prober_used: str = "auto"
    return_value: Any | None = None
    return_type: str | None = None
    events: list[TraceEvent] = Field(default_factory=list)
    captured_strings: list[str] = Field(default_factory=list)
    memory_dumps: dict[str, str] = Field(default_factory=dict)
    modified_registers: dict[str, Any] = Field(default_factory=dict)
    instructions_executed: int = 0
    execution_time_ms: float = 0.0
    error: str | None = None

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> TraceResult:
            return self
        return _identity().__await__()

# ============================================================================
# Equivalence & Recompilation Differential Verification Models
# ============================================================================

class DifferentialVectorResult(BaseModel):
    """Execution comparison outcome for a single test vector."""
    model_config = ConfigDict(validate_assignment=True)

    vector_name: str
    passed: bool
    original_exit_code: int
    reconstructed_exit_code: int
    original_stdout: str = ""
    reconstructed_stdout: str = ""
    original_stderr: str = ""
    reconstructed_stderr: str = ""
    diff_details: str | None = None
    vector_id: str | None = None

    @model_validator(mode="after")
    def sync_vector_id(self) -> DifferentialVectorResult:
        if self.vector_id is None:
            self.vector_id = self.vector_name
        return self

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> DifferentialVectorResult:
            return self
        return _identity().__await__()


class DifferentialResult(BaseModel):
    """Aggregate result from multi-vector differential testing."""
    model_config = ConfigDict(validate_assignment=True)

    session_id: str
    all_passed: bool
    total_vectors: int
    passed_vectors: int
    equivalence_percentage: float
    vector_results: list[DifferentialVectorResult] = Field(default_factory=list)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> DifferentialResult:
            return self
        return _identity().__await__()


class RecompileResult(BaseModel):
    """Outcome of sandboxed recompilation and closed-loop equivalence check."""
    model_config = ConfigDict(validate_assignment=True)

    session_id: str
    success: bool
    binary_path: str | None = None
    compile_errors: str = ""
    compile_warnings: str = ""
    equivalence_percentage: float = 0.0
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)
    differential_report: dict[str, Any] | None = None

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __await__(self) -> Any:
        async def _identity() -> RecompileResult:
            return self
        return _identity().__await__()


# ============================================================================
# Dynamic Prober Exceptions
# ============================================================================

class DynamicProberError(Exception):
    """Base exception for dynamic tracing failures."""
    pass


class ArchitectureCompatibilityError(DynamicProberError):
    """Raised when host architecture or OS cannot run target binary natively."""
    pass


class FridaNotAvailableError(DynamicProberError):
    """Raised when Frida runtime or device is missing/unusable."""
    pass


class FridaAttachError(DynamicProberError):
    """Raised when Frida cannot attach to target process."""
    pass


class TraceTimeoutError(DynamicProberError):
    """Raised when execution exceeds allocated timeout duration."""
    pass


class EmulationTimeoutError(DynamicProberError):
    """Raised when emulation exceeds maximum cycles or timeout."""
    pass


