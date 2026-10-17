"""
Metis Reverse - High-Fidelity Mock Decompiler Backend
Provides realistic simulation of Ghidra/IDA responses for deterministic unit testing.
"""

from __future__ import annotations

import copy
import os
import re
import uuid
from typing import Any

from metis_reverse.backends.base import BaseBackend
from metis_reverse.core.evidence import EvidenceStore
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BasicBlock,
    BinarySection,
    BinarySession,
    DecompiledCode,
    Function,
    Instruction,
    SectionPermission,
    Symbol,
    SymbolType,
    TargetArtifact,
    Variable,
)


class MockDecompilerBackend(BaseBackend):
    """
    High-fidelity in-memory decompiler engine simulating Tier 2 behavior.
    """

    def __init__(
        self,
        simulate_failures: bool = False,
        fail_addresses: set[int] | None = None,
    ) -> None:
        self.simulate_failures = simulate_failures
        self.fail_addresses: set[int] = fail_addresses or set()
        self.calls_log: list[dict[str, Any]] = []
        self.mutations_log: list[dict[str, Any]] = []
        self._custom_functions: dict[int, Function] = {}
        self._custom_code: dict[int, str] = {}

    @property
    def name(self) -> str:
        return "mock"

    @property
    def tier(self) -> int:
        return 2

    def _record_call(self, method: str, **kwargs: Any) -> None:
        self.calls_log.append({"method": method, "args": kwargs})

    def has_called(self, method: str, **kwargs: Any) -> bool:
        """Check if method was called with matching arguments."""
        for call in self.calls_log:
            if call["method"] == method:
                match = True
                for k, v in kwargs.items():
                    if call["args"].get(k) != v:
                        match = False
                        break
                if match:
                    return True
        return False

    def register_function_fixture(
        self,
        address: int,
        name: str,
        decompiled_code: str,
        size: int = 48,
        return_type: str = "int",
        parameters: list[Variable] | None = None,
    ) -> None:
        """Seed specific function responses for test targets."""
        fn = Function(
            address=address,
            name=name,
            size=size,
            is_stripped=False,
            basic_blocks=[
                BasicBlock(
                    start_address=address,
                    end_address=address + size,
                    size=size,
                    jump_targets=[],
                )
            ],
            parameters=parameters or [],
            return_type=return_type,
            decompiled_code=decompiled_code,
            evidence_tag_ids=[],
        )
        self._custom_functions[address] = fn
        self._custom_code[address] = decompiled_code

    # -------------------------------------------------------------------------
    # BaseBackend Implementation
    # -------------------------------------------------------------------------
    def load_artifact(
        self, artifact_or_path: str | TargetArtifact
    ) -> BinarySession:
        if isinstance(artifact_or_path, TargetArtifact):
            artifact = artifact_or_path
            if not artifact.sections and artifact.file_path and os.path.exists(artifact.file_path):
                from metis_reverse.backends.tier1_native.binary_parser import LiefBinaryParser
                try:
                    parsed_art, _, _ = LiefBinaryParser.parse(str(artifact.file_path))
                    artifact = parsed_art
                except Exception:
                    pass
        else:
            from metis_reverse.backends.tier1_native.binary_parser import LiefBinaryParser
            try:
                artifact, _, _ = LiefBinaryParser.parse(str(artifact_or_path))
            except Exception:
                artifact = TargetArtifact(
                    artifact_id=f"mock_{uuid.uuid4().hex[:8]}",
                    file_path=str(artifact_or_path),
                    file_name=os.path.basename(str(artifact_or_path)),
                    file_size=1024,
                    format=ArtifactFormat.ELF,
                    architecture=ArchitectureType.X86_64,
                )

        if artifact.architecture == ArchitectureType.UNKNOWN or str(artifact.architecture).lower() in ("unknown", "architecturetype.unknown"):
            artifact.architecture = ArchitectureType.X86_64

        if not artifact.sections:
            artifact.sections = [
                BinarySection(
                    name=".text",
                    virtual_address=0x1000,
                    virtual_size=0x1000,
                    raw_offset=0x1000,
                    raw_size=0x1000,
                    permissions=[SectionPermission.READ, SectionPermission.EXECUTE],
                    entropy=0.0,
                )
            ]

        self._record_call("load_artifact", artifact_path=artifact.file_path or getattr(artifact, "path", ""))

        session_id = f"mock-session-{uuid.uuid4().hex[:8]}"
        functions: dict[int, Function] = {}
        symbols: dict[Any, Symbol] = {}

        # 1. Populate custom seeded functions if any
        for addr, fn in self._custom_functions.items():
            functions[addr] = copy.deepcopy(fn)
            sym = Symbol(
                address=addr,
                name=fn.name,
                type=SymbolType.FUNCTION,
                size=fn.size,
                confidence=1.0,
            )
            symbols[fn.name] = sym
            symbols[addr] = sym

        # 2. If no custom functions registered, provide standard high-fidelity mock binary
        if not functions:
            main_addr = artifact.entry_point or 0x100003F10
            verify_addr = 0x100003E40
            hash_addr = 0x100003D20

            functions[main_addr] = Function(
                address=main_addr,
                name="main",
                size=64,
                is_stripped=False,
                basic_blocks=[
                    BasicBlock(
                        start_address=main_addr,
                        end_address=main_addr + 32,
                        size=32,
                        jump_targets=[main_addr + 32],
                    ),
                    BasicBlock(
                        start_address=main_addr + 32,
                        end_address=main_addr + 64,
                        size=32,
                        jump_targets=[],
                    ),
                ],
                parameters=[
                    Variable(name="argc", type="int", location="rdi"),
                    Variable(name="argv", type="char **", location="rsi"),
                ],
                return_type="int",
                decompiled_code=(
                    "int main(int argc, char **argv) {\n"
                    "    int status;\n"
                    "    if (argc < 2) {\n"
                    '        printf("Usage: %s <key>\\n", *argv);\n'
                    "        return 1;\n"
                    "    }\n"
                    "    status = verify_license(argv[1], 16);\n"
                    "    return status;\n"
                    "}\n"
                ),
                evidence_tag_ids=[],
            )

            functions[verify_addr] = Function(
                address=verify_addr,
                name="verify_license",
                size=80,
                is_stripped=False,
                basic_blocks=[
                    BasicBlock(
                        start_address=verify_addr,
                        end_address=verify_addr + 80,
                        size=80,
                        jump_targets=[],
                    )
                ],
                parameters=[
                    Variable(name="key", type="const char *", location="rdi"),
                    Variable(name="length", type="int", location="rsi"),
                ],
                return_type="int",
                decompiled_code=(
                    "int verify_license(const char *key, int length) {\n"
                    "    int32_t hash_val;\n"
                    "    if (key == (char *)0x0 || length <= 0) {\n"
                    "        return 0;\n"
                    "    }\n"
                    "    hash_val = calculate_hash((const uint8_t *)key, (size_t)length);\n"
                    "    return (hash_val == 0x5a3c1f);\n"
                    "}\n"
                ),
                evidence_tag_ids=[],
            )

            functions[hash_addr] = Function(
                address=hash_addr,
                name="calculate_hash",
                size=48,
                is_stripped=False,
                basic_blocks=[
                    BasicBlock(
                        start_address=hash_addr,
                        end_address=hash_addr + 48,
                        size=48,
                        jump_targets=[],
                    )
                ],
                parameters=[
                    Variable(name="data", type="const uint8_t *", location="rdi"),
                    Variable(name="len", type="size_t", location="rsi"),
                ],
                return_type="int32_t",
                decompiled_code=(
                    "int32_t calculate_hash(const uint8_t *data, size_t len) {\n"
                    "    uint32_t h = 0x811c9dc5;\n"
                    "    for (size_t i = 0; i < len; i++) {\n"
                    "        h = (h ^ data[i]) * 0x01000193;\n"
                    "    }\n"
                    "    return (int32_t)h;\n"
                    "}\n"
                ),
                evidence_tag_ids=[],
            )

            for fn in functions.values():
                sym = Symbol(
                    address=fn.address,
                    name=fn.name,
                    type=SymbolType.FUNCTION,
                    size=fn.size,
                    confidence=1.0,
                )
                symbols[fn.name] = sym
                symbols[fn.address] = sym

        return BinarySession(
            session_id=session_id,
            artifact=artifact,
            backend_type="mock",
            functions=functions,
            symbols=symbols,
            evidence_store=EvidenceStore(),
        )

    def disassemble_range(
        self, session: BinarySession, start_addr: int, size: int
    ) -> list[Instruction]:
        self._record_call("disassemble_range", start_addr=start_addr, size=size)
        if self.simulate_failures or start_addr in self.fail_addresses:
            raise RuntimeError(f"Mock disassembly failure at 0x{start_addr:x}")

        instructions: list[Instruction] = []
        arch_str = session.artifact.architecture.value.lower() if hasattr(session.artifact.architecture, "value") else str(session.artifact.architecture).lower()
        is_arm64 = "arm64" in arch_str or "aarch64" in arch_str
        curr_addr = start_addr
        end_addr = start_addr + size

        step = 4 if is_arm64 else 5
        count = 0
        while curr_addr < end_addr:
            if is_arm64:
                mnemonics = [
                    ("stp", "x29, x30, [sp, #-16]!"),
                    ("mov", "x29, sp"),
                    ("sub", "sp, sp, #0x20"),
                    ("str", "w0, [sp, #0x1c]"),
                    ("ldr", "w0, [sp, #0x1c]"),
                    ("add", "w0, w0, #1"),
                    ("ldp", "x29, x30, [sp], #16"),
                    ("ret", ""),
                ]
                mnem, op_str = mnemonics[count % len(mnemonics)]
                raw = b"\x1f\x20\x03\xd5"
            else:
                mnemonics = [
                    ("push", "rbp"),
                    ("mov", "rbp, rsp"),
                    ("sub", "rsp, 0x20"),
                    ("mov", "dword ptr [rbp - 4], edi"),
                    ("mov", "eax, dword ptr [rbp - 4]"),
                    ("add", "eax, 1"),
                    ("pop", "rbp"),
                    ("ret", ""),
                ]
                mnem, op_str = mnemonics[count % len(mnemonics)]
                raw = b"\x90\x90\x90\x90\x90"

            instructions.append(
                Instruction(
                    address=curr_addr,
                    mnemonic=mnem,
                    op_str=op_str,
                    size=step,
                    raw_bytes=raw,
                )
            )
            curr_addr += step
            count += 1

        return instructions

    def get_cfg(
        self, session: BinarySession, func_addr: int | None = None
    ) -> dict[str, Any]:
        self._record_call("get_cfg", session_id=session.session_id)
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        for fn in session.functions.values():
            if func_addr is not None and fn.address != func_addr:
                continue
            for i, bb in enumerate(fn.basic_blocks):
                nodes.append({
                    "id": f"bb_{bb.start_address:x}",
                    "function": fn.name,
                    "start": bb.start_address,
                    "end": bb.end_address,
                    "size": bb.size,
                })
                if i + 1 < len(fn.basic_blocks):
                    next_bb = fn.basic_blocks[i + 1]
                    edges.append({
                        "source": f"bb_{bb.start_address:x}",
                        "target": f"bb_{next_bb.start_address:x}",
                        "type": "fallthrough",
                    })

        return {
            "entry_point": session.artifact.entry_point,
            "nodes": nodes,
            "edges": edges,
            "total_blocks": len(nodes),
        }

    def decompile_function(
        self, session: BinarySession, func_addr: int
    ) -> DecompiledCode:
        self._record_call("decompile_function", func_addr=func_addr)
        if self.simulate_failures or func_addr in self.fail_addresses:
            raise RuntimeError(f"Decompilation failed for address 0x{func_addr:x}")

        fn = session.functions.get(func_addr)
        if fn and fn.decompiled_code:
            code = (
                fn.decompiled_code.source_code
                if isinstance(fn.decompiled_code, DecompiledCode)
                else str(fn.decompiled_code)
            )
            name = fn.name
        else:
            name = f"sub_{func_addr:x}"
            code = (
                f"/* Simulated Decompiler Output for {name} @ 0x{func_addr:x} */\n"
                f"undefined8 {name}(undefined8 param_1, undefined8 param_2) {{\n"
                f"    int32_t iVar1;\n"
                f"    iVar1 = (int32_t)param_1 + (int32_t)param_2;\n"
                f"    return (undefined8)iVar1;\n"
                f"}}\n"
            )

        return DecompiledCode(
            function_address=func_addr,
            function_name=name,
            source_code=code,
            code=code,
            language="c",
        )

    def mutate_symbol(
        self, session: BinarySession, addr: int, new_name: str
    ) -> bool:
        self._record_call("mutate_symbol", addr=addr, new_name=new_name)

        target_fn = session.functions.get(addr)
        old_name = target_fn.name if target_fn else f"sub_{addr:x}"

        # 1. Update Function record
        if target_fn:
            target_fn.name = new_name
            if target_fn.decompiled_code:
                pattern = r"\b" + re.escape(old_name) + r"\b"
                if isinstance(target_fn.decompiled_code, DecompiledCode):
                    target_fn.decompiled_code.source_code = re.sub(
                        pattern, new_name, target_fn.decompiled_code.source_code
                    )
                else:
                    target_fn.decompiled_code = re.sub(pattern, new_name, str(target_fn.decompiled_code))

        # 2. Update Symbol in session
        if old_name in session.symbols:
            sym = session.symbols.pop(old_name)
            sym.name = new_name
            session.symbols[new_name] = sym
            session.symbols[addr] = sym
        else:
            sym = Symbol(
                address=addr,
                name=new_name,
                type=SymbolType.FUNCTION,
                size=target_fn.size if target_fn else 32,
                confidence=1.0,
            )
            session.symbols[new_name] = sym
            session.symbols[addr] = sym

        if addr in session.symbols_by_address:
            session.symbols_by_address[addr].name = new_name

        # 3. Propagate renaming across all decompiled functions in session
        pattern = r"\b" + re.escape(old_name) + r"\b"
        for fn in session.functions.values():
            if fn.decompiled_code and fn.address != addr:
                if isinstance(fn.decompiled_code, DecompiledCode):
                    fn.decompiled_code.source_code = re.sub(
                        pattern, new_name, fn.decompiled_code.source_code
                    )
                else:
                    fn.decompiled_code = re.sub(pattern, new_name, str(fn.decompiled_code))

        # 4. Audit mutation
        self.mutations_log.append({
            "type": "rename_symbol",
            "address": addr,
            "old_name": old_name,
            "new_name": new_name,
        })
        return True

    def mutate_type(
        self, session: BinarySession, addr: int, new_type: str
    ) -> bool:
        self._record_call("mutate_type", addr=addr, new_type=new_type)

        target_fn = session.functions.get(addr)
        if not target_fn:
            return False

        old_type = target_fn.return_type
        target_fn.return_type = new_type

        # Update return type keyword in decompiled code
        if target_fn.decompiled_code:
            code_text = (
                target_fn.decompiled_code.source_code
                if isinstance(target_fn.decompiled_code, DecompiledCode)
                else str(target_fn.decompiled_code)
            )
            lines = code_text.splitlines()
            if lines:
                first_line = lines[0]
                m = re.match(
                    r"^(\s*)([\w\*\s]+?\b)(" + re.escape(target_fn.name) + r"\s*\(.*)$",
                    first_line,
                )
                if m:
                    leading_ws = m.group(1)
                    rest = m.group(3)
                    lines[0] = f"{leading_ws}{new_type} {rest}"
                    new_code = "\n".join(lines) + "\n"
                    if isinstance(target_fn.decompiled_code, DecompiledCode):
                        target_fn.decompiled_code.source_code = new_code
                        target_fn.decompiled_code.code = new_code
                    else:
                        target_fn.decompiled_code = new_code

        self.mutations_log.append({
            "type": "mutate_type",
            "address": addr,
            "old_type": old_type,
            "new_type": new_type,
        })
        return True


# Alias for backward compatibility
MockBackend = MockDecompilerBackend
