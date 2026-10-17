"""
Metis Reverse - Isolated Unicorn Engine Dynamic Micro-Emulation Prober.
Performs in-memory function-slice execution, GOT resolution, and memory extraction.
"""

from __future__ import annotations

import contextlib
import logging
import struct
import time
from abc import ABC, abstractmethod
from typing import Any

import lief
from unicorn import (
    UC_ARCH_ARM64,
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MODE_32,
    UC_MODE_64,
    UC_MODE_ARM,
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
    UcError,
)
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X7,
)
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

from metis_reverse.core.models import (
    ArchitectureType,
    BinarySession,
    TraceEvent,
    TraceEventType,
    TraceResult,
)
from metis_reverse.dynamic.prober_base import (
    BaseProber,
    ProberUnavailableError,
)

logger = logging.getLogger("metis_reverse.dynamic.unicorn")

SENTINEL_RETURN_ADDRESS = 0xDEAD0000
PAGE_SIZE = 4096


def build_page_mappings(
    sections: list[tuple[int, int, bytes, int]],
    page_size: int = PAGE_SIZE,
) -> list[tuple[int, int, bytes, int]]:
    """
    Coalesces arbitrary virtual memory slices into non-overlapping,
    4KB page-aligned memory blocks with merged permission bitmasks.
    """
    pages: dict[int, dict[str, Any]] = {}
    for va, size, content, prot in sections:
        if size <= 0:
            continue
        p_start = (va // page_size) * page_size
        p_end = ((va + size + page_size - 1) // page_size) * page_size
        for p in range(p_start, p_end, page_size):
            if p not in pages:
                pages[p] = {"bytes": bytearray(page_size), "prot": prot}
            else:
                pages[p]["prot"] |= prot

        content_len = len(content)
        for i in range(min(size, content_len)):
            addr = va + i
            p = (addr // page_size) * page_size
            offset = addr % page_size
            pages[p]["bytes"][offset] = content[i]

    sorted_pages = sorted(pages.keys())
    if not sorted_pages:
        return []

    blocks: list[tuple[int, int, bytes, int]] = []
    curr_start = sorted_pages[0]
    curr_size = page_size
    curr_prot = pages[curr_start]["prot"]
    curr_bytes = bytearray(pages[curr_start]["bytes"])

    for p in sorted_pages[1:]:
        if p == curr_start + curr_size and pages[p]["prot"] == curr_prot:
            curr_size += page_size
            curr_bytes.extend(pages[p]["bytes"])
        else:
            blocks.append((curr_start, curr_size, bytes(curr_bytes), curr_prot))
            curr_start = p
            curr_size = page_size
            curr_prot = pages[p]["prot"]
            curr_bytes = bytearray(pages[p]["bytes"])
    blocks.append((curr_start, curr_size, bytes(curr_bytes), curr_prot))
    return blocks


class ArchAdapter(ABC):
    """Abstract hardware architecture adapter for Unicorn."""

    @abstractmethod
    def create_engine(self) -> Uc: ...

    @abstractmethod
    def setup_frame(
        self, uc: Uc, sp: int, sentinel_addr: int, args: list[int]
    ) -> int: ...

    @abstractmethod
    def read_pc(self, uc: Uc) -> int: ...

    @abstractmethod
    def set_pc(self, uc: Uc, addr: int) -> None: ...

    @abstractmethod
    def read_return_value(self, uc: Uc) -> int: ...

    @abstractmethod
    def make_ret_instruction(self) -> bytes: ...


class X86_64Adapter(ArchAdapter):
    """System V AMD64 ABI adapter for x86_64."""

    ARG_REGS = [
        UC_X86_REG_RDI,
        UC_X86_REG_RSI,
        UC_X86_REG_RDX,
        UC_X86_REG_RCX,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
    ]

    def create_engine(self) -> Uc:
        return Uc(UC_ARCH_X86, UC_MODE_64)

    def setup_frame(
        self, uc: Uc, sp: int, sentinel_addr: int, args: list[int]
    ) -> int:
        for i, val in enumerate(args[: len(self.ARG_REGS)]):
            uc.reg_write(self.ARG_REGS[i], val)
        curr_sp = sp
        if len(args) > len(self.ARG_REGS):
            for val in reversed(args[len(self.ARG_REGS) :]):
                curr_sp -= 8
                uc.mem_write(curr_sp, struct.pack("<Q", val))
        curr_sp -= 8
        uc.mem_write(curr_sp, struct.pack("<Q", sentinel_addr))
        uc.reg_write(UC_X86_REG_RSP, curr_sp)
        return curr_sp

    def read_pc(self, uc: Uc) -> int:
        return uc.reg_read(UC_X86_REG_RIP)

    def set_pc(self, uc: Uc, addr: int) -> None:
        uc.reg_write(UC_X86_REG_RIP, addr)

    def read_return_value(self, uc: Uc) -> int:
        val = uc.reg_read(UC_X86_REG_RAX)
        if val > 0x7FFFFFFFFFFFFFFF:
            val -= 0x10000000000000000
        return val

    def make_ret_instruction(self) -> bytes:
        return b"\xc3"


class ARM64Adapter(ArchAdapter):
    """AAPCS64 standard adapter for ARM64."""

    ARG_REGS = [
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X6,
        UC_ARM64_REG_X7,
    ]

    def create_engine(self) -> Uc:
        return Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    def setup_frame(
        self, uc: Uc, sp: int, sentinel_addr: int, args: list[int]
    ) -> int:
        for i, val in enumerate(args[: len(self.ARG_REGS)]):
            uc.reg_write(self.ARG_REGS[i], val)
        curr_sp = sp
        if len(args) > len(self.ARG_REGS):
            for val in reversed(args[len(self.ARG_REGS) :]):
                curr_sp -= 8
                uc.mem_write(curr_sp, struct.pack("<Q", val))
        uc.reg_write(UC_ARM64_REG_LR, sentinel_addr)
        uc.reg_write(UC_ARM64_REG_SP, curr_sp)
        return curr_sp

    def read_pc(self, uc: Uc) -> int:
        return uc.reg_read(UC_ARM64_REG_PC)

    def set_pc(self, uc: Uc, addr: int) -> None:
        uc.reg_write(UC_ARM64_REG_PC, addr)

    def read_return_value(self, uc: Uc) -> int:
        val = uc.reg_read(UC_ARM64_REG_X0)
        if val > 0x7FFFFFFFFFFFFFFF:
            val -= 0x10000000000000000
        return val

    def make_ret_instruction(self) -> bytes:
        return bytes([0xC0, 0x03, 0x5F, 0xD6])


class X86_32Adapter(ArchAdapter):
    """cdecl adapter for x86 32-bit."""

    def create_engine(self) -> Uc:
        return Uc(UC_ARCH_X86, UC_MODE_32)

    def setup_frame(
        self, uc: Uc, sp: int, sentinel_addr: int, args: list[int]
    ) -> int:
        uc.mem_write(sp, struct.pack("<I", sentinel_addr))
        for i, val in enumerate(args):
            uc.mem_write(sp + 4 + (i * 4), struct.pack("<I", val & 0xFFFFFFFF))
        uc.reg_write(UC_X86_REG_ESP, sp)
        return sp

    def read_pc(self, uc: Uc) -> int:
        return uc.reg_read(UC_X86_REG_EIP)

    def set_pc(self, uc: Uc, addr: int) -> None:
        uc.reg_write(UC_X86_REG_EIP, addr)

    def read_return_value(self, uc: Uc) -> int:
        val = uc.reg_read(UC_X86_REG_EAX)
        if val > 0x7FFFFFFF:
            val -= 0x100000000
        return val

    def make_ret_instruction(self) -> bytes:
        return b"\xc3"


class HeapManager:
    """Manages isolated heap allocations for function arguments and buffers."""

    def __init__(self, uc: Uc, base_addr: int, max_size: int = 0x200000):
        self.uc = uc
        self.base_addr = base_addr
        self.max_size = max_size
        self.current_offset = 0x1000
        self.allocated_buffers: dict[int, int] = {}
        uc.mem_map(base_addr, max_size, UC_PROT_READ | UC_PROT_WRITE)

    def allocate(self, size: int, init_bytes: bytes | None = None) -> int:
        aligned_size = (size + 15) & ~15
        if self.current_offset + aligned_size > self.max_size:
            raise MemoryError("Emulated heap exhausted")
        ptr = self.base_addr + self.current_offset
        self.current_offset += aligned_size
        self.allocated_buffers[ptr] = size
        if init_bytes:
            self.uc.mem_write(ptr, init_bytes)
        else:
            self.uc.mem_write(ptr, b"\x00" * size)
        return ptr

    def allocate_string(self, text: str) -> int:
        data = text.encode("utf-8") + b"\x00"
        return self.allocate(len(data), data)


class UnicornProber(BaseProber):
    """
    Hermetic in-memory micro-emulation prober powered by Unicorn Engine.
    Executes function slices across x86_64, ARM64, and x86_32 architectures.
    """

    def __init__(
        self,
        max_instructions: int = 100000,
        timeout_us: int = 2000000,
        auto_alloc_unmapped: bool = True,
        max_scratch_pages: int = 256,
    ):
        self.max_instructions = max_instructions
        self.timeout_us = timeout_us
        self.auto_alloc_unmapped = auto_alloc_unmapped
        self.max_scratch_pages = max_scratch_pages

    @property
    def name(self) -> str:
        return "unicorn"

    def is_available(self, session: BinarySession | None = None) -> bool:
        """Check if Unicorn Engine is available and compatible."""
        try:
            import unicorn  # noqa: F401
        except ImportError:
            return False

        if session is not None:
            arch = session.artifact.architecture
            return arch in (
                ArchitectureType.X86_64,
                ArchitectureType.ARM64,
                ArchitectureType.X86,
            )
        return True

    def trace_function(
        self,
        session: BinarySession,
        function_address: int,
        args: list[Any] | None = None,
        *,
        timeout_seconds: float = 5.0,
        max_instructions: int = 100000,
        **kwargs: Any,
    ) -> TraceResult:
        """
        Execute function in-memory micro-emulation and extract trace facts.
        """
        start_time = time.time()
        timeout_us = int(timeout_seconds * 1_000_000)
        max_insn = max_instructions or self.max_instructions

        adapter = self._get_adapter(session)
        uc = adapter.create_engine()

        # 1. Map binary segments with 4KB page alignment
        self._map_binary_segments(uc, session)

        # 2. Map stack and heap
        bitness = session.artifact.bitness or 64
        stack_base = 0x7FFF00000000 if bitness == 64 else 0x70000000
        stack_size = 0x200000 if bitness == 64 else 0x100000
        uc.mem_map(stack_base, stack_size, UC_PROT_READ | UC_PROT_WRITE)
        sp = stack_base + stack_size - 0x1000

        heap_base = 0x600000000000 if bitness == 64 else 0x50000000
        heap = HeapManager(uc, heap_base, max_size=0x200000)

        # 3. Resolve imports and stubs
        stub_functions = self._setup_stubs_and_canary(uc, session, adapter, bitness)

        # 4. Marshal and inject arguments
        concrete_args = self._marshal_args(heap, args or [])
        adapter.setup_frame(uc, sp, SENTINEL_RETURN_ADDRESS, concrete_args)
        adapter.set_pc(uc, function_address)

        # 5. Setup hooks
        events: list[TraceEvent] = []
        captured_fault: list[str] = []
        scratch_page_count = [0]
        step = [0]

        def hook_code(uc_inst: Uc, addr: int, size: int, user_data: Any) -> None:
            step[0] += 1
            if addr in stub_functions:
                self._handle_libc_stub(uc_inst, stub_functions[addr], adapter)
            if len(events) < 500:
                events.append(
                    TraceEvent(
                        step=step[0],
                        event_type=TraceEventType.EXEC,
                        address=addr,
                        details={"size": size},
                    )
                )

        def hook_mem_write(
            uc_inst: Uc, access: int, addr: int, size: int, val: int, user_data: Any
        ) -> None:
            step[0] += 1
            if len(events) < 500:
                events.append(
                    TraceEvent(
                        step=step[0],
                        event_type=TraceEventType.MEM_WRITE,
                        address=addr,
                        details={"size": size, "value": hex(val)},
                    )
                )

        def hook_unmapped(
            uc_inst: Uc, access: int, addr: int, size: int, val: int, user_data: Any
        ) -> bool:
            pc = adapter.read_pc(uc_inst)
            if addr < 0x1000:
                captured_fault.append(
                    f"Null pointer dereference at 0x{addr:x} from PC 0x{pc:x}"
                )
                uc_inst.emu_stop()
                return False
            if self.auto_alloc_unmapped and scratch_page_count[0] < self.max_scratch_pages:
                scratch_page_count[0] += 1
                page_addr = (addr // PAGE_SIZE) * PAGE_SIZE
                try:
                    uc_inst.mem_map(page_addr, PAGE_SIZE, UC_PROT_ALL)
                    return True
                except Exception:
                    pass
            captured_fault.append(f"Unmapped memory access at 0x{addr:x} from PC 0x{pc:x}")
            uc_inst.emu_stop()
            return False

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

        # 6. Start emulation
        success = False
        error_msg: str | None = None
        try:
            uc.emu_start(
                begin=function_address,
                until=SENTINEL_RETURN_ADDRESS,
                timeout=timeout_us,
                count=max_insn,
            )
            final_pc = adapter.read_pc(uc)
            if final_pc == SENTINEL_RETURN_ADDRESS:
                success = True
            else:
                error_msg = f"Emulation stopped early at PC 0x{final_pc:x} (limit reached)"
        except UcError as err:
            error_msg = captured_fault[0] if captured_fault else f"Unicorn CPU error: {err}"
        except Exception as err:
            error_msg = f"Emulation error: {err}"

        # 7. Extract results
        ret_val = adapter.read_return_value(uc) if success else None
        dumps = self._dump_buffers(uc, heap)
        strings = self._extract_strings_from_dumps(dumps)
        exec_time_ms = (time.time() - start_time) * 1000.0

        return TraceResult(
            success=success,
            session_id=session.session_id,
            function_address=function_address,
            function_name=f"sub_{function_address:x}",
            prober="unicorn",
            prober_used="unicorn",
            return_value=ret_val,
            return_type="int" if ret_val is not None else None,
            events=events,
            captured_strings=strings,
            memory_dumps=dumps,
            instructions_executed=step[0],
            execution_time_ms=exec_time_ms,
            error=error_msg,
        )

    def _get_adapter(self, session: BinarySession) -> ArchAdapter:
        arch = session.artifact.architecture
        if arch == ArchitectureType.X86_64:
            return X86_64Adapter()
        if arch in (ArchitectureType.ARM64, ArchitectureType.AARCH64):
            return ARM64Adapter()
        if arch == ArchitectureType.X86:
            return X86_32Adapter()
        raise ProberUnavailableError(f"Unsupported architecture for Unicorn prober: {arch}")

    def _map_binary_segments(self, uc: Uc, session: BinarySession) -> None:
        file_path = session.artifact.file_path
        slices: list[tuple[int, int, bytes, int]] = []
        try:
            b = lief.parse(file_path)
            if b and hasattr(b, "segments"):
                for seg in b.segments:
                    name = getattr(seg, "name", "")
                    if name in ("__PAGEZERO",):
                        continue
                    vsize = int(seg.virtual_size)
                    if vsize <= 0:
                        continue
                    va = int(seg.virtual_address)
                    prot = UC_PROT_READ
                    init_prot = int(getattr(seg, "init_protection", 0))
                    if init_prot & 2:
                        prot |= UC_PROT_WRITE
                    if init_prot & 4:
                        prot |= UC_PROT_EXEC
                    content = bytes(seg.content) if seg.content is not None else b""
                    slices.append((va, vsize, content, prot))
        except Exception as e:
            logger.debug("LIEF segment extraction fallback: %s", e)

        if not slices:
            with open(file_path, "rb") as f:
                raw_bytes = f.read()
            for s in session.artifact.sections:
                prot = UC_PROT_READ
                for p in s.permissions:
                    if p == "w" or getattr(p, "value", None) == "w":
                        prot |= UC_PROT_WRITE
                    elif p == "x" or getattr(p, "value", None) == "x":
                        prot |= UC_PROT_EXEC
                content = raw_bytes[s.raw_offset : s.raw_offset + s.raw_size]
                slices.append((s.virtual_address, s.virtual_size, content, prot))

        blocks = build_page_mappings(slices)
        for b_addr, b_size, b_data, b_prot in blocks:
            uc.mem_map(b_addr, b_size, b_prot)
            if b_data:
                uc.mem_write(b_addr, b_data)

    def _setup_stubs_and_canary(
        self, uc: Uc, session: BinarySession, adapter: ArchAdapter, bitness: int
    ) -> dict[int, str]:
        stub_base = 0x100010000 if bitness == 64 else 0x30000000
        uc.mem_map(stub_base, 0x10000, UC_PROT_ALL)

        canary_addr = stub_base + 0x8000
        canary_val = struct.pack("<Q" if bitness == 64 else "<I", 0x1122334455667788)
        uc.mem_write(canary_addr, canary_val)

        ret_insn = adapter.make_ret_instruction()
        stub_functions: dict[int, str] = {}
        try:
            b = lief.parse(session.artifact.file_path)
            if b and hasattr(b, "bindings"):
                for i, bnd in enumerate(b.bindings):
                    sym_name = bnd.symbol.name if bnd.symbol else ""
                    if sym_name in ("___stack_chk_guard", "__stack_chk_guard"):
                        uc.mem_write(bnd.address, struct.pack("<Q" if bitness == 64 else "<I", canary_addr))
                    else:
                        stub_addr = stub_base + (i * 16)
                        uc.mem_write(stub_addr, ret_insn)
                        uc.mem_write(bnd.address, struct.pack("<Q" if bitness == 64 else "<I", stub_addr))
                        clean_name = sym_name.lstrip("_")
                        stub_functions[stub_addr] = clean_name
        except Exception as e:
            logger.debug("Binding resolution warning: %s", e)
        return stub_functions

    def _read_cstring(self, uc: Uc, ptr: int, max_len: int = 1024) -> bytes:
        if ptr < 0x1000:
            return b""
        res = bytearray()
        for i in range(max_len):
            try:
                b = uc.mem_read(ptr + i, 1)[0]
                if b == 0:
                    break
                res.append(b)
            except Exception:
                break
        return bytes(res)

    def _handle_libc_stub(self, uc: Uc, fn_name: str, adapter: ArchAdapter) -> None:
        """Emulate standard C library functions when jumped to via PLT/GOT."""
        # Read args based on adapter
        if isinstance(adapter, ARM64Adapter):
            a0 = uc.reg_read(UC_ARM64_REG_X0)
            a1 = uc.reg_read(UC_ARM64_REG_X1)
            a2 = uc.reg_read(UC_ARM64_REG_X2)

            def set_ret(val: int) -> None:
                uc.reg_write(UC_ARM64_REG_X0, val & 0xFFFFFFFFFFFFFFFF)
        elif isinstance(adapter, X86_64Adapter):
            a0 = uc.reg_read(UC_X86_REG_RDI)
            a1 = uc.reg_read(UC_X86_REG_RSI)
            a2 = uc.reg_read(UC_X86_REG_RDX)

            def set_ret(val: int) -> None:
                uc.reg_write(UC_X86_REG_RAX, val & 0xFFFFFFFFFFFFFFFF)
        else:
            sp = uc.reg_read(UC_X86_REG_ESP)
            try:
                a0 = struct.unpack("<I", uc.mem_read(sp + 4, 4))[0]
                a1 = struct.unpack("<I", uc.mem_read(sp + 8, 4))[0]
                a2 = struct.unpack("<I", uc.mem_read(sp + 12, 4))[0]
            except Exception:
                a0, a1, a2 = 0, 0, 0

            def set_ret(val: int) -> None:
                uc.reg_write(UC_X86_REG_EAX, val & 0xFFFFFFFF)

        name = fn_name.lower()
        if name == "strcmp":
            s1 = self._read_cstring(uc, a0)
            s2 = self._read_cstring(uc, a1)
            ret = 0 if s1 == s2 else (1 if s1 > s2 else -1)
            set_ret(ret)
        elif name == "strncmp":
            s1 = self._read_cstring(uc, a0, max_len=a2)[:a2]
            s2 = self._read_cstring(uc, a1, max_len=a2)[:a2]
            ret = 0 if s1 == s2 else (1 if s1 > s2 else -1)
            set_ret(ret)
        elif name == "strlen":
            s = self._read_cstring(uc, a0)
            set_ret(len(s))
        elif name == "memcmp":
            try:
                b1 = bytes(uc.mem_read(a0, a2))
                b2 = bytes(uc.mem_read(a1, a2))
                ret = 0 if b1 == b2 else (1 if b1 > b2 else -1)
            except Exception:
                ret = 0
            set_ret(ret)
        elif name == "strncpy":
            with contextlib.suppress(Exception):
                s = self._read_cstring(uc, a1, max_len=a2)
                buf = s + b"\x00" * max(0, a2 - len(s))
                uc.mem_write(a0, buf[:a2])
            set_ret(a0)
        elif name == "strcpy":
            with contextlib.suppress(Exception):
                s = self._read_cstring(uc, a1)
                uc.mem_write(a0, s + b"\x00")
            set_ret(a0)
        elif name in ("memcpy", "memmove"):
            with contextlib.suppress(Exception):
                data = bytes(uc.mem_read(a1, a2))
                uc.mem_write(a0, data)
            set_ret(a0)
        elif name == "memset":
            with contextlib.suppress(Exception):
                uc.mem_write(a0, bytes([a1 & 0xFF]) * a2)
            set_ret(a0)
        elif name in ("printf", "puts", "fprintf", "snprintf", "sprintf"):
            set_ret(0)
        elif name == "atoi":
            try:
                raw = self._read_cstring(uc, a0).decode("utf-8", errors="ignore").strip()
                val = int(raw) if (raw.isdigit() or (raw.startswith("-") and raw[1:].isdigit())) else 0
            except Exception:
                val = 0
            set_ret(val)
        else:
            set_ret(0)

    def _marshal_args(self, heap: HeapManager, args: list[Any]) -> list[int]:
        concrete_args: list[int] = []
        for a in args:
            if isinstance(a, int):
                concrete_args.append(a)
            elif isinstance(a, str):
                ptr = heap.allocate_string(a)
                concrete_args.append(ptr)
            elif isinstance(a, (bytes, bytearray)):
                ptr = heap.allocate(len(a), bytes(a))
                concrete_args.append(ptr)
            elif isinstance(a, dict) and "size" in a:
                ptr = heap.allocate(int(a["size"]))
                concrete_args.append(ptr)
            else:
                ptr = heap.allocate(256)
                concrete_args.append(ptr)
        return concrete_args

    def _dump_buffers(self, uc: Uc, heap: HeapManager) -> dict[str, str]:
        dumps: dict[str, str] = {}
        for ptr, size in heap.allocated_buffers.items():
            try:
                data = uc.mem_read(ptr, min(size, 1024))
                dumps[f"heap_0x{ptr:x}"] = bytes(data).hex()
            except Exception:
                pass
        return dumps

    def _extract_strings_from_dumps(self, dumps: dict[str, str], min_len: int = 4) -> list[str]:
        found: set[str] = set()
        for hex_str in dumps.values():
            try:
                raw = bytes.fromhex(hex_str)
                curr = bytearray()
                for b in raw:
                    if 0x20 <= b <= 0x7E:
                        curr.append(b)
                    else:
                        if len(curr) >= min_len:
                            found.add(curr.decode("utf-8", errors="ignore"))
                        curr.clear()
                if len(curr) >= min_len:
                    found.add(curr.decode("utf-8", errors="ignore"))
            except Exception:
                pass
        return sorted(found)
