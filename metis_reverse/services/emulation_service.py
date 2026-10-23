"""EmulationService: Micro-emulation and breakpoint-based register/memory capture."""

import re
from typing import Dict, Any, List, Optional, Tuple
from ..engine.base import BaseReEngine

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


def _parse_int(val_str: str) -> Optional[int]:
    clean = val_str.strip().lstrip("#").rstrip("!")
    try:
        if clean.startswith("0x") or clean.startswith("-0x"):
            return int(clean, 16)
        return int(clean)
    except ValueError:
        return None


def _to_int(val: Any) -> int:
    """Coerce integer or string representation of integer to int."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        clean = val.strip().lstrip("#")
        if clean.startswith("0x") or clean.startswith("-0x"):
            return int(clean, 16)
        return int(clean)
    return int(val)


class EmulationService:
    """Manages controlled micro-emulation around specific functions or basic blocks."""

    def __init__(self, engine: BaseReEngine):
        self.engine = engine

    def _get_arch_and_registers(self, session_id: str, start_va: str) -> Tuple[str, Dict[str, int], str, Any, Any]:
        arch = "x86_64"
        try:
            meta = self.engine.get_metadata(session_id)
            arch = meta.get("arch", "x86_64")
        except Exception:
            pass

        start_int = int(start_va, 16) if start_va.startswith("0x") else int(start_va)
        arch_upper = arch.upper()

        if "ARM64" in arch_upper or "AARCH64" in arch_upper:
            regs = {f"x{i}": 0 for i in range(31)}
            for i in range(31):
                regs[f"w{i}"] = 0
            regs["fp"] = 0x16fdff000
            regs["x29"] = 0x16fdff000
            regs["lr"] = 0x100000000
            regs["x30"] = 0x100000000
            regs["sp"] = 0x16fdff000
            regs["pc"] = start_int
            regs["xzr"] = 0
            regs["wzr"] = 0
            pc_name = "pc"
            cs_arch = capstone.CS_ARCH_ARM64 if HAS_CAPSTONE else None
            cs_mode = capstone.CS_MODE_ARM if HAS_CAPSTONE else None
        elif "X86_64" in arch_upper or "AMD64" in arch_upper:
            regs = {
                "rax": 0, "rcx": 0, "rdx": 0, "rbx": 0,
                "rsp": 0x7ffffff0, "rbp": 0x7ffffff0, "rsi": 0, "rdi": 0,
                "r8": 0, "r9": 0, "r10": 0, "r11": 0, "r12": 0, "r13": 0, "r14": 0, "r15": 0,
                "rip": start_int,
            }
            pc_name = "rip"
            cs_arch = capstone.CS_ARCH_X86 if HAS_CAPSTONE else None
            cs_mode = capstone.CS_MODE_64 if HAS_CAPSTONE else None
        else:
            regs = {
                "eax": 0, "ecx": 0, "edx": 0, "ebx": 0,
                "esp": 0x7ffffff0, "ebp": 0x7ffffff0, "esi": 0, "edi": 0,
                "eip": start_int,
            }
            pc_name = "eip"
            cs_arch = capstone.CS_ARCH_X86 if HAS_CAPSTONE else None
            cs_mode = capstone.CS_MODE_32 if HAS_CAPSTONE else None

        return arch, regs, pc_name, cs_arch, cs_mode

    def emulate_slice(
        self,
        session_id: str,
        start_va: str,
        stop_va: str,
        initial_registers: Optional[Dict[str, Any]] = None,
        memory_inspect_addresses: Optional[List[str]] = None,
        max_steps: int = 1000,
        import_stubs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Performs controlled micro-emulation from start_va until stop_va (breakpoint).

        Breakpoint semantics: Standard debugger 'break before execution'. When PC reaches
        stop_va, emulation stops before executing the instruction at stop_va.
        """
        arch, registers, pc_name, cs_arch, cs_mode = self._get_arch_and_registers(session_id, start_va)

        # Simulated memory overlay & uninitialized memory access warnings (P4-1)
        sim_mem: Dict[int, int] = {}
        uninitialized_accesses: List[Dict[str, Any]] = []

        def _get_reg(name: str) -> int:
            clean = name.lower().strip().lstrip("#").rstrip("!")
            if clean in ("xzr", "wzr"):
                return 0
            if clean in registers:
                return registers[clean]
            if clean.startswith("w") and clean[1:].isdigit():
                return registers.get(f"x{clean[1:]}", 0) & 0xFFFFFFFF
            return 0

        def _set_reg(name: str, val: Any):
            clean = name.lower().strip().lstrip("#").rstrip("!")
            int_val = _to_int(val) & 0xFFFFFFFFFFFFFFFF
            if clean in ("xzr", "wzr"):
                return
            if clean.startswith("w") and clean[1:].isdigit():
                x_name = f"x{clean[1:]}"
                registers[x_name] = int_val & 0xFFFFFFFF
                registers[clean] = int_val & 0xFFFFFFFF
            else:
                registers[clean] = int_val
                if clean.startswith("x") and clean[1:].isdigit():
                    registers[f"w{clean[1:]}"] = int_val & 0xFFFFFFFF
                if clean == "x29":
                    registers["fp"] = int_val
                elif clean == "fp":
                    registers["x29"] = int_val
                elif clean == "x30":
                    registers["lr"] = int_val
                elif clean == "lr":
                    registers["x30"] = int_val

        # Normalize and apply initial registers
        if initial_registers:
            for k, v in initial_registers.items():
                try:
                    _set_reg(k, v)
                except Exception:
                    pass

        try:
            start_int = int(start_va, 16) if start_va.startswith("0x") else int(start_va)
            stop_int = int(stop_va, 16) if stop_va.startswith("0x") else int(stop_va)
        except ValueError:
            start_int = 0
            stop_int = 0

        def _mem_write(addr: int, data: bytes):
            for i, b in enumerate(data):
                sim_mem[addr + i] = b

        def _mem_read(addr: int, size: int) -> bytes:
            result = bytearray(size)
            is_unmapped = False
            try:
                engine_bytes = self.engine.get_memory_slice(session_id, hex(addr), size)
                if engine_bytes and not all(b == 0 for b in engine_bytes):
                    result[:len(engine_bytes)] = engine_bytes
                else:
                    is_unmapped = True
            except Exception:
                is_unmapped = True

            has_sim = any((addr + i) in sim_mem for i in range(size))
            if is_unmapped and not has_sim:
                uninit_info = {"addr": hex(addr), "size": size, "pc": hex(registers.get(pc_name, 0))}
                if uninit_info not in uninitialized_accesses:
                    uninitialized_accesses.append(uninit_info)
                    trace.append(f"uninitialized_memory_access: read at {hex(addr)} (size {size})")

            for i in range(size):
                curr = addr + i
                if curr in sim_mem:
                    result[i] = sim_mem[curr]
            return bytes(result)

        # Read actual code bytes between start_va and stop_va
        code_size = max(4, min(abs(stop_int - start_int) + 32, 4096)) if stop_int > start_int else 64
        try:
            code_bytes = self.engine.get_memory_slice(session_id, start_va, code_size)
        except Exception:
            code_bytes = b""

        trace = [
            f"Arch: {arch}, IP: {pc_name} = {start_va}",
            f"Initial registers: {list(registers.keys())[:8]}...",
        ]

        steps_executed = 0
        breakpoint_hit = False
        has_error = False
        error_msg: Optional[str] = None

        if HAS_CAPSTONE and cs_arch is not None and code_bytes and not all(b == 0 for b in code_bytes):
            try:
                md = capstone.Cs(cs_arch, cs_mode)
                disasm_insns = list(md.disasm(code_bytes, start_int))
                for insn in disasm_insns:
                    # Break BEFORE executing instruction if PC reaches stop_int
                    if insn.address == stop_int:
                        breakpoint_hit = True
                        registers[pc_name] = insn.address
                        trace.append(f"Breakpoint hit at {hex(stop_int)} (before execution)")
                        break

                    if steps_executed >= max_steps:
                        trace.append(f"Reached max steps limit ({max_steps})")
                        break

                    registers[pc_name] = insn.address
                    line = f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}"
                    trace.append(line)
                    steps_executed += 1

                    mnemonic = insn.mnemonic.lower()
                    op_str = insn.op_str.strip().lower()

                    # 1. ARM64 Instruction Emulation
                    if "ARM64" in arch.upper():
                        # stp (store pair)
                        if mnemonic == "stp":
                            # Pre-index writeback: stp xt1, xt2, [xn, #imm]!
                            m_pre = re.match(r"^([a-z0-9]+),\s*([a-z0-9]+),\s*\[([a-z0-9]+),\s*#?(-?0x[0-9a-f]+|-?\d+)\]!$", op_str)
                            # Post-index writeback: stp xt1, xt2, [xn], #imm
                            m_post = re.match(r"^([a-z0-9]+),\s*([a-z0-9]+),\s*\[([a-z0-9]+)\],\s*#?(-?0x[0-9a-f]+|-?\d+)$", op_str)
                            # Offset: stp xt1, xt2, [xn, #imm] or [xn]
                            m_off = re.match(r"^([a-z0-9]+),\s*([a-z0-9]+),\s*\[([a-z0-9]+)(?:,\s*#?(-?0x[0-9a-f]+|-?\d+))?\]$", op_str)

                            if m_pre:
                                rt1, rt2, rn, imm_str = m_pre.groups()
                                imm = _parse_int(imm_str) or 0
                                new_rn = (_get_reg(rn) + imm) & 0xFFFFFFFFFFFFFFFF
                                _set_reg(rn, new_rn)
                                is_64 = rt1.startswith("x") or rt1 in ("fp", "lr", "sp")
                                stride = 8 if is_64 else 4
                                _mem_write(new_rn, _get_reg(rt1).to_bytes(stride, "little"))
                                _mem_write(new_rn + stride, _get_reg(rt2).to_bytes(stride, "little"))
                            elif m_post:
                                rt1, rt2, rn, imm_str = m_post.groups()
                                imm = _parse_int(imm_str) or 0
                                curr_rn = _get_reg(rn)
                                is_64 = rt1.startswith("x") or rt1 in ("fp", "lr", "sp")
                                stride = 8 if is_64 else 4
                                _mem_write(curr_rn, _get_reg(rt1).to_bytes(stride, "little"))
                                _mem_write(curr_rn + stride, _get_reg(rt2).to_bytes(stride, "little"))
                                _set_reg(rn, (curr_rn + imm) & 0xFFFFFFFFFFFFFFFF)
                            elif m_off:
                                rt1, rt2, rn, imm_str = m_off.groups()
                                imm = _parse_int(imm_str) if imm_str else 0
                                base = (_get_reg(rn) + imm) & 0xFFFFFFFFFFFFFFFF
                                is_64 = rt1.startswith("x") or rt1 in ("fp", "lr", "sp")
                                stride = 8 if is_64 else 4
                                _mem_write(base, _get_reg(rt1).to_bytes(stride, "little"))
                                _mem_write(base + stride, _get_reg(rt2).to_bytes(stride, "little"))

                        # ldp (load pair)
                        elif mnemonic == "ldp":
                            m_off = re.match(r"^([a-z0-9]+),\s*([a-z0-9]+),\s*\[([a-z0-9]+)(?:,\s*#?(-?0x[0-9a-f]+|-?\d+))?\]$", op_str)
                            if m_off:
                                rt1, rt2, rn, imm_str = m_off.groups()
                                imm = _parse_int(imm_str) if imm_str else 0
                                base = (_get_reg(rn) + imm) & 0xFFFFFFFFFFFFFFFF
                                is_64 = rt1.startswith("x") or rt1 in ("fp", "lr", "sp")
                                stride = 8 if is_64 else 4
                                v1 = int.from_bytes(_mem_read(base, stride), "little")
                                v2 = int.from_bytes(_mem_read(base + stride, stride), "little")
                                _set_reg(rt1, v1)
                                _set_reg(rt2, v2)

                        # str / stur
                        elif mnemonic in ("str", "stur"):
                            m_pre = re.match(r"^([a-z0-9]+),\s*\[([a-z0-9]+),\s*#?(-?0x[0-9a-f]+|-?\d+)\]!$", op_str)
                            m_post = re.match(r"^([a-z0-9]+),\s*\[([a-z0-9]+)\],\s*#?(-?0x[0-9a-f]+|-?\d+)$", op_str)
                            m_off = re.match(r"^([a-z0-9]+),\s*\[([a-z0-9]+)(?:,\s*#?(-?0x[0-9a-f]+|-?\d+))?\]$", op_str)
                            if m_pre:
                                rt, rn, imm_str = m_pre.groups()
                                imm = _parse_int(imm_str) or 0
                                new_rn = (_get_reg(rn) + imm) & 0xFFFFFFFFFFFFFFFF
                                _set_reg(rn, new_rn)
                                is_64 = rt.startswith("x") or rt in ("fp", "lr", "sp")
                                stride = 8 if is_64 else 4
                                _mem_write(new_rn, _get_reg(rt).to_bytes(stride, "little"))
                            elif m_post:
                                rt, rn, imm_str = m_post.groups()
                                imm = _parse_int(imm_str) or 0
                                curr_rn = _get_reg(rn)
                                is_64 = rt.startswith("x") or rt in ("fp", "lr", "sp")
                                stride = 8 if is_64 else 4
                                _mem_write(curr_rn, _get_reg(rt).to_bytes(stride, "little"))
                                _set_reg(rn, (curr_rn + imm) & 0xFFFFFFFFFFFFFFFF)
                            elif m_off:
                                rt, rn, imm_str = m_off.groups()
                                imm = _parse_int(imm_str) if imm_str else 0
                                base = (_get_reg(rn) + imm) & 0xFFFFFFFFFFFFFFFF
                                is_64 = rt.startswith("x") or rt in ("fp", "lr", "sp")
                                stride = 8 if is_64 else 4
                                _mem_write(base, _get_reg(rt).to_bytes(stride, "little"))

                        # ldr / ldur
                        elif mnemonic in ("ldr", "ldur"):
                            m_off = re.match(r"^([a-z0-9]+),\s*\[([a-z0-9]+)(?:,\s*#?(-?0x[0-9a-f]+|-?\d+))?\]$", op_str)
                            if m_off:
                                rt, rn, imm_str = m_off.groups()
                                imm = _parse_int(imm_str) if imm_str else 0
                                base = (_get_reg(rn) + imm) & 0xFFFFFFFFFFFFFFFF
                                is_64 = rt.startswith("x") or rt in ("fp", "lr", "sp")
                                stride = 8 if is_64 else 4
                                val = int.from_bytes(_mem_read(base, stride), "little")
                                _set_reg(rt, val)

                        # add / sub
                        elif mnemonic in ("add", "adds", "sub", "subs"):
                            m_arith = re.match(r"^([a-z0-9]+),\s*([a-z0-9]+),\s*(.+)$", op_str)
                            if m_arith:
                                rd, rn, op2_str = m_arith.groups()
                                rn_val = _get_reg(rn)
                                op2_clean = op2_str.strip().lstrip("#")
                                op2_val = _get_reg(op2_clean) if op2_clean in registers else (_parse_int(op2_clean) or 0)
                                if mnemonic.startswith("add"):
                                    res_val = (rn_val + op2_val) & 0xFFFFFFFFFFFFFFFF
                                else:
                                    res_val = (rn_val - op2_val) & 0xFFFFFFFFFFFFFFFF
                                _set_reg(rd, res_val)

                        # mov / movz / movk
                        elif mnemonic in ("mov", "movz", "movk", "movabs"):
                            m_mov = re.match(r"^([a-z0-9]+),\s*(.+)$", op_str)
                            if m_mov:
                                rd, src_str = m_mov.groups()
                                src_clean = src_str.strip().lstrip("#")
                                val = _get_reg(src_clean) if src_clean in registers else (_parse_int(src_clean) or 0)
                                _set_reg(rd, val)

                        # adr / adrp
                        elif mnemonic in ("adr", "adrp"):
                            m_adr = re.match(r"^([a-z0-9]+),\s*#?(-?0x[0-9a-f]+|-?\d+)$", op_str)
                            if m_adr:
                                rd, imm_str = m_adr.groups()
                                _set_reg(rd, _parse_int(imm_str) or 0)

                    # 2. x86_64 Instruction Emulation
                    else:
                        if mnemonic == "push":
                            reg = op_str.strip()
                            val = _get_reg(reg)
                            rsp_val = (_get_reg("rsp") - 8) & 0xFFFFFFFFFFFFFFFF
                            _set_reg("rsp", rsp_val)
                            _mem_write(rsp_val, val.to_bytes(8, "little"))
                        elif mnemonic == "pop":
                            reg = op_str.strip()
                            rsp_val = _get_reg("rsp")
                            val = int.from_bytes(_mem_read(rsp_val, 8), "little")
                            _set_reg(reg, val)
                            _set_reg("rsp", (rsp_val + 8) & 0xFFFFFFFFFFFFFFFF)
                        elif mnemonic == "mov":
                            m_mov = re.match(r"^([a-z0-9]+),\s*([a-z0-9]+)$", op_str)
                            if m_mov:
                                dst, src = m_mov.groups()
                                val = _get_reg(src) if src in registers else (_parse_int(src) or 0)
                                _set_reg(dst, val)
                        elif mnemonic == "sub":
                            m_sub = re.match(r"^([a-z0-9]+),\s*(.+)$", op_str)
                            if m_sub:
                                dst, src = m_sub.groups()
                                val = _parse_int(src) or 0
                                _set_reg(dst, (_get_reg(dst) - val) & 0xFFFFFFFFFFFFFFFF)
                        elif mnemonic == "add":
                            m_add = re.match(r"^([a-z0-9]+),\s*(.+)$", op_str)
                            if m_add:
                                dst, src = m_add.groups()
                                val = _parse_int(src) or 0
                                _set_reg(dst, (_get_reg(dst) + val) & 0xFFFFFFFFFFFFFFFF)

                    # Advance PC to next instruction after execution
                    registers[pc_name] = insn.address + insn.size

            except Exception as e:
                has_error = True
                error_msg = str(e)
                trace.append(f"Disassembly / emulation error: {error_msg}")

        if not breakpoint_hit and not has_error:
            if steps_executed == 0:
                registers[pc_name] = start_int
            trace.append(f"Stopped at {hex(registers[pc_name])}")

        # Capture inspected memory snapshots
        memory_snapshots: Dict[str, str] = {}
        if memory_inspect_addresses:
            for addr in memory_inspect_addresses:
                try:
                    addr_int = int(addr, 16) if addr.startswith("0x") else int(addr)
                    raw_bytes = _mem_read(addr_int, 64)
                    memory_snapshots[addr] = raw_bytes.hex()
                except Exception:
                    memory_snapshots[addr] = ""

        # Filter register display to standard registers
        if "ARM64" in arch.upper():
            reg_display_keys = [f"x{i}" for i in range(31)] + ["sp", "pc", "fp", "lr"]
        else:
            reg_display_keys = list(registers.keys())

        final_regs = {}
        for k in reg_display_keys:
            if k in registers:
                v = registers[k]
                final_regs[k] = hex(v) if isinstance(v, int) else v

        if has_error:
            status = "emulation_error"
        elif breakpoint_hit:
            status = "breakpoint_reached"
        else:
            status = "not_reached"

        result = {
            "status": status,
            "arch": arch,
            "start_va": start_va,
            "stop_va": stop_va,
            "steps_executed": steps_executed,
            "final_registers": final_regs,
            "memory_snapshots": memory_snapshots,
            "uninitialized_memory_accesses": uninitialized_accesses,
            "trace_log": trace,
            "micro_emulated": not has_error,
            "hypothesis_guidance": "Compare register output and memory snapshots with your static reverse-engineering deduction."
        }
        if has_error:
            result["has_error"] = True
            result["error"] = error_msg
        return result
