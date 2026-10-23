# Metis Reverse MCP: Escape Hatch & Sandbox Probe Recipes

When facing custom packers, non-standard containers, obfuscated strings, dynamic API hashing, or unmapped data structures, Metis Reverse provides two complementary sandbox execution primitives:
- **`re_verify_hypothesis`**: Tests decryption or hash-cracking scripts against a virtual memory slice (`target_va`, `slice_size`).
- **`re_run_probe_script`** *(Escape Hatch 1)*: Executes custom structure-parsing probes with direct physical file access (`read_file_range`), virtual memory reads (`read_memory`), and dynamic child artifact mounting (`register_child`).

This reference provides the exact sandbox API contract and **10 copy-pasteable, production-grade Python probe recipes**.

---

## 1. Sandbox Runtime Environment & API Contract

Both `re_verify_hypothesis` and `re_run_probe_script` execute inside `HypothesisSandbox`—an isolated, read-only, time-bounded Python environment.

### 1.1 Pre-Imported Modules & Built-in Helpers (Available in Both Tools)
- **Standard & Binary Modules** (already injected into global scope; `import` statements also work for standard modules):
  - `struct`, `zlib`, `hashlib`, `binascii`, `base64`, `math`, `re`, `json`
  - `capstone` (Capstone disassembly engine, if installed in host Python environment)
  - `lief` (LIEF binary parser, if installed in host Python environment)
- **Built-in Bitwise & Crypto Helpers**:
  - `ror(val: int, r: int, bits: int = 32) -> int`: Rotate right within `bits`-width mask.
  - `rol(val: int, r: int, bits: int = 32) -> int`: Rotate left within `bits`-width mask.
  - `safe_xor(data: bytes, key: bytes) -> bytes`: Repeating-key XOR over `data`.
  - `safe_rc4(data: bytes, key: bytes) -> bytes`: Standard RC4 keystream encryption/decryption.

### 1.2 Tool-Specific Globals & Entrypoints

| Feature | `re_verify_hypothesis` | `re_run_probe_script` |
| :--- | :--- | :--- |
| **Injected Data Globals** | `memory_slice: bytes`, `data: bytes`, `va: str` | `artifact_id: str` |
| **Injected Read / Mount APIs** | *(Reads `target_va` slice automatically)* | `read_file_range(offset: int, size: int) -> bytes`<br>`read_memory(va: str, size: int) -> bytes`<br>`register_child(offset: int, length: int, data: bytes, name: str = "", description: str = "") -> dict` |
| **Auto-Invoked Entrypoint** | `def verify(data: bytes): ...` or `def decrypt(data: bytes): ...` or assign `result = ...` | `def probe(): ...` or `def parse(): ...` or assign `result = ...` |
| **Confirmation Contract** | `hypothesis_confirmed` becomes `True` if:<br>1. `expected_output` is passed and matches `returned_value` / `returned_hex`, **OR**<br>2. `verify(data)` returns `True` or a dict `{"confirmed": True, ...}` (and `memory_slice` is not all `0x00` bytes). | `success: True`, returns `returned_value`, `stdout`, and `registered_children` list with new `artifact_id`s. |

### 1.3 Sandbox Security Guardrails (R6)
- **No Network or Subprocess Execution**: `socket`, `urllib`, `os.system`, and `subprocess` are blocked.
- **Strictly Read-Only Target**: Original binaries cannot be modified.
- **DoS & Traversal Limits**: Maximum child artifact size is `50 MB`. Child artifact `name` cannot contain `..`, `/`, or `\`. Execution timeout defaults to `5.0s`.

---

## Recipe 1: Zlib / Raw Deflate Overlay Unpacking & Child Mounting (`re_run_probe_script`)

### Use Case
A binary or firmware image contains a compressed payload in an overlay or custom section (e.g., at file offset `0x84000` with an 8-byte header `[magic(4B), compressed_size(4B)]`). We want to decompress it and mount it into the `ArtifactTree` for recursive decompilation.

```python
import struct
import zlib

def probe():
    base_offset = 0x84000
    header = read_file_range(base_offset, 8)
    if len(header) < 8:
        return {"error": f"Offset 0x{base_offset:x} out of range"}

    magic, comp_size = struct.unpack("<4sI", header)
    comp_bytes = read_file_range(base_offset + 8, min(comp_size, 10 * 1024 * 1024))

    try:
        # Try standard zlib header first, then raw deflate (-15)
        unpacked = zlib.decompress(comp_bytes)
    except Exception:
        unpacked = zlib.decompress(comp_bytes, -15)

    child_info = register_child(
        offset=base_offset + 8,
        length=len(unpacked),
        data=unpacked,
        name="unpacked_overlay.bin",
        description=f"Decompressed payload from 0x{base_offset:x} (magic={magic.hex()})"
    )
    print(f"[+] Decompressed {len(unpacked)} bytes -> {child_info}")
    return child_info
```

---

## Recipe 2: Single-Byte & Multi-Byte Rolling XOR Brute-Force (`re_verify_hypothesis`)

### Use Case
Decompiled code shows an XOR loop over an encrypted buffer at `target_va`, but the key is computed dynamically or unknown. This script brute-forces single-byte keys (and checks known multi-byte keys) using printable ASCII scoring.

```python
def verify(data: bytes):
    best_key = None
    best_score = 0.0
    best_pt = b""

    for k in range(1, 256):
        candidate = safe_xor(data, bytes([k]))
        # Strip trailing nulls before scoring printable ASCII ratio
        stripped = candidate.rstrip(b"\x00")
        if not stripped:
            continue
        printable = sum(1 for b in stripped if 32 <= b <= 126 or b in (9, 10, 13))
        score = printable / len(stripped)
        if score > best_score:
            best_score = score
            best_key = k
            best_pt = stripped

    if best_score >= 0.85 and best_key is not None:
        text = best_pt.decode("utf-8", errors="replace")
        print(f"[+] Found XOR key: 0x{best_key:02x} (score={best_score:.2f}): {text}")
        return {
            "confirmed": True,
            "xor_key_hex": hex(best_key),
            "confidence_score": round(best_score, 3),
            "plaintext": text
        }

    return {"confirmed": False, "best_score": round(best_score, 3)}
```

---

## Recipe 3: RC4 Stream Cipher Decryption & Header Validation (`re_verify_hypothesis`)

### Use Case
`re_query_function` reveals a 256-byte S-box permutation loop (KSA + PRGA) decrypting a configuration block or embedded stage-2 binary with a discovered key string. Use the built-in `safe_rc4` helper to verify the key and inspect the decrypted output.

```python
def verify(data: bytes):
    candidate_keys = [
        b"MetisSecretKey2026",
        b"internal_config_key",
        bytes.fromhex("deadbeefcafebabe"),
    ]

    for key in candidate_keys:
        pt = safe_rc4(data, key)
        # Check for JSON, URL, ELF/PE/Mach-O magic, or high ASCII ratio
        is_magic = pt.startswith((b"{", b"http", b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe"))
        printable_ratio = sum(1 for b in pt if 32 <= b <= 126) / max(len(pt), 1)
        if is_magic or printable_ratio > 0.85:
            return {
                "confirmed": True,
                "matched_key": key.hex(),
                "plaintext_preview": pt[:128].decode("utf-8", errors="replace"),
                "plaintext_hex": pt[:64].hex()
            }

    return {"confirmed": False}
```

---

## Recipe 4: Custom Archive / TLV Container Unpacker (`re_run_probe_script`)

### Use Case
A proprietary bundle uses a custom directory header at offset `0x10000`:
`[Magic "PACK" (4B)] [EntryCount (4B)]` followed by `EntryCount` records of `[Type (4B), DataOffset (4B), DataLength (4B), Name (16B)]`.

```python
import struct

def probe():
    base_offset = 0x10000
    hdr = read_file_range(base_offset, 8)
    if len(hdr) < 8 or hdr[:4] != b"PACK":
        return {"error": f"Invalid container magic at 0x{base_offset:x}: {hdr[:4]}"}

    entry_count = struct.unpack("<I", hdr[4:8])[0]
    entry_size = 28  # 4 + 4 + 4 + 16
    table_raw = read_file_range(base_offset + 8, entry_count * entry_size)

    mounted = []
    for i in range(min(entry_count, 64)):
        rec = table_raw[i * entry_size:(i + 1) * entry_size]
        if len(rec) < entry_size:
            break
        t_type, rel_off, data_len = struct.unpack("<III", rec[:12])
        raw_name = rec[12:28].split(b"\x00")[0].decode("ascii", errors="ignore")
        safe_name = "".join(c for c in raw_name if c.isalnum() or c in ("_", "-", ".")) or f"entry_{i}.bin"

        payload = read_file_range(base_offset + rel_off, data_len)
        info = register_child(
            offset=base_offset + rel_off,
            length=len(payload),
            data=payload,
            name=safe_name,
            description=f"TLV entry #{i} (type={t_type})"
        )
        mounted.append(info)

    return {"entries_mounted": len(mounted), "children": mounted}
```

---

## Recipe 5: C++ / Rust / ObjC VTable & Function Pointer Table Scanner (`re_run_probe_script`)

### Use Case
Decompilation shows indirect virtual calls such as `(*(*(void ***)(rdi) + 0x18))(rdi)`. You know the vtable resides at virtual address `0x100008200` (or file offset `0x8200`) and want to enumerate all virtual method pointers in order.

```python
import struct

def probe():
    vtable_va = "0x100008200"
    ptr_size = 8  # 64-bit architecture
    max_slots = 32

    raw = read_memory(vtable_va, max_slots * ptr_size)
    if not raw:
        # Fallback to physical file offset if needed
        raw = read_file_range(0x8200, max_slots * ptr_size)

    slots = []
    for idx in range(0, len(raw), ptr_size):
        chunk = raw[idx:idx + ptr_size]
        if len(chunk) < ptr_size:
            break
        fn_ptr = struct.unpack("<Q", chunk)[0]
        if fn_ptr == 0:
            break  # Null terminator or RTTI boundary
        slots.append({
            "slot_index": idx // ptr_size,
            "byte_offset": hex(idx),
            "target_va": f"0x{fn_ptr:x}"
        })

    return {"vtable_base": vtable_va, "method_count": len(slots), "slots": slots}
```

---

## Recipe 6: Multi-Algorithm Dynamic API Hash Cracker (`re_verify_hypothesis`)

### Use Case
Malware or shellcode resolves imports dynamically using `ROR13`, `DJB2`, `FNV-1a (32-bit)`, or `CRC32`. Pass the 4-byte immediate hash slice at `target_va` (or set `TARGET_HASH` directly) to test against common Windows/POSIX API names using built-in `ror` and `zlib.crc32`.

```python
import struct
import zlib

def djb2(name: bytes) -> int:
    h = 5381
    for b in name:
        h = ((h << 5) + h + b) & 0xFFFFFFFF
    return h

def fnv1a_32(name: bytes) -> int:
    h = 0x811C9DC5
    for b in name:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h

def ror13_hash(name: bytes) -> int:
    h = 0
    for b in name:
        h = (ror(h, 13, 32) + b) & 0xFFFFFFFF
    return h

def verify(data: bytes):
    target_hash = struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0

    candidates = [
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc",
        "VirtualAllocEx", "VirtualProtect", "CreateThread", "CreateRemoteThread",
        "CreateProcessA", "CreateProcessW", "OpenProcess", "WriteProcessMemory",
        "WinExec", "InternetOpenA", "HttpOpenRequestA", "WinHttpSendRequest",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "LdrLoadDll"
    ]

    for api in candidates:
        raw = api.encode("ascii")
        algos = {
            "ror13": ror13_hash(raw),
            "ror13_null": ror13_hash(raw + b"\x00"),
            "djb2": djb2(raw),
            "fnv1a_32": fnv1a_32(raw),
            "crc32": zlib.crc32(raw) & 0xFFFFFFFF,
        }
        for algo_name, h_val in algos.items():
            if h_val == target_hash:
                return {
                    "confirmed": True,
                    "api_name": api,
                    "algorithm": algo_name,
                    "hash_hex": f"0x{target_hash:08x}"
                }

    return {"confirmed": False, "queried_hash": f"0x{target_hash:08x}"}
```

---

## Recipe 7: Go / Rust Non-Null-Terminated `{ptr, len}` String Table Recovery (`re_run_probe_script`)

### Use Case
Go and Rust store strings as `(data_ptr: uint64, byte_len: uint64)` pairs without `\x00` terminators, causing standard C-string extractors to merge adjacent strings into a giant blob. This probe parses a slice of `{ptr, len}` descriptors and resolves each string cleanly.

```python
import struct

def probe():
    # Example: table of {ptr, len} structs at VA 0x10000c000
    table_va = "0x10000c000"
    entry_count = 20
    raw_table = read_memory(table_va, entry_count * 16)

    recovered = []
    for i in range(0, len(raw_table), 16):
        entry = raw_table[i:i + 16]
        if len(entry) < 16:
            break
        str_ptr, str_len = struct.unpack("<QQ", entry)
        if 0 < str_len <= 512 and str_ptr > 0x1000:
            s_bytes = read_memory(f"0x{str_ptr:x}", str_len)
            if s_bytes:
                recovered.append({
                    "index": i // 16,
                    "ptr_va": f"0x{str_ptr:x}",
                    "length": str_len,
                    "text": s_bytes.decode("utf-8", errors="replace")
                })

    return {"recovered_count": len(recovered), "strings": recovered}
```

---

## Recipe 8: On-the-Fly Capstone Disassembly & Instruction Pattern Hunting (`re_run_probe_script`)

### Use Case
When inspecting unmapped shellcode, custom trampolines, or instructions truncated by `noreturn` calls, use the pre-injected `capstone` module inside `re_run_probe_script` to disassemble arbitrary physical offsets or virtual addresses.

```python
def probe():
    if capstone is None:
        return {"error": "Capstone not installed in environment"}

    code_offset = 0x1200
    base_va = 0x100001200
    raw_code = read_file_range(code_offset, 128)

    # Use CS_ARCH_X86 + CS_MODE_64 or CS_ARCH_ARM64 + CS_MODE_ARM
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    insns = []
    for insn in md.disasm(raw_code, base_va):
        insns.append(f"0x{insn.address:x}: {insn.mnemonic}\t{insn.op_str}")

    return {"instruction_count": len(insns), "disassembly": insns}
```

---

## Recipe 9: Stack String / Immediate Mov-Byte Reconstruction (`re_verify_hypothesis`)

### Use Case
Obfuscated binaries construct sensitive strings on the stack using sequences of immediate `mov byte ptr [rbp - offset], 0x..` or `mov dword ptr [rsp + offset], 0x........` instructions. Feed the instruction slice via `target_va` to extract the immediate bytes in order.

```python
import re

def verify(data: bytes):
    # Extract C6 45 xx <imm8> or C6 85 xx xx xx xx <imm8> (x86_64 mov byte [rbp+disp], imm8)
    chars = []
    i = 0
    while i < len(data) - 3:
        if data[i] == 0xC6 and (data[i + 1] & 0xC7) == 0x45:
            imm = data[i + 3]
            if imm != 0:
                chars.append(chr(imm) if 32 <= imm <= 126 else f"\\x{imm:02x}")
            i += 4
            continue
        i += 1

    reconstructed = "".join(chars)
    if len(reconstructed) >= 4:
        return {"confirmed": True, "stack_string": reconstructed}
    return {"confirmed": False, "partial": reconstructed}
```

---

## Recipe 10: Mock Context Struct Builder for `re_emulate_slice` (`re_verify_hypothesis`)

### Use Case
Before calling `re_emulate_slice`, you may need to verify the exact byte layout of a synthetic struct or register state to check how bitfields and little-endian integers pack in memory.

```python
import struct

def verify(data: bytes):
    """
    Constructs a 32-byte AuthContext structure:
      +0x00: magic (uint32 = 0x4D455453 'STEM')
      +0x04: flags (uint32 = 0x00000001 AUTHENTICATED)
      +0x08: user_id (uint64 = 1001)
      +0x10: token_va (uint64 = 0x100009000)
      +0x18: crc_check (uint64 = 0)
    """
    ctx_bytes = struct.pack("<IIQQQ", 0x4D455453, 1, 1001, 0x100009000, 0)
    return {
        "confirmed": True,
        "struct_size": len(ctx_bytes),
        "struct_hex": ctx_bytes.hex()
    }
```
