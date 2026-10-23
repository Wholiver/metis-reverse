#!/usr/bin/env python3
"""Generates benchmark fixtures for Metis Reverse acceptance and evaluation suite."""

import os
import struct
import hashlib
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


def build_bun_composite_fixture() -> Path:
    """Builds an authentic Mach-O 64-bit ARM64 Bun composite binary fixture.
    
    Contains:
    - Mach-O header with ImageBase 0x100000000
    - __TEXT segment with entrypoint VA 0x100a28080 containing prologue 'f8 5f bc a9'
    - __BUN large data segment containing StandaloneModuleGraph
    - Embedded JS modules with URLs, env vars, and native bridge calls
    - 5 embedded native .node modules with 64-byte N-API property descriptors:
        * image-processor.node
        * computer-use-swift.node
        * computer-use-input.node
        * audio-capture.node
        * url-handler.node
    - Fixed-length Go/Rust string slices without null terminators
    """
    total_size = 0x80000 # 512 KB
    buf = bytearray(total_size)

    # 1. Mach-O 64-bit LE Header
    # magic=0xfeedfacf, cputype=0x0100000c (ARM64), cpusubtype=0, filetype=2 (EXECUTE), ncmds=2
    magic = 0xfeedfacf
    cputype = 0x0100000c
    cpusubtype = 0
    filetype = 2
    ncmds = 2
    # Load Command 1: LC_SEGMENT_64 __TEXT with 1 section (__text) -> size 72 + 80 = 152 bytes
    # Load Command 2: LC_SEGMENT_64 __BUN -> size 72 bytes
    sizeofcmds = 152 + 72 # 224 bytes
    flags = 0x200085
    reserved = 0
    header_bytes = struct.pack("<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
    buf[:32] = header_bytes

    # Load Command 1: LC_SEGMENT_64 __TEXT (0x19) with 1 section
    # cmd=0x19, cmdsize=152, segname='__TEXT\x00', vmaddr=0x100a00000, vmsize=0x30000, fileoff=0, filesize=0x30000, maxprot=7, initprot=5, nsects=1, flags=0
    seg_text = struct.pack(
        "<II16sQQQQiiII",
        0x19, 152, b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x100a00000, 0x30000, 0, 0x30000, 7, 5, 1, 0
    )
    buf[32:32 + 72] = seg_text

    # Section 1 inside __TEXT: __text
    # sectname='__text\x00', segname='__TEXT\x00', addr=0x100a00000, size=0x30000, offset=0, align=4, reloff=0, nreloc=0, flags=0x80000400
    sect_text = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x100a00000, 0x30000, 0, 4, 0, 0, 0x80000400, 0, 0, 0
    )
    buf[32 + 72:32 + 152] = sect_text

    # Load Command 2: LC_SEGMENT_64 __BUN (0x19) with 0 sections
    # cmd=0x19, cmdsize=72, segname='__BUN\x00', vmaddr=0x100a30000, vmsize=0x50000, fileoff=0x30000, filesize=0x50000, maxprot=3, initprot=3, nsects=0, flags=0
    seg_bun = struct.pack(
        "<II16sQQQQiiII",
        0x19, 72, b"__BUN\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        0x100a30000, 0x50000, 0x30000, 0x50000, 3, 3, 0, 0
    )
    buf[32 + 152:32 + 224] = seg_bun

    # 2. Place entrypoint prologue 'f85fbca9' at VA 0x100a28080 (offset 0x28080)
    prologue_offset = 0x28080
    buf[prologue_offset:prologue_offset + 4] = bytes.fromhex("f85fbca9")
    # Followed by some ARM64 instructions: mov x29, sp; nop; ret
    buf[prologue_offset + 4:prologue_offset + 16] = bytes.fromhex("fd0300911f2003d5c0035fd6")

    # String constants in __TEXT
    text_strs = (
        b"$sSSN\x00" # Swift String type
        b"_ZN3Foo3BarEv\x00" # C++ vtable/symbol
        b"initWithCoder:\x00" # ObjC selector
        b"FixedLengthSecretKeyWithoutNullTerminator12345678AdjacentStringDoNotConcat" # Fixed length Go/Rust string pool
    )
    buf[0x1000:0x1000 + len(text_strs)] = text_strs

    # 3. Build __BUN segment at offset 0x30000
    bun_start = 0x30000
    cur_bun = bun_start

    # Bundled JS modules
    js_app = b"""//$bunfs/root/app.js
const img = require("image-processor");
const swift = require("computer-use-swift");
const input = require("computer-use-input");
const audio = require("audio-capture");
const url = require("url-handler");

console.log("Bun Polyglot App initializing...");
const processed = img.processImage(Buffer.from("raw_pixels"));
const currentMode = img.filterMode;
img.quality = 95;
swift.captureScreen();
input.sendClick(100, 200);
audio.startStream();
url.openBrowser("https://internal.corp/admin");
"""
    buf[cur_bun:cur_bun + len(js_app)] = js_app
    cur_bun += len(js_app) + 64

    js_config = b"""//$bunfs/root/config.js
export const API_ENDPOINT = "https://api.internal.corp/v2/secure";
export const MASTER_KEY = process.env.AUTH_SECRET;
export const SERVER_CONFIG = {
    "timeout_ms": 3000,
    "max_retries": 5,
    "cluster_id": "us-east-prod"
};
"""
    buf[cur_bun:cur_bun + len(js_config)] = js_config
    cur_bun += len(js_config) + 64

    # Native .node modules
    def create_embedded_node(name: str, export_name: str, has_accessors: bool = False) -> bytes:
        # Build self-contained Mach-O 64-bit dylib/.node slice with 64-byte descriptors
        node_len = 0x2000 # 8KB
        nbuf = bytearray(node_len)
        # Header
        n_magic = struct.pack("<IIIIIIII", 0xfeedfacf, 0x0100000c, 0, 6, 1, 72, 0, 0)
        nbuf[:32] = n_magic
        n_seg = struct.pack(
            "<II16sQQQQiiII",
            0x19, 72, b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0x100000000, node_len, 0, node_len, 7, 5, 0, 0
        )
        nbuf[32:32 + 72] = n_seg

        # Symbols & names
        id_str = f"node_modules/{name}/{name}.node\x00napi_register_module_v1\x00{export_name}\x00filterMode\x00quality\x00"
        nbuf[0x200:0x200 + len(id_str)] = id_str.encode()

        # Build 64-byte N-API property descriptors table at offset 0x400
        # 1. method descriptor: 'export_name' at local offset 0x1000 (VA 0x100001000)
        utf8_off = 0x100000000 + 0x200 + id_str.find(export_name)
        method_va = 0x100001000
        nbuf[0x1000:0x1008] = b"\xc0\x03\x5f\xd6\x00\x00\x00\x00" # ARM64 ret instruction
        desc1 = struct.pack("<QQQQQQQQ", utf8_off, 0, method_va, 0, 0, 0, 1, 0) # attributes=1 (writable)
        nbuf[0x400:0x440] = desc1

        if has_accessors:
            # 2. getter/setter descriptor: 'filterMode' at local offsets 0x1200 / 0x1280
            fm_off = 0x100000000 + 0x200 + id_str.find("filterMode")
            getter_va = 0x100001200
            setter_va = 0x100001280
            nbuf[0x1200:0x1208] = b"\xc0\x03\x5f\xd6\x00\x00\x00\x00"
            nbuf[0x1280:0x1288] = b"\xc0\x03\x5f\xd6\x00\x00\x00\x00"
            desc2 = struct.pack("<QQQQQQQQ", fm_off, 0, 0, getter_va, setter_va, 0, 2, 0)
            nbuf[0x440:0x480] = desc2

            # 3. getter/setter descriptor: 'quality' at local offsets 0x1300 / 0x1380
            q_off = 0x100000000 + 0x200 + id_str.find("quality")
            q_get = 0x100001300
            q_set = 0x100001380
            nbuf[0x1300:0x1308] = b"\xc0\x03\x5f\xd6\x00\x00\x00\x00"
            nbuf[0x1380:0x1388] = b"\xc0\x03\x5f\xd6\x00\x00\x00\x00"
            desc3 = struct.pack("<QQQQQQQQ", q_off, 0, 0, q_get, q_set, 0, 2, 0)
            nbuf[0x480:0x4c0] = desc3

        return bytes(nbuf)

    node_modules = [
        ("image-processor", "processImage", True),
        ("computer-use-swift", "captureScreen", False),
        ("computer-use-input", "sendClick", False),
        ("audio-capture", "startStream", False),
        ("url-handler", "openBrowser", False),
    ]

    for mod_name, export_sym, has_acc in node_modules:
        # Preceding path label for module graph resolver
        pre_label = f"node_modules/{mod_name}/{mod_name}.node\x00".encode()
        buf[cur_bun:cur_bun + len(pre_label)] = pre_label
        cur_bun += len(pre_label)
        # Pad to 16 bytes alignment
        if cur_bun % 16 != 0:
            cur_bun += 16 - (cur_bun % 16)

        node_bytes = create_embedded_node(mod_name, export_sym, has_accessors=has_acc)
        buf[cur_bun:cur_bun + len(node_bytes)] = node_bytes
        cur_bun += len(node_bytes) + 32

    # Trailer signature: \n---- Bun! ----\n
    trailer = b"\n---- Bun! ----\n"
    buf[total_size - len(trailer):] = trailer

    out_path = FIXTURES_DIR / "bun_composite_sample"
    out_path.write_bytes(bytes(buf))
    return out_path


def build_family_fixtures():
    """Generates synthetic binary fixtures for all Phase 3 language families."""
    # 1. Go fixture
    go_data = (
        b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 32) +
        b"\xf1\xff\xff\xff" + # Go 1.20+ pclntab magic
        b"Go buildinf:\x00" +
        b"main.WorkerThread\x00" +
        b"main.DecryptPayload\x00" +
        b"runtime.gopanic\x00" +
        b"sync/atomic.LoadInt64\x00"
    )
    (FIXTURES_DIR / "sample_go.bin").write_bytes(go_data)

    # 2. Rust fixture
    rust_data = (
        b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 32) +
        b"rust_begin_unwind\x00" +
        b"_ZN7mycrate3foo17h1234567890abcdefE\x00" +
        b"_ZN7mycrate3bar17h0123456789abcdefE\x00" +
        b"_R7mycrate3bazE\x00"
    )
    (FIXTURES_DIR / "sample_rust.bin").write_bytes(rust_data)

    # 3. Python / PyInstaller fixture
    py_data = (
        b"MEI\x0c\x0b\x0a\x0b\x0e" + # PyInstaller magic
        b"\xa7\x0e\r\n" + # Python 3.11 pyc magic
        b"pyimod01_os_path\x00" +
        b"main_script_bytecode_payload"
    )
    (FIXTURES_DIR / "sample_pyinstaller.bin").write_bytes(py_data)

    # 4. .NET fixture
    dotnet_data = (
        b"MZ\x90\x00" + (b"\x00" * 0x38) + struct.pack("<I", 0x80) +
        (b"\x00" * 0x40) + b"PE\x00\x00" + (b"\x00" * 0x100) +
        b"mscoree.dll\x00_CorExeMain\x00" +
        b"BSJB" + (b"\x00" * 8) + struct.pack("<I", 12) + b"v4.0.30319\x00\x00"
    )
    (FIXTURES_DIR / "sample_dotnet.dll").write_bytes(dotnet_data)

    # 5. Lua fixture
    lua_data = b"\x1bLua\x54\x00\x01\x04\x08" + b"lua_compiled_chunk_data"
    (FIXTURES_DIR / "sample_lua.luac").write_bytes(lua_data)

    # 6. Firmware fixture
    fw_data = (
        b"hsqs\x00\x00\x01\x00" + # SquashFS magic
        b"\x27\x05\x19\x56" + # U-Boot uImage magic
        (b"\x00" * 128) + b"Linux Kernel / Busybox firmware image"
    )
    (FIXTURES_DIR / "sample_firmware.bin").write_bytes(fw_data)

    # 7. JVM / Android fixture
    dex_data = (
        b"dex\n035\x00" + (b"\x00" * 24) +
        struct.pack("<I", 512) + (b"\x00" * 64) +
        b"Lcom/example/app/MainActivity;\x00" +
        b"Lcom/example/crypto/NativeBridge;\x00" +
        b"Lcom/google/firebase/FirebaseApp;\x00"
    )
    (FIXTURES_DIR / "sample_android.dex").write_bytes(dex_data)

    # 8. WebAssembly fixture
    wasm_data = (
        b"\x00asm" + struct.pack("<I", 1) + # Wasm v1
        b"\x01\x08\x01\x60\x00\x01\x7f" + # Type section
        b"\x03\x02\x01\x00" + # Function section
        b"\x07\x0a\x01\x06addTwo\x00\x00" # Export section: export "addTwo"
    )
    (FIXTURES_DIR / "sample_wasm.wasm").write_bytes(wasm_data)

    # 9. IL2CPP Metadata fixture with realistic string pool, image headers, and type definitions
    str_pool = (
        b"\x00Assembly-CSharp.dll\x00UnityEngine.CoreModule.dll\x00"
        b"SecurityController\x00DecryptPayload\x00mscorlib.dll\x00"
        b"Game.Security\x00InitializeSecurity\x00TokenKey\x00"
    )
    il2cpp_buf = bytearray(1024)
    # Magic & Version
    il2cpp_buf[:4] = b"\xaf\x1b\xb1\xfa" # 0xFAB11BAF
    struct.pack_into("<I", il2cpp_buf, 4, 29) # version 29

    # Offsets layout in header:
    # 8: stringLiteralOffset, 12: stringLiteralSize
    struct.pack_into("<II", il2cpp_buf, 8, 0x100, 16)
    # 16: stringLiteralDataOffset, 20: stringLiteralDataSize
    struct.pack_into("<II", il2cpp_buf, 16, 0x110, 64)
    # 24: stringOffset, 28: stringSize
    str_offset = 0x200
    struct.pack_into("<II", il2cpp_buf, 24, str_offset, len(str_pool))
    il2cpp_buf[str_offset:str_offset + len(str_pool)] = str_pool

    # 160: typeDefinitionsOffset, 164: typeDefinitionsSize
    type_offset = 0x300
    struct.pack_into("<II", il2cpp_buf, 160, type_offset, 96)
    # Type 1: nameIndex = str_pool.find(b"SecurityController"), nsIndex = str_pool.find(b"Game.Security")
    sc_name_idx = str_pool.find(b"SecurityController")
    sc_ns_idx = str_pool.find(b"Game.Security")
    struct.pack_into("<II", il2cpp_buf, type_offset, sc_name_idx, sc_ns_idx)

    # 176: imagesOffset, 180: imagesSize
    img_offset = 0x380
    struct.pack_into("<II", il2cpp_buf, 176, img_offset, 48)
    # Image 1: nameIndex = str_pool.find(b"Assembly-CSharp.dll")
    asm_name_idx = str_pool.find(b"Assembly-CSharp.dll")
    struct.pack_into("<I", il2cpp_buf, img_offset, asm_name_idx)

    (FIXTURES_DIR / "global-metadata.dat").write_bytes(bytes(il2cpp_buf))

    # 10. Flutter fixture with AOT snapshot clusters, Dart feature flags, and package URIs
    flutter_buf = bytearray(2048)
    flutter_header = (
        b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 32) +
        b"libflutter.so\x00" +
        b"kSnapshotMagic\x00" +
        b"product no-type-checks arm64-sysv\x00" +
        b"isolate_snapshot_data\x00" +
        b"vm_snapshot_data\x00" +
        b"isolate_snapshot_instructions\x00" +
        b"package:my_app/main.dart\x00" +
        b"package:my_app/security/vault.dart\x00" +
        b"a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e\x00"
    )
    flutter_buf[:len(flutter_header)] = flutter_header
    (FIXTURES_DIR / "sample_flutter.so").write_bytes(bytes(flutter_buf))

    # 11. HarmonyOS Ark Bytecode fixture with class headers and literal string constants
    ark_buf = bytearray(1024)
    # Magic 0x12 00 00 00, Version 1, FileSize 1024, NumClasses 3
    struct.pack_into("<IIII", ark_buf, 0, 0x00000012, 1, 1024, 3)
    ark_strings = b"EntryAbility\x00MainPage\x00onWindowStageCreate\x00hilog\x00onCreate\x00"
    ark_buf[64:64 + len(ark_strings)] = ark_strings
    (FIXTURES_DIR / "sample_ark.abc").write_bytes(bytes(ark_buf))

    # 12. UPX Packer fixture
    upx_data = (
        b"MZ\x90\x00" + (b"\x00" * 60) + struct.pack("<I", 64) +
        b"PE\x00\x00" + (b"\x00" * 128) +
        b"UPX0\x00\x00\x00\x00" + b"UPX1\x00\x00\x00\x00" + b"UPX!\x00\x00\x00\x00"
    )
    (FIXTURES_DIR / "sample_upx.bin").write_bytes(upx_data)


def build_large_sample_fixture() -> Path:
    """Constructs a 48 MB 64-bit Mach-O binary fixture with distinct anchors to stress-test 64-bit offsets."""
    out_path = FIXTURES_DIR / "sample_large_48mb.bin"
    with open(out_path, "wb") as f:
        # 1. Mach-O 64-bit Header
        magic = 0xfeedfacf
        cputype = 0x0100000c # ARM64
        cpusubtype = 0
        filetype = 2 # MH_EXECUTE
        ncmds = 2
        sizeofcmds = 72 * 2
        flags = 0x200085
        reserved = 0
        hdr = struct.pack("<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
        f.write(hdr)

        # 2. Command 1: __TEXT (64KB at VA 0x100000000)
        text_seg = struct.pack(
            "<II16sQQQQiiII",
            0x19, 72, b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0x100000000, 0x10000, 0, 0x10000, 7, 5, 0, 0
        )
        f.write(text_seg)

        # 3. Command 2: __DATA_LARGE (48MB at VA 0x100010000, offset 0x10000)
        data_size = 48 * 1024 * 1024
        data_seg = struct.pack(
            "<II16sQQQQiiII",
            0x19, 72, b"__DATA_LARGE\x00\x00\x00\x00",
            0x100010000, data_size, 0x10000, data_size, 3, 3, 0, 0
        )
        f.write(data_seg)

        # Anchor 0: Head at offset 0x10000 (VA 0x100010000)
        f.seek(0x10000)
        f.write(b"CANARY_HEAD_0x100010000_OFFSET_0x10000")

        # Anchor 1: 16MB at offset 0x1010000 (VA 0x101010000)
        f.seek(0x10000 + 16 * 1024 * 1024)
        f.write(b"CANARY_16MB_0x101010000_OFFSET_0x1010000")

        # Anchor 2: 32MB at offset 0x2010000 (VA 0x201010000)
        f.seek(0x10000 + 32 * 1024 * 1024)
        f.write(b"CANARY_32MB_0x201010000_OFFSET_0x2010000")

        # Anchor 3: Tail at offset 0x10000 + data_size - 64 (VA 0x100010000 + data_size - 64)
        f.seek(0x10000 + data_size - 64)
        f.write(b"CANARY_TAIL_0x300FFC0_OFFSET_END")

        f.flush()
    return out_path


if __name__ == "__main__":
    bun_p = build_bun_composite_fixture()
    print("Created Bun composite fixture at:", bun_p)
    build_family_fixtures()
    print("Created all Phase 3 family fixtures in:", FIXTURES_DIR)
    large_p = build_large_sample_fixture()
    print("Created 48MB large sample fixture at:", large_p)
