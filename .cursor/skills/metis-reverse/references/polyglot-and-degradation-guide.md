# Metis Reverse MCP: Polyglot Reversing & 4-Tier Degradation Guide

This guide equips AI Agents with architecture-specific playbooks for **12 modern polyglot ecosystems** and defines the **4-Tier Deterministic Degradation Strategy** when heavy external decompilers (Ghidra `12.1.1+`, `ilspycmd`, `jadx`) are absent or encounter opaque bytecodes.

---

## Table of Contents

- [Part 1: Polyglot Ecosystem Reversing Playbooks (12 Families)](#part-1-polyglot-ecosystem-reversing-playbooks-12-families)
  - [1. Go (Golang) Binaries (`pclntab` & `ABIInternal`)](#1-go-golang-binaries-pclntab--abiinternal)
  - [2. Rust Binaries (Legacy / `v0` Mangling & Monomorphization)](#2-rust-binaries-legacy--v0-mangling--monomorphization)
  - [3. Bun Standalone & Electron ASAR Hybrid Bundles (`N-API`)](#3-bun-standalone--electron-asar-hybrid-bundles-n-api)
  - [4. Android APK / DEX & Native JNI (`RegisterNatives`)](#4-android-apk--dex--native-jni-registernatives)
  - [5. .NET / CLR Assemblies & P/Invoke (`CLI Header`)](#5-net--clr-assemblies--pinvoke-cli-header)
  - [6. Python & PyInstaller Executables (`MEI` TOC & `.pyc` Repair)](#6-python--pyinstaller-executables-mei-toc--pyc-repair)
  - [7. Unity IL2CPP (`libil2cpp.so` & `global-metadata.dat`)](#7-unity-il2cpp-libil2cppso--global-metadatadat)
  - [8. Flutter & Dart AOT (`libapp.so` & Object Pool)](#8-flutter--dart-aot-libappso--object-pool)
  - [9. HarmonyOS ArkTS (`.abc` Bytecode & Native N-API)](#9-harmonyos-arkts-abc-bytecode--native-n-api)
  - [10. Lua & LuaJIT Bytecode (`\x1bLua` & `\x1bLJ`)](#10-lua--luajit-bytecode-x1blua--x1blj)
  - [11. WebAssembly Modules (`\x00asm`)](#11-webassembly-modules-x00asm)
  - [12. Embedded Firmware Containers (SquashFS, CramFS, U-Boot)](#12-embedded-firmware-containers-squashfs-cramfs-u-boot)
- [Part 2: The 4-Tier Deterministic Degradation Matrix](#part-2-the-4-tier-deterministic-degradation-matrix)
  - [Core Principle: Truth in Advertising (R3 / R4)](#core-principle-truth-in-advertising-r3--r4)
  - [4-Tier Fallback Hierarchy](#4-tier-fallback-hierarchy)
  - [Degradation & Diagnostic Fields Reference](#degradation--diagnostic-fields-reference)
  - [Agent Do's & Don'ts in Degraded Mode](#agent-dos--donts-in-degraded-mode)
- [Part 3: Missing Dependency Remediation & Auto-Configuration Guide](#part-3-missing-dependency-remediation--auto-configuration-guide)
  - [1. Symptom-to-Dependency Remediation Matrix](#1-symptom-to-dependency-remediation-matrix)
  - [2. Auto-Discovery Paths in `MetisConfig`](#2-auto-discovery-paths-in-metisconfig)
  - [3. One-Shot Environment Doctor & Setup Commands](#3-one-shot-environment-doctor--setup-commands)

---

## Part 1: Polyglot Ecosystem Reversing Playbooks (12 Families)

### 1. Go (Golang) Binaries (`pclntab` & `ABIInternal`)
- **Binary Signatures & Internals**:
  - Statically linked runtime (`runtime.main`, `runtime.gopanic`), section `.gopclntab` or `Go buildinf:` magic.
  - **`pclntab` Magic Bytes** (little-endian):
    - `fb ff ff ff` (`0xfffffffb`) -> Go 1.2 - 1.15
    - `fa ff ff ff` (`0xfffffffa`) -> Go 1.16 - 1.17
    - `f0 ff ff ff` (`0xfffffff0`) -> Go 1.18 - 1.19
    - `f1 ff ff ff` (`0xfffffff1`) -> Go 1.20+
  - **Calling Convention (`ABIInternal`, Go 1.17+)**: Passes integer arguments and return values in registers (`RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11` on x86_64) instead of the stack. Standard C decompilers often emit `unaff_RBX` warnings.
  - **String Representation**: 16-byte `{uint8 *ptr, int len}` structs without `\x00` terminators.
- **Actionable Workflow**:
  1. Call `re_capabilities` and `re_query_function` with `include_libraries=false` to fold `runtime.*` and `sync.*` noise.
  2. When `decompiler_warnings` reports `unaff_` registers, inspect the side-by-side `disassembly` field to trace `RAX`/`RBX`/`RCX` arguments.
  3. For CGO bridges, run `re_bridge_map(bridge_type="cgo")` to recover `_cgoexp_*` and `_cgo_*` exports.
  4. Use Recipe 7 in `escape-hatch-probe-recipes.md` (`re_run_probe_script`) to extract `{ptr, len}` string tables cleanly.

---

### 2. Rust Binaries (Legacy / `v0` Mangling & Monomorphization)
- **Binary Signatures & Internals**:
  - Contains `rust_begin_unwind`, `/rustc/<commit>`, `.cargo`, or mangled symbols:
    - **Legacy Mangling**: `_ZN<len><crate><len><module><len><item>17h<16-hex-hash>E`
    - **v0 Mangling**: `_R...`
  - **Monomorphization**: Generic functions instantiate separate machine-code copies per concrete type, inflating function counts.
  - **Enums & `Result<T, E>`**: Represented as tagged unions (`discriminant` + payload); `unwrap()` / `expect()` branches reference panic location structs (`{file_ptr, file_len, line, col}`).
- **Actionable Workflow**:
  1. Keep `include_libraries=false` in `re_query_function` to fold `core::`, `alloc::`, and `std::` boilerplate.
  2. Anchor analysis on panic strings (`referenced_strings_shielded`) to infer module filenames, line numbers, and invariant checks.
  3. For Python/Rust extensions (`PyO3`), call `re_bridge_map(bridge_type="pyo3")`; for Tauri desktop apps, call `re_bridge_map(bridge_type="tauri")`.

---

### 3. Bun Standalone & Electron ASAR Hybrid Bundles (`N-API`)
- **Binary Signatures & Internals**:
  - **Bun Single-File Executables**: Native ELF/Mach-O/PE host binary with an embedded `__BUN` section or `---- Bun! ----` trailer containing bundled JavaScript and optional `.node` native addons.
  - **Electron Apps**: `app.asar` archive (`\x04\x00\x00\x00` header + JSON file directory) paired with native `.node` addons and preload scripts (`contextBridge.exposeInMainWorld`).
  - **N-API (`napi_property_descriptor`)**: Native `.node` shared libraries register methods via `napi_define_properties` using a 64-byte struct on 64-bit targets:
    ```c
    typedef struct {
      const char *utf8name;       // +0x00: Pointer to exported JS property/function name
      napi_value name;            // +0x08
      napi_callback method;       // +0x10: Native C/C++ implementation VA!
      napi_callback getter;       // +0x18
      napi_callback setter;       // +0x20
      napi_value value;           // +0x28
      napi_property_attributes attributes; // +0x30
      void *data;                 // +0x38
    } napi_property_descriptor;   // Total = 64 bytes (0x40)
    ```
- **Actionable Workflow**:
  1. `re_session_manager(action="open")` automatically extracts Bun standalone payloads into child nodes in the `ArtifactTree`. Call `re_tree_status` and `re_list_artifacts` to inspect them.
  2. For JS modules, **never read minified bundles whole**: run `js_list_modules` -> `js_list_closures` -> `js_get_module(slice_mode="closure", closure_name="...")`.
  3. Call `re_bridge_map(bridge_type="napi")` (or `"ipc"`) to parse 64-byte `napi_property_descriptor` tables and link JS calls directly to native `handler_va`, `local_file_offset`, and `container_file_offset`.

---

### 4. Android APK / DEX & Native JNI (`RegisterNatives`)
- **Binary Signatures & Internals**:
  - DEX header `dex\n035\x00` (or `038`/`039`) with string/type/proto/method index tables; native libraries reside in `lib/<abi>/lib*.so`.
  - **Static JNI**: Exported symbols matching `Java_<pkg>_<Class>_<method>`.
  - **Dynamic JNI**: Registered inside `JNI_OnLoad` via `(*env)->RegisterNatives(env, clazz, methods, count)` where each `JNINativeMethod` is `{const char *name, const char *signature, void *fnPtr}` (24 bytes on 64-bit).
- **Actionable Workflow**:
  1. Mount the `.so` or DEX artifact and call `re_bridge_map(bridge_type="jni")` to recover both static `Java_*` exports and dynamic `JNINativeMethod` descriptors.
  2. Call `re_decompile_function` on the resolved `fnPtr` VAs and refine JNI env parameter types via `re_refine_model`.

---

### 5. .NET / CLR Assemblies & P/Invoke (`CLI Header`)
- **Binary Signatures & Internals**:
  - PE binary containing `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` (`BSJB` metadata root signature `0x424A5342`), `#~` metadata tables (`Module`, `TypeDef`, `MethodDef`, `ImplMap`), and `#Strings` / `#US` heaps.
  - Native interop uses P/Invoke (`[DllImport("...")]` recorded in `ImplMap` / `ModuleRef`).
- **Actionable Workflow**:
  1. Check `re_capabilities` to see if `ilspycmd` is available or if metadata table extraction is active.
  2. Run `re_bridge_map(bridge_type="pinvoke")` to enumerate unmanaged DLL imports and native entrypoints.

---

### 6. Python & PyInstaller Executables (`MEI` TOC & `.pyc` Repair)
- **Binary Signatures & Internals**:
  - PyInstaller bundles append a `MEI\x0c\x0b\x0a\x0b\x0e` cookie at the tail of the PE/ELF binary pointing to a CArchive Table of Contents (TOC) of zlib-compressed `.pyc` entries and native `.pyd` / `.so` extensions.
  - Extracted `.pyc` files in PyInstaller often strip the 16-byte Python 3.7+ `.pyc` magic header (`[magic(4B), bitfield(4B), timestamp/hash(8B)]`).
- **Actionable Workflow**:
  1. Call `re_triage` and `re_capabilities` to detect `PyInstaller` and Python bytecode version.
  2. Use `re_run_probe_script` to unpack CArchive entries, prepend the matching 16-byte `.pyc` header if stripped, and mount native `.pyd`/`.so` extensions via `register_child` followed by `re_bridge_map(bridge_type="pyo3")`.

---

### 7. Unity IL2CPP (`libil2cpp.so` & `global-metadata.dat`)
- **Binary Signatures & Internals**:
  - Compiles C# IL into native C++ (`libil2cpp.so` / `GameAssembly.dll`) while stripping symbol names into an external `global-metadata.dat` file starting with magic `0xFAB11BAF` (`\xaf\x1b\xb1\xfa`) and a 32-bit version integer (typically v24–v31).
- **Actionable Workflow**:
  1. Inspect `global-metadata.dat` via `re_read_file_range(offset=0, length=64)` to verify magic `0xFAB11BAF` and metadata version.
  2. Use `re_run_probe_script` to parse string/method definition tables from `global-metadata.dat` and commit recovered method names to `libil2cpp.so` via `re_refine_model`.

---

### 8. Flutter & Dart AOT (`libapp.so` & Object Pool)
- **Binary Signatures & Internals**:
  - Dart AOT code is compiled into `libapp.so` (`_kDartVmSnapshotInstructions`, `_kDartIsolateSnapshotInstructions`, `_kDartIsolateSnapshotData`).
  - Uses a dedicated Object Pool register (`PP`, e.g., `x27` on ARM64, `r15` on x86_64) to load literals, strings, and dispatch targets.
- **Actionable Workflow**:
  1. Locate `_kDartIsolateSnapshotData` and `_kDartIsolateSnapshotInstructions` via `re_triage` / `re_query_function`.
  2. Use `re_extract_schemas` and `re_bridge_map` to identify Flutter `MethodChannel` / `BasicMessageChannel` route strings and native plugin handlers.

---

### 9. HarmonyOS ArkTS (`.abc` Bytecode & Native N-API)
- **Binary Signatures & Internals**:
  - HarmonyOS HAP/APP packages compile ArkTS/TS into Panda/Ark bytecode (`.abc`, magic `PANDA\x00\x00\x00`) and pair with native C++ `lib*.so` modules registered via ArkUI N-API (`napi_module_register`).
- **Actionable Workflow**:
  1. Inspect native `lib*.so` modules with `re_bridge_map(bridge_type="napi")` to map ArkTS JS bindings to native C++ VAs.
  2. Inspect `.abc` constant pools using `re_read_file_range` or `re_run_probe_script`.

---

### 10. Lua & LuaJIT Bytecode (`\x1bLua` & `\x1bLJ`)
- **Binary Signatures & Internals**:
  - Standard Lua bytecode starts with `\x1bLua` followed by version byte (`0x51` = Lua 5.1, `0x52` = 5.2, `0x53` = 5.3, `0x54` = 5.4).
  - LuaJIT bytecode starts with `\x1bLJ\x01` (2.0) or `\x1bLJ\x02` (2.1).
- **Actionable Workflow**:
  1. Verify header magic and endianness via `re_triage` / `re_read_file_range`.
  2. If custom-encrypted (common in Cocos2d-x games via XXTEA/XOR), locate the key in `libcocos2dlua.so` using `re_hunt_crypto_and_hashes`, verify decryption in `re_verify_hypothesis`, and mount the clean bytecode with `re_register_child_artifact`.

---

### 11. WebAssembly Modules (`\x00asm`)
- **Binary Signatures & Internals**:
  - Starts with `\x00asm\x01\x00\x00\x00` followed by typed sections (`1: Type`, `2: Import`, `3: Function`, `7: Export`, `10: Code`, `11: Data`).
- **Actionable Workflow**:
  1. Use `re_triage` and `re_capabilities` to inspect Wasm sections.
  2. Parse Import/Export/Data sections via `re_run_probe_script` to map host JS imports (`env.*`, `wasi_snapshot_preview1.*`) and exported Wasm functions.

---

### 12. Embedded Firmware Containers (SquashFS, CramFS, U-Boot)
- **Binary Signatures & Internals**:
  - Common magic signatures inside monolithic firmware blobs:
    - **U-Boot uImage**: `0x27051956` (`\x27\x05\x19\x56`)
    - **SquashFS**: `hsqs` (`0x73717368` little-endian) or `sqsh`
    - **CramFS**: `0x28cd3d45`
    - **JFFS2**: `0x1985`
    - **LZMA / XZ / Gzip** kernel streams
- **Actionable Workflow**:
  1. Run `re_triage` to inspect section/chunk entropy (compressed filesystems exhibit entropy $> 7.2$).
  2. Run a signature-scanning probe in `re_run_probe_script` to locate partition offsets and mount sub-partitions via `register_child`.

---

## Part 2: The 4-Tier Deterministic Degradation Matrix

### Core Principle: Truth in Advertising (R3 / R4)
When heavy external decompilers (such as Ghidra Headless `12.1.1+`, `ilspycmd`, `jadx`, or `unblob`) are not installed in the host environment—or when analyzing proprietary/modified bytecode versions—Metis Reverse **never fabricates fake C pseudocode**. Instead, it sets explicit degradation metadata and falls back deterministically through four capability tiers.

### 4-Tier Fallback Hierarchy

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Full AST Decompilation (GhidraHeadlessEngine / Native Toolchains)    │
│   • High-level C pseudocode + CFG hash + side-by-side disassembly            │
│   • decompiler_available: true, is_ast_decompiler: true                      │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ (External AST decompiler unavailable)
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ Tier 2: Structured Capstone Synthesis (NativeEngine + LIEF)                  │
│   • Basic-block disassembly, symbol/relocation resolution, call-target xref  │
│   • decompiler_available: false, decompilation_fidelity: "assembly_synthesis"│
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ (Stripped symbols / custom ABI)
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Deep Static, Crypto & Heuristic Bridge Recovery                      │
│   • S-Box/IV scanning (re_hunt_crypto_and_hashes)                            │
│   • N-API / JNI / IPC descriptor recovery (re_bridge_map)                    │
│   • Embedded SQLite / Protobuf / JSON Schema extraction (re_extract_schemas) │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ (Custom packer / opaque container)
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ Tier 4: Sandbox Python Probe & Micro-Emulation Escape Hatches                │
│   • Custom binary slicing & unpacking (re_run_probe_script + register_child) │
│   • Sandbox algorithm verification (re_verify_hypothesis)                    │
│   • Instruction-level slice execution (re_emulate_slice)                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Degradation & Diagnostic Fields Reference

Always inspect these fields in `re_query_function`, `re_decompile_function`, `re_capabilities`, and `re_triage` outputs:

| Output Field | Full AST Mode Value | Degraded / Alert Value | Operational Meaning & Required Agent Action |
| :--- | :--- | :--- | :--- |
| `decompiler_available` | `true` | `false` | Indicates whether an AST C decompiler (Ghidra) is active. When `false`, analyze the instruction stream in `disassembly` / `decompiled_code`. |
| `is_ast_decompiler` | `true` | `false` | Confirms whether output comes from an AST decompiler vs assembly synthesis. |
| `decompilation_fidelity` | `"c_pseudocode"` | `"assembly_synthesis"` | Explicitly states the representation fidelity. Report this transparently to the user. |
| `decompiler_warnings` | `[]` (omitted) | `["Non-standard register calling convention...", "Possible noreturn truncation..."]` | Alerts when `unaff_` registers or short `noreturn` bodies occur. Cross-check the `disassembly` field immediately. |
| `memory_view_unreliable` | `false` | `true` | Triggered in `re_triage` when section headers (`VirtualSize` vs `PointerToRawData`) are tampered with. Prefer `re_read_file_range` over VA reads. |
| `libraries_folded` | `{"folded": true, ...}` | `{"folded": false, ...}` | Indicates whether standard library callers/callees were collapsed to save context tokens (`R13`). |

---

### Agent Do's & Don'ts in Degraded Mode

#### Do's
1. **Check `re_capabilities` Early**: Know immediately whether Ghidra is active or if `NativeEngine` (Capstone + LIEF) is driving the session.
2. **Combine Disassembly with Sandbox Verification**: In Tier 2 (`assembly_synthesis`), read the instruction sequence (`mov`, `xor`, `ror`, `ldr`, `bl`), formulate a hypothesis, and verify it against real bytes using `re_verify_hypothesis`.
3. **Use `re_run_probe_script` for Custom Disassembly or Parsing**: Remember that `capstone` and `lief` are pre-injected inside `re_run_probe_script`, allowing you to write custom cross-reference scanners or structure parsers in seconds.
4. **Tag Evidence Honestly**: Use `status="corroborated"` when backed by sandbox execution and `status="proven"` when backed by exact `{va, rva, file_offset}` coordinates.

#### Don'ts
1. **Never Claim Assembly Synthesis is Ghidra C Output**: Always be transparent when `decompiler_available: false`.
2. **Never Retry `re_decompile_function` in a Loop Hoping for AST Output**: If `re_capabilities` reports degraded mode, pivot immediately to Tier 2/3/4 workflows.
3. **Never Guess Unresolved Register Values**: When `unaff_` warnings appear or indirect jumps occur, use `re_emulate_slice` or `re_run_probe_script` to determine concrete values.

---

## Part 3: Missing Dependency Remediation & Auto-Configuration Guide

When an Agent detects that the user's host environment is running in Degraded Mode (Tier 2/3/4) due to missing local libraries or external CLI toolchains, it should guide the user—or execute the setup steps directly with user permission—to upgrade the environment to Tier 1.

### 1. Symptom-to-Dependency Remediation Matrix

| Tool Output / Symptom | Missing Dependency | Impact When Missing | Installation Command (macOS / Linux) |
| :--- | :--- | :--- | :--- |
| `NativeEngine` unavailable (falls back to `MockEngine`) or `lief is None` in sandbox | Python `lief` package | Cannot parse PE/ELF/Mach-O headers, sections, symbols, or FatBinaries natively | `.venv/bin/pip install lief` |
| `disassembly` unavailable or `capstone is None` in sandbox | Python `capstone` package | Cannot disassemble x86/x86_64/ARM64 instructions or resolve Mach-O GOT stubs | `.venv/bin/pip install capstone` |
| `ModuleNotFoundError: No module named 'yaml'` | Python `pyyaml` package | Cannot persist `.metis_sidecars/*.yaml` files | `.venv/bin/pip install "pyyaml>=6.0"` |
| `ghidra_available: false` / `decompiler_available: false` | **Ghidra Headless** (`>= 12.1.1` or `11.3.1+`) + **JDK 21** | Falls back from AST C pseudocode (`GhidraHeadlessEngine`) to Capstone assembly synthesis (`NativeEngine`) | `brew install --cask temurin@21 ghidra` (or run `bash scripts/setup_ghidra.sh`) |
| `.NET` adapter returns `engine_status: "not_installed (graceful metadata degradation)"` | **.NET SDK** + `ilspycmd` | Only extracts CLR `BSJB` header & P/Invoke tables instead of full C# AST decompilation | `brew install --cask dotnet-sdk && dotnet tool install -g ilspycmd` |
| `JVM/Android` adapter returns `engine_status: "not_installed (graceful metadata degradation)"` | `jadx` | Only extracts DEX class descriptors & JNI bridges instead of full Java/Kotlin decompilation | `brew install jadx` (macOS) / `sudo apt install jadx` (Linux) |
| `Firmware` adapter returns `engine_status: "not_installed (graceful metadata degradation)"` | `unblob` + `libmagic` | Only scans SquashFS/U-Boot/TRX magic headers instead of recursive filesystem extraction | `brew install libmagic unblob` (macOS) / `sudo apt install libmagic1 && pipx install unblob` (Linux) |
| External signature scan needed for `re_triage(tool_feedback=...)` | `yara` | Cannot run external YARA rules prior to `re_triage` | `brew install yara` (macOS) / `sudo apt install yara` (Linux) |

---

### 2. Auto-Discovery Paths in `MetisConfig`

`MetisConfig` (`metis_reverse/config.py`) automatically configures `PATH`, `JAVA_HOME`, `DOTNET_ROOT`, and `DYLD_FALLBACK_LIBRARY_PATH` on initialization. Specifically:
1. **Ghidra**: Checks `$GHIDRA_INSTALL_DIR` first, then scans `~/.local/share/metis_env/ghidra*` for `support/analyzeHeadless`.
2. **Java 21**: Checks `~/.local/share/metis_env/jdk-21/Contents/Home/bin` and prepends it to `PATH` and `JAVA_HOME`.
3. **.NET Tools**: Checks `~/.dotnet` and `~/.dotnet/tools` (where `dotnet tool install -g ilspycmd` places `ilspycmd`) and prepends both to `PATH`.
4. **Local & Homebrew Binaries**: Prepends `~/.local/bin` and Homebrew `bin`/`lib` directories so `jadx`, `unblob`, and `libmagic.dylib` are discovered automatically even in stripped IDE/MCP subprocess environments.

---

### 3. One-Shot Environment Doctor & Setup Commands

#### A. Run Non-Destructive Environment Audit
```bash
.venv/bin/python - <<'EOF'
import shutil
from metis_reverse.config import MetisConfig
cfg = MetisConfig()
print("=== Metis Reverse Environment Audit ===")
for pkg in ("yaml", "lief", "capstone"):
    try:
        m = __import__(pkg)
        ver = getattr(m, "__version__", "loaded")
        print(f"  [OK] Python {pkg}: {ver}")
    except ImportError:
        print(f"  [MISSING] Python {pkg}")
print("  [Ghidra]", cfg.check_ghidra_version())
for tool in ("java", "ilspycmd", "jadx", "unblob", "yara"):
    path = shutil.which(tool)
    status = "OK" if path else "MISSING"
    print(f"  [{status}] CLI {tool}: {path}")
EOF
```

#### B. Bootstrap Python Virtual Environment & Core Native Engine
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]" lief capstone pyyaml
```

#### C. Wire MCP Server Configuration (`.cursor/mcp.json` or Claude Desktop)
```json
{
  "mcpServers": {
    "metis-reverse": {
      "command": "/ABSOLUTE/PATH/TO/metis-revers/.venv/bin/python",
      "args": ["-m", "metis_reverse.server"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/ABSOLUTE/PATH/TO/ghidra_PUBLIC",
        "METIS_SIDECAR_DIR": "/ABSOLUTE/PATH/TO/metis-revers/.metis_sidecars"
      }
    }
  }
}
```
After installing missing dependencies or updating `env`, restart the MCP server process and verify via `re_capabilities(session_id="...")`.
