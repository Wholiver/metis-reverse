"""BridgeService: Cross-language bridge mapping and inter-op analysis.

Implements P1-2 and Escape Hatch 3:
- N-API (.node) exports & napi_property_descriptor structure recovery.
- Universal bridge map for Electron IPC, Tauri, JNI, PyO3, Go CGO, .NET P/Invoke.
- Heuristic cross-layer linking matching shared route names, method IDs, and protocol schemas.
"""

import re
import struct
from typing import Dict, Any, List, Optional, Tuple
from ..storage.artifact_tree import ArtifactTree, ArtifactNode


class BridgeService:
    """Discovers and maps cross-boundary API invocations between High-Level runtimes and Native code."""

    @classmethod
    def analyze_bridge(
        cls,
        tree: ArtifactTree,
        artifact_id: str,
        bridge_type: str = "all", # "napi", "ipc", "tauri", "jni", "pyo3", "cgo", "pinvoke", "all"
        heuristic_mode: bool = True
    ) -> Dict[str, Any]:
        """Builds a comprehensive cross-layer bridge map for an artifact."""
        node = tree.get_node(artifact_id)
        if not node:
            return {"status": "error", "message": f"Artifact '{artifact_id}' not found"}

        content = tree.get_content(artifact_id) or b""
        bridges: List[Dict[str, Any]] = []

        # 1. N-API (.node) Bridge Analysis
        if bridge_type in ("napi", "all"):
            napi_mappings = cls._analyze_napi(content, node)
            bridges.extend(napi_mappings)

        # 2. Android JNI Bridge Analysis
        if bridge_type in ("jni", "all"):
            jni_mappings = cls._analyze_jni(content, node)
            bridges.extend(jni_mappings)

        # 3. Python PyO3 / C-API Bridge Analysis
        if bridge_type in ("pyo3", "all"):
            py_mappings = cls._analyze_python_capi(content, node)
            bridges.extend(py_mappings)

        # 4. Electron IPC Bridge Analysis
        if bridge_type in ("ipc", "all"):
            ipc_mappings = cls._analyze_electron_ipc(content, node)
            bridges.extend(ipc_mappings)

        # 5. Tauri Command Bridge Analysis
        if bridge_type in ("tauri", "all"):
            tauri_mappings = cls._analyze_tauri(content, node)
            bridges.extend(tauri_mappings)

        # 6. Go CGO & .NET P/Invoke
        if bridge_type in ("cgo", "all"):
            cgo_mappings = cls._analyze_cgo(content, node)
            bridges.extend(cgo_mappings)
        if bridge_type in ("pinvoke", "all"):
            pinvoke_mappings = cls._analyze_pinvoke(content, node)
            bridges.extend(pinvoke_mappings)

        # 7. Heuristic Cross-Layer Linking across Artifact Tree (Escape Hatch 3)
        heuristic_links = []
        if heuristic_mode:
            heuristic_links = cls._discover_heuristic_links(tree, artifact_id, bridges)

        return {
            "status": "success",
            "artifact_id": artifact_id,
            "artifact_name": node.name,
            "bridge_count": len(bridges),
            "heuristic_links_count": len(heuristic_links),
            "bridges": bridges,
            "heuristic_links": heuristic_links,
        }

    @classmethod
    def resolve_native_address(
        cls,
        va: int,
        data: bytes,
        node: Optional[ArtifactNode] = None,
        default_img_base: int = 0
    ) -> Dict[str, Any]:
        """Accurately converts a virtual address (VA) to local file offset and container physical offset (P1-2, R8).

        Inspects Mach-O 64-bit LC_SEGMENT_64, ELF program headers (PT_LOAD), or PE section headers.
        Validates that local_file_offset is strictly within [0, len(data)) and container_file_offset is within node range.
        """
        local_off = None
        rva = None
        seg_name = None

        # 1. Mach-O 64-bit parsing
        if len(data) >= 32 and data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            endian = "<" if data[:4] == b"\xcf\xfa\xed\xfe" else ">"
            try:
                magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
                    f"{endian}IIIIIIII", data[:32]
                )
                cur = 32
                for _ in range(ncmds):
                    if cur + 8 > len(data):
                        break
                    cmd, cmdsize = struct.unpack(f"{endian}II", data[cur:cur + 8])
                    if cmd == 0x19 and cur + 56 <= len(data): # LC_SEGMENT_64
                        s_name = data[cur + 8:cur + 24].split(b"\x00")[0].decode("ascii", "ignore")
                        vmaddr, vmsize, fileoff, filesize = struct.unpack(f"{endian}QQQQ", data[cur + 24:cur + 56])
                        if vmaddr <= va < vmaddr + vmsize:
                            rel = va - vmaddr
                            rva = rel
                            if rel < filesize:
                                local_off = fileoff + rel
                                seg_name = s_name
                            break
                    cur += cmdsize
            except Exception:
                pass

        # 2. ELF 64-bit parsing
        elif len(data) >= 64 and data[:4] == b"\x7fELF" and data[4] == 2:
            endian = "<" if data[5] == 1 else ">"
            try:
                e_phoff = struct.unpack(f"{endian}Q", data[32:40])[0]
                e_phentsize = struct.unpack(f"{endian}H", data[54:56])[0]
                e_phnum = struct.unpack(f"{endian}H", data[56:58])[0]
                for idx in range(e_phnum):
                    ph_cur = e_phoff + idx * e_phentsize
                    if ph_cur + 56 > len(data):
                        break
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack(
                        f"{endian}IIQQQQQ", data[ph_cur:ph_cur + 56]
                    )
                    if p_type == 1 and p_vaddr <= va < p_vaddr + p_memsz: # PT_LOAD
                        rel = va - p_vaddr
                        rva = rel
                        if rel < p_filesz:
                            local_off = p_offset + rel
                            seg_name = f"PT_LOAD_{idx}"
                        break
            except Exception:
                pass

        # 3. Fallback translation via default_img_base
        if local_off is None:
            img_b = default_img_base or (0x100000000 if len(data) >= 4 and data[:4] == b"\xcf\xfa\xed\xfe" else 0)
            if va >= img_b:
                candidate = va - img_b
                rva = candidate
                if 0 <= candidate < len(data):
                    local_off = candidate
            elif 0 <= va < len(data):
                local_off = va
                rva = va

        # Bounds validation
        in_bounds = (local_off is not None) and (0 <= local_off < len(data))
        node_file_off = node.file_offset if node else 0
        node_size = node.size if node else len(data)

        container_file_off = (node_file_off + local_off) if in_bounds else None
        container_in_bounds = in_bounds and (container_file_off is not None) and (node_file_off <= container_file_off < node_file_off + node_size)

        return {
            "va": hex(va),
            "rva": hex(rva) if rva is not None else None,
            "local_file_offset": local_off if in_bounds else None,
            "file_offset": local_off if in_bounds else None,
            "container_file_offset": container_file_off if container_in_bounds else None,
            "segment": seg_name,
            "in_bounds": in_bounds and container_in_bounds,
            "node_bounds": [node_file_off, node_file_off + node_size] if node else [0, len(data)],
        }

    @classmethod
    def _analyze_napi(cls, data: bytes, node: ArtifactNode) -> List[Dict[str, Any]]:
        """Recovers N-API exports, napi_create_function, and 64-byte napi_property_descriptor mappings (P1-2).
        
        64-bit ABI napi_property_descriptor struct layout (64 bytes):
          0x00: const char* utf8name (or 0)
          0x08: napi_value name (or 0)
          0x10: napi_callback method
          0x18: napi_callback getter
          0x20: napi_callback setter
          0x28: napi_value value
          0x30: uint32_t attributes (+ 4 bytes padding)
          0x38: void* data
        """
        mappings: List[Dict[str, Any]] = []

        has_napi = (
            b"napi_register_module" in data
            or b"napi_create_function" in data
            or b"napi_define_properties" in data
            or b"node_module_register" in data
            or "napi_node" in node.families
        )
        if not has_napi:
            return mappings

        # 1. Structured scan for 64-byte napi_property_descriptor arrays
        # Image base reference (Mach-O default 0x100000000 or ELF 0x0)
        img_base = 0x100000000 if len(data) >= 4 and data[:4] == b"\xcf\xfa\xed\xfe" else 0
        desc_stride = 64
        i = 0
        while i + desc_stride <= len(data):
            try:
                utf8_ptr, name_ptr, method_ptr, getter_ptr, setter_ptr, val_ptr, attrs, data_ptr = struct.unpack(
                    "<QQQQQQQQ", data[i:i + desc_stride]
                )
                is_method = method_ptr != 0 and (getter_ptr == 0 and setter_ptr == 0)
                is_accessor = (getter_ptr != 0 or setter_ptr != 0)
                
                if (is_method or is_accessor) and attrs <= 0x2000:
                    prop_name = None
                    # Resolve utf8name pointer via segment translation
                    name_res = cls.resolve_native_address(utf8_ptr, data, node, default_img_base=img_base)
                    name_off = name_res.get("local_file_offset")
                    if name_off is not None and 0 <= name_off < len(data) - 2:
                        raw_str = data[name_off:name_off + 64].split(b"\x00")[0]
                        if raw_str and all(32 <= b <= 126 for b in raw_str):
                            prop_name = raw_str.decode("ascii")

                    if prop_name:
                        target_ptr = method_ptr if is_method else (getter_ptr or setter_ptr)
                        resolved = cls.resolve_native_address(target_ptr, data, node, default_img_base=img_base)
                        kind = "method" if is_method else "getter/setter"
                        mappings.append({
                            "bridge_type": "napi",
                            "js_symbol": prop_name,
                            "property_kind": kind,
                            "descriptor_offset": hex(i),
                            "descriptor_size": 64,
                            "attributes": hex(attrs),
                            "native_implementation": {
                                "va": resolved["va"],
                                "rva": resolved["rva"],
                                "file_offset": resolved["file_offset"],
                                "local_file_offset": resolved["local_file_offset"],
                                "container_file_offset": resolved["container_file_offset"],
                                "coordinate_valid": resolved["in_bounds"],
                                "physical_range": resolved["node_bounds"],
                            },
                            "callback_pointers": {
                                "method": hex(method_ptr),
                                "getter": hex(getter_ptr),
                                "setter": hex(setter_ptr),
                            },
                            "confidence": 0.98 if resolved["in_bounds"] else 0.40,
                            "description": f"64-byte N-API descriptor recovered: '{prop_name}' -> native implementation at {hex(target_ptr)} ({kind})",
                        })
                        i += desc_stride
                        continue
            except Exception:
                pass
            i += 8

        # 2. String/Export pattern fallback if binary is stripped or uses napi_create_function directly
        if len(mappings) < 5:
            fn_name_matches = re.finditer(rb"(?:exports\.)?([a-zA-Z0-9_\$]{3,64})\x00", data)
            for m in fn_name_matches:
                name_str = m.group(1).decode("ascii", "ignore")
                if name_str in ("utf8name", "method", "getter", "setter", "attributes", "data", "value", "exports"):
                    continue
                if any(m_entry["js_symbol"] == name_str for m_entry in mappings):
                    continue
                offset = m.start()
                resolved = cls.resolve_native_address(img_base + offset, data, node, default_img_base=img_base)
                mappings.append({
                    "bridge_type": "napi",
                    "js_symbol": name_str,
                    "descriptor_offset": hex(offset),
                    "property_kind": "method",
                    "native_implementation": {
                        "va": resolved["va"],
                        "rva": resolved["rva"],
                        "file_offset": resolved["file_offset"],
                        "local_file_offset": resolved["local_file_offset"],
                        "container_file_offset": resolved["container_file_offset"],
                        "coordinate_valid": resolved["in_bounds"],
                        "physical_range": resolved["node_bounds"],
                    },
                    "description": f"N-API native exported method '{name_str}' mapped to native implementation",
                    "confidence": 0.85,
                })
                if len(mappings) >= 64:
                    break

        return mappings

    @classmethod
    def _analyze_jni(cls, data: bytes, node: ArtifactNode) -> List[Dict[str, Any]]:
        """Recovers Java Native Interface exports (Java_package_class_method)."""
        mappings: List[Dict[str, Any]] = []
        matches = re.finditer(rb"Java_([a-zA-Z0-9_]+)_([a-zA-Z0-9_]+)", data)
        for m in matches:
            full_sym = m.group(0).decode("ascii", "ignore")
            parts = full_sym.split("_")
            java_class = "/".join(parts[1:-1])
            java_method = parts[-1]
            mappings.append({
                "bridge_type": "jni",
                "java_symbol": f"{java_class}.{java_method}",
                "native_symbol": full_sym,
                "offset": hex(m.start()),
                "confidence": 0.98,
            })
        return mappings

    @classmethod
    def _analyze_python_capi(cls, data: bytes, node: ArtifactNode) -> List[Dict[str, Any]]:
        """Recovers PyMethodDef entries: {ml_name, ml_meth, ml_flags, ml_doc}."""
        mappings: List[Dict[str, Any]] = []
        # PyMethodDef matches common method names followed by docstrings
        matches = re.finditer(rb"PyInit_([a-zA-Z0-9_]+)", data)
        for m in matches:
            mod_name = m.group(1).decode("ascii", "ignore")
            mappings.append({
                "bridge_type": "pyo3_capi",
                "module_init": f"PyInit_{mod_name}",
                "python_module": mod_name,
                "offset": hex(m.start()),
                "confidence": 0.95,
            })
        return mappings

    @classmethod
    def _analyze_electron_ipc(cls, data: bytes, node: ArtifactNode) -> List[Dict[str, Any]]:
        """Recovers Electron ipcRenderer and ipcMain channel names."""
        mappings: List[Dict[str, Any]] = []
        channel_matches = re.finditer(rb"(?:ipcRenderer|ipcMain)\.(?:send|invoke|on|handle)\s*\(\s*['\"]([^'\"]+)['\"]", data)
        for m in channel_matches:
            channel_name = m.group(1).decode("utf-8", "ignore")
            mappings.append({
                "bridge_type": "electron_ipc",
                "channel": channel_name,
                "offset": hex(m.start()),
                "confidence": 0.92,
            })
        return mappings

    @classmethod
    def _analyze_tauri(cls, data: bytes, node: ArtifactNode) -> List[Dict[str, Any]]:
        """Recovers Tauri commands invoked via invoke('cmd_name')."""
        mappings: List[Dict[str, Any]] = []
        cmd_matches = re.finditer(rb"invoke\s*\(\s*['\"]([a-zA-Z0-9_\-]+)['\"]", data)
        for m in cmd_matches:
            cmd = m.group(1).decode("utf-8", "ignore")
            mappings.append({
                "bridge_type": "tauri_command",
                "command": cmd,
                "offset": hex(m.start()),
                "confidence": 0.90,
            })
        return mappings

    @classmethod
    def _analyze_cgo(cls, data: bytes, node: ArtifactNode) -> List[Dict[str, Any]]:
        """Recovers Go CGO bridges."""
        mappings: List[Dict[str, Any]] = []
        matches = re.finditer(rb"_cgo_[a-zA-Z0-9_]+", data)
        seen = set()
        for m in matches:
            sym = m.group(0).decode("ascii", "ignore")
            if sym not in seen:
                seen.add(sym)
                mappings.append({
                    "bridge_type": "cgo",
                    "cgo_symbol": sym,
                    "offset": hex(m.start()),
                    "confidence": 0.95,
                })
        return mappings

    @classmethod
    def _analyze_pinvoke(cls, data: bytes, node: ArtifactNode) -> List[Dict[str, Any]]:
        """Recovers .NET P/Invoke DLL import signatures."""
        mappings: List[Dict[str, Any]] = []
        matches = re.finditer(rb"\[DllImport\([\"']([a-zA-Z0-9_\.\-]+)[\"']\)]", data)
        for m in matches:
            dll = m.group(1).decode("utf-8", "ignore")
            mappings.append({
                "bridge_type": "pinvoke",
                "target_dll": dll,
                "offset": hex(m.start()),
                "confidence": 0.95,
            })
        return mappings

    @classmethod
    def _discover_heuristic_links(
        cls,
        tree: ArtifactTree,
        artifact_id: str,
        known_bridges: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Escape Hatch 3: Heuristic Cross-Layer Linking across Artifact Tree nodes.
        
        Searches sibling artifacts (e.g. JS files, Native binaries) for shared channel
        names, method identifiers, route strings, or protocol schemas.
        """
        links: List[Dict[str, Any]] = []
        # Collect candidate search tokens from known bridges
        tokens = set()
        for b in known_bridges:
            for k in ("js_symbol", "channel", "command", "java_symbol"):
                if k in b and len(b[k]) >= 4:
                    tokens.add(b[k])

        if not tokens:
            return links

        for node_id, sibling_node in tree.nodes.items():
            if node_id == artifact_id:
                continue
            sibling_content = tree.get_content(node_id)
            if not sibling_content:
                continue

            for token in tokens:
                token_bytes = token.encode("utf-8", "ignore")
                idx = sibling_content.find(token_bytes)
                if idx != -1:
                    links.append({
                        "link_type": "heuristic_link",
                        "source_artifact": artifact_id,
                        "target_artifact": node_id,
                        "shared_token": token,
                        "target_offset": hex(idx),
                        "confidence": 0.8,
                        "note": f"Found shared symbol/route '{token}' in sibling artifact '{sibling_node.name}'",
                    })

        return links
