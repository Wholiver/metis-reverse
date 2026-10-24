"""ContainerExtractor: Structured and heuristic artifact extraction for Metis Reverse.

Implements P0-2:
- Level 1: Structured container parsing (Bun StandaloneModuleGraph, Mach-O, PE, ELF, asar, zip/PyInstaller).
- Level 2: Heuristic magic scanning with bounded header validation (preventing DoS per R6).
- Level 3: Dynamic registration hooks for custom sandbox probe scripts.
"""

import struct
import io
import re
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from ..storage.artifact_tree import ArtifactNode, ArtifactTree


class ContainerExtractor:
    """Discovers, parses, and extracts embedded artifacts across software types."""

    BUN_SIGNATURE = b"\n---- Bun! ----\n"
    BUN_ALT_SIGNATURE = b"---- Bun! ----"

    @classmethod
    def extract_bun_standalone(cls, data: bytes, parent_node: ArtifactNode, tree: ArtifactTree) -> List[ArtifactNode]:
        """Parses Bun StandaloneModuleGraph and extracts embedded JS, assets, and .node modules.
        
        Bun stores embedded files in its standalone bundle trailer or __BUN section.
        Format typically contains:
        - '$bunfs/root/...' file paths
        - Bundled JS modules
        - Embedded .node Mach-O / ELF shared libraries
        - Trailing '---- Bun! ----' marker with module table offsets
        """
        extracted_nodes: List[ArtifactNode] = []
        
        # 1. Look for Bun signature
        marker_idx = data.rfind(cls.BUN_ALT_SIGNATURE)
        if marker_idx == -1 and b"__BUN" not in data and b"$bunfs" not in data:
            return extracted_nodes

        # 2. Extract modules by searching for Bun filesystem paths or boundaries
        # Pattern: matches paths like /$bunfs/root/app.js or node_modules/foo/index.node
        path_matches = list(re.finditer(rb"(?:/|\$bunfs/root/|[a-zA-Z0-9_\-\./]+)\.([a-zA-Z0-9_\-]+)", data))
        
        # 3. Detect embedded Mach-O / ELF native .node modules inside the data
        native_slices = cls.scan_heuristic_magics(data, offset_delta=parent_node.file_offset)
        for n_meta in native_slices:
            # Check if this slice is likely a .node native module
            slice_off = n_meta["offset"] - parent_node.file_offset
            pre_window = data[max(0, slice_off - 512):slice_off]
            node_name_match = re.search(rb"([a-zA-Z0-9_\-]+\.node)", pre_window)
            if not node_name_match:
                # Also check within first 2048 bytes of the module slice for install name or dylib ID
                node_name_match = re.search(rb"([a-zA-Z0-9_\-]+\.node)", n_meta["content"][:2048])
            
            node_name = node_name_match.group(1).decode("utf-8", "ignore") if node_name_match else f"embedded_native_{len(extracted_nodes)}.{n_meta.get('suggested_ext', 'node')}"
            
            sub_id = f"{parent_node.id}:node:{len(extracted_nodes)}"
            child = ArtifactNode(
                id=sub_id,
                parent_id=parent_node.id,
                name=node_name,
                file_offset=n_meta["offset"],
                size=n_meta["size"],
                sha256=hashlib.sha256(n_meta["content"]).hexdigest(),
                families=["native", n_meta.get("format", "unknown"), "napi_node"],
                custom_metadata={"extracted_by": "bun_standalone_extractor", "magic": n_meta.get("magic"), "module_name": node_name},
            )
            tree.add_node(child, content=n_meta["content"])
            extracted_nodes.append(child)

        # 4. Extract embedded JS modules and assets
        # Bun prefixes modules with: //$bunfs/root/path or // @bun\n
        bun_js_matches = list(re.finditer(rb"(?:/\$bunfs/root/|//\s*@bun)[\s\S]*?(?=(?:/\$bunfs/root/|---- Bun! ----|$))", data))
        if bun_js_matches:
            for i, m in enumerate(bun_js_matches):
                chunk = m.group(0)
                if len(chunk) < 10:
                    continue
                # Extract clean module name from header
                name_m = re.search(rb"(?:/\$bunfs/root/|//\s*)([a-zA-Z0-9_\-\./]+\.(?:js|ts|jsx|tsx|json))", chunk)
                mod_name = name_m.group(1).decode("utf-8", "ignore") if name_m else f"module_{i}.js"

                sub_id = f"{parent_node.id}:js:{i}"
                child = ArtifactNode(
                    id=sub_id,
                    parent_id=parent_node.id,
                    name=mod_name,
                    file_offset=parent_node.file_offset + m.start(),
                    size=len(chunk),
                    sha256=hashlib.sha256(chunk).hexdigest(),
                    families=["javascript", "bundled_js", "bun_module"],
                    custom_metadata={"module_path": mod_name},
                )
                tree.add_node(child, content=chunk)
                extracted_nodes.append(child)

        return extracted_nodes

    @classmethod
    def scan_heuristic_magics(cls, data: bytes, offset_delta: int = 0) -> List[Dict[str, Any]]:
        """Level 2: Scans for binary and container magics with strict header bounds validation (R6)."""
        findings: List[Dict[str, Any]] = []
        length = len(data)

        # Magics:
        # ELF: 7f 45 4c 46
        # Mach-O 64-bit LE: cf fa ed fe
        # Mach-O 64-bit BE: fe ed fa cf
        # Mach-O Fat: ca fe ba be
        # PE / MZ: 4d 5a ('MZ')
        # Zip / Jar / Asar: 50 4b 03 04 ('PK\x03\x04')
        
        i = 0
        while i <= length - 16:
            # 1. ELF Magic
            if data[i:i+4] == b"\x7fELF" and i > 0: # skip root header if at 0
                if i + 64 <= length:
                    ei_class = data[i+4]
                    if ei_class in (1, 2): # 32-bit or 64-bit
                        # Extract size from ELF header section header / program header bounds
                        try:
                            if ei_class == 2 and i + 64 <= length:
                                e_shoff = struct.unpack("<Q", data[i+40:i+48])[0]
                                e_shentsize = struct.unpack("<H", data[i+58:i+60])[0]
                                e_shnum = struct.unpack("<H", data[i+60:i+62])[0]
                                est_size = e_shoff + (e_shentsize * e_shnum)
                                if 64 <= est_size <= (length - i):
                                    findings.append({
                                        "offset": offset_delta + i,
                                        "size": est_size,
                                        "format": "elf",
                                        "magic": "ELF",
                                        "suggested_ext": "so",
                                        "content": data[i:i+est_size],
                                    })
                                    i += max(est_size, 16)
                                    continue
                        except Exception:
                            pass

            # 2. Mach-O 64-bit Little Endian (ARM64 / x86_64)
            elif data[i:i+4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") and i > 0:
                if i + 32 <= length:
                    try:
                        is_le = data[i:i+4] == b"\xcf\xfa\xed\xfe"
                        endian = "<" if is_le else ">"
                        ncmds = struct.unpack(f"{endian}I", data[i+16:i+20])[0]
                        sizeofcmds = struct.unpack(f"{endian}I", data[i+20:i+24])[0]
                        # Bounds check to avoid DoS (R6)
                        if 1 <= ncmds <= 500 and 16 <= sizeofcmds <= (length - i - 32):
                            # Walk load commands to estimate full Mach-O filesize
                            total_size = 32 + sizeofcmds
                            cur_cmd_off = i + 32
                            for _ in range(min(ncmds, 100)):
                                if cur_cmd_off + 8 > length:
                                    break
                                cmd, cmdsize = struct.unpack(f"{endian}II", data[cur_cmd_off:cur_cmd_off+8])
                                if cmdsize < 8:
                                    break
                                # LC_SEGMENT_64 == 0x19
                                if cmd == 0x19 and cur_cmd_off + 72 <= length:
                                    seg_fileoff = struct.unpack(f"{endian}Q", data[cur_cmd_off+40:cur_cmd_off+48])[0]
                                    seg_filesize = struct.unpack(f"{endian}Q", data[cur_cmd_off+48:cur_cmd_off+56])[0]
                                    if seg_fileoff + seg_filesize > total_size:
                                        total_size = seg_fileoff + seg_filesize
                                cur_cmd_off += cmdsize
                            
                            if 32 < total_size <= (length - i):
                                findings.append({
                                    "offset": offset_delta + i,
                                    "size": total_size,
                                    "format": "macho",
                                    "magic": "Mach-O",
                                    "suggested_ext": "dylib",
                                    "content": data[i:i+total_size],
                                })
                                i += max(total_size, 16)
                                continue
                    except Exception:
                        pass

            # 3. PE (MZ)
            elif data[i:i+2] == b"MZ" and i > 0:
                if i + 0x40 <= length:
                    try:
                        e_lfanew = struct.unpack("<I", data[i+0x3c:i+0x40])[0]
                        if 0x40 <= e_lfanew <= 0x1000 and i + e_lfanew + 4 <= length:
                            if data[i+e_lfanew:i+e_lfanew+4] == b"PE\x00\x00":
                                # Safe estimate
                                est_size = 4096
                                findings.append({
                                    "offset": offset_delta + i,
                                    "size": est_size,
                                    "format": "pe",
                                    "magic": "PE/COFF",
                                    "suggested_ext": "dll",
                                    "content": data[i:i+est_size],
                                })
                                i += max(est_size, 16)
                                continue
                    except Exception:
                        pass

            # 4. Zip container
            elif data[i:i+4] == b"PK\x03\x04" and i > 0:
                # Find end of central directory
                eocd = data.find(b"PK\x05\x06", i)
                if eocd != -1 and (eocd + 22 - i) <= (length - i):
                    zip_size = eocd + 22 - i
                    findings.append({
                        "offset": offset_delta + i,
                        "size": zip_size,
                        "format": "zip",
                        "magic": "ZIP",
                        "suggested_ext": "zip",
                        "content": data[i:i+zip_size],
                    })
                    i += max(zip_size, 16)
                    continue

            i += 4

        return findings

    @classmethod
    def register_custom_child_artifact(
        cls,
        tree: ArtifactTree,
        parent_id: str,
        offset: int,
        length: int,
        content: bytes,
        name: str = "",
        description: str = "",
        families: Optional[List[str]] = None,
    ) -> ArtifactNode:
        """Level 3: Dynamic child artifact registration via sandbox scripts (P0-2, Escape Hatch 1)."""
        parent = tree.get_node(parent_id)
        if not parent:
            raise KeyError(f"Parent artifact '{parent_id}' not found in artifact tree")

        actual_size = len(content) if content else length
        if actual_size > 4 * 1024 * 1024 * 1024:
            raise ValueError(f"Artifact size ({actual_size} bytes) exceeds safety limit of 4GB (R6 DoS protection)")

        if name and (".." in name or "/" in name or "\\" in name):
            raise ValueError("Artifact name cannot contain directory traversal characters ('..', '/', '\\')")

        node_id = f"{parent_id}:custom:{len(parent.children)}"
        node = ArtifactNode(
            id=node_id,
            parent_id=parent_id,
            name=name or f"artifact_{node_id}",
            file_offset=offset,
            size=actual_size,
            sha256=hashlib.sha256(content).hexdigest() if content else "",
            families=families or ["custom_payload", "script_extracted"],
            custom_metadata={
                "description": description,
                "registered_dynamically": True,
                "parent_offset": offset,
                "parent_length": length,
            },
        )
        tree.add_node(node, content=content)
        return node

    @classmethod
    def extract_directory_bundle(cls, dir_path: Path, root_node: ArtifactNode, tree: ArtifactTree) -> List[ArtifactNode]:
        """Scans macOS .app bundles, frameworks, and installation directories, building the child artifact tree."""
        extracted: List[ArtifactNode] = []
        if not dir_path.is_dir():
            return extracted

        # Check for macOS .app or bundle structure
        info_plist_path = None
        for cand in [dir_path / "Contents" / "Info.plist", dir_path / "Info.plist"]:
            if cand.is_file():
                info_plist_path = cand
                break

        parsed_plist: Dict[str, Any] = {}
        main_exec_name = None
        if info_plist_path:
            try:
                plist_data = info_plist_path.read_bytes()
                import plistlib
                parsed_plist = plistlib.loads(plist_data)
                main_exec_name = parsed_plist.get("CFBundleExecutable")
                root_node.custom_metadata["parsed_plist"] = parsed_plist
                plist_node = ArtifactNode(
                    id=f"{root_node.id}:info_plist",
                    parent_id=root_node.id,
                    name=info_plist_path.name,
                    file_path=str(info_plist_path.absolute()),
                    size=len(plist_data),
                    sha256=hashlib.sha256(plist_data).hexdigest(),
                    families=["plist", "bplist" if plist_data.startswith(b"bplist00") else "xml_plist", "metadata"],
                    custom_metadata={"parsed_plist": parsed_plist},
                )
                tree.add_node(plist_node, content=plist_data)
                extracted.append(plist_node)
            except Exception:
                pass

        # Identify main executable
        if main_exec_name:
            exec_cand = dir_path / "Contents" / "MacOS" / main_exec_name
            if not exec_cand.is_file():
                exec_cand = dir_path / main_exec_name
            if exec_cand.is_file():
                st = exec_cand.stat()
                hdr = exec_cand.read_bytes()[:4096] if st.st_size > 0 else b""
                from .polyglot_detector import PolyglotDetector
                labels = PolyglotDetector.detect_labels(hdr)
                exec_node = ArtifactNode(
                    id=f"{root_node.id}:main_exec",
                    parent_id=root_node.id,
                    name=main_exec_name,
                    file_path=str(exec_cand.absolute()),
                    size=st.st_size,
                    families=["main_executable", "native"] + [l["name"].lower() for l in labels],
                    capabilities=PolyglotDetector.get_capabilities(labels),
                    is_activated=True,
                    custom_metadata={"is_main_executable": True},
                )
                tree.add_node(exec_node)
                extracted.append(exec_node)

        # Recursively search for significant files:
        # Dynamic libraries, frameworks, native modules, app.asar, databases
        count = 0
        for p in dir_path.rglob("*"):
            if not p.is_file() or count >= 200:
                continue
            if info_plist_path and p.resolve() == info_plist_path.resolve():
                continue
            if main_exec_name and p.name == main_exec_name:
                continue

            rel_str = str(p.relative_to(dir_path))
            lower_name = p.name.lower()
            families = []

            if lower_name.endswith((".dylib", ".so", ".dll")):
                families = ["dynamic_library", "native"]
            elif lower_name.endswith(".node"):
                families = ["napi_node", "native"]
            elif lower_name == "app.asar":
                families = ["electron_asar", "container"]
            elif lower_name.endswith((".sqlite", ".sqlite3", ".db")):
                families = ["sqlite", "database"]
            elif lower_name == "assets.car":
                families = ["car_archive", "assets"]
            elif lower_name.endswith((".class", ".jar")):
                families = ["jvm", "bytecode"]
            elif lower_name.endswith(".wasm"):
                families = ["wasm", "bytecode"]
            elif lower_name.endswith(".pyc"):
                families = ["python", "bytecode"]
            elif lower_name.endswith(".hbc"):
                families = ["hermes", "bytecode"]
            elif lower_name in ("package.json", "manifest.json", "cargo.toml"):
                families = ["manifest", "configuration"]

            if families:
                st = p.stat()
                node_id = f"{root_node.id}:item:{count}"
                child = ArtifactNode(
                    id=node_id,
                    parent_id=root_node.id,
                    name=p.name,
                    file_path=str(p.absolute()),
                    size=st.st_size,
                    families=families,
                    custom_metadata={"relative_path": rel_str},
                )
                tree.add_node(child)
                extracted.append(child)
                count += 1

        return extracted

    @classmethod
    def extract_archive_container(cls, archive_path: Path, root_node: ArtifactNode, tree: ArtifactTree) -> List[ArtifactNode]:
        """Enumerates archive containers (.zip, .vsix, .crx, .ipa, .jar, .whl) safely per R6."""
        import zipfile
        import io

        extracted: List[ArtifactNode] = []
        if not archive_path.is_file():
            return extracted

        is_crx = False
        crx_zip_offset = 0

        # Check for CRX2 / CRX3
        try:
            with open(archive_path, "rb") as f:
                magic = f.read(4)
                if magic == b"Cr24":
                    is_crx = True
                    ver = struct.unpack("<I", f.read(4))[0]
                    if ver == 2:
                        pubkey_len = struct.unpack("<I", f.read(4))[0]
                        sig_len = struct.unpack("<I", f.read(4))[0]
                        crx_zip_offset = 16 + pubkey_len + sig_len
                    elif ver == 3:
                        header_len = struct.unpack("<I", f.read(4))[0]
                        crx_zip_offset = 12 + header_len
        except Exception:
            pass

        try:
            if is_crx and crx_zip_offset > 0:
                with open(archive_path, "rb") as f:
                    f.seek(crx_zip_offset)
                    zip_bytes = f.read()
                zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
            else:
                zf = zipfile.ZipFile(archive_path)

            file_size = archive_path.stat().st_size
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            ratio = (total_uncompressed / max(1, file_size))
            if ratio > 100 and total_uncompressed > 50 * 1024 * 1024:
                raise ValueError(f"Zip bomb detected: expansion ratio {ratio:.1f}x exceeds safety threshold of 100x")

            count = 0
            for info in zf.infolist():
                if info.is_dir() or count >= 150:
                    continue
                name = Path(info.filename).name
                lower = info.filename.lower()
                families = []
                if "manifest.json" in lower or "package.json" in lower or "manifest.mf" in lower:
                    families = ["manifest", "configuration"]
                elif lower.endswith((".dylib", ".so", ".dll", ".node")):
                    families = ["dynamic_library", "native"]
                elif lower.endswith(".class"):
                    families = ["jvm", "bytecode"]
                elif lower.endswith(".js"):
                    families = ["javascript"]
                elif "boot-inf/classes" in lower:
                    families = ["spring_boot", "jvm"]

                if families or count < 20:
                    child = ArtifactNode(
                        id=f"{root_node.id}:entry:{count}",
                        parent_id=root_node.id,
                        name=name or info.filename,
                        size=info.file_size,
                        families=families or ["archive_entry"],
                        custom_metadata={"archive_path": info.filename, "compressed_size": info.compress_size},
                    )
                    if info.file_size < 65536:
                        try:
                            content = zf.read(info.filename)
                            tree.add_node(child, content=content)
                        except Exception:
                            tree.add_node(child)
                    else:
                        tree.add_node(child)
                    extracted.append(child)
                    count += 1
        except Exception:
            pass

        return extracted
