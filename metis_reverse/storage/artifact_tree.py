"""Artifact Tree data models and registry for Metis Reverse.

Implements P0-2, P0-3, and R8:
- Hierarchical multi-family artifact nodes (native, bytecode, packed JS, child libs).
- Lazy activation to prevent context explosion on large archive sets.
- Universal object identification and cross-tree search.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import hashlib
import datetime
from pathlib import Path


@dataclass
class ArtifactNode:
    """A node in the Artifact Tree representing a file, segment, or derived sub-artifact."""
    id: str                                # Unique identifier, e.g. "root", "root:node:0", "root:bun:my_app"
    parent_id: Optional[str] = None        # Parent artifact ID, None if root
    name: str = ""                         # Human-readable name
    file_path: Optional[str] = None        # Absolute or relative disk path if backed by file
    file_offset: int = 0                   # Offset within the parent container / file
    size: int = 0                          # Size in bytes
    sha256: str = ""                       # SHA-256 of artifact content
    families: List[str] = field(default_factory=list) # e.g. ["macho", "arm64", "bun", "javascript"]
    triage: Dict[str, Any] = field(default_factory=dict) # L0 triage metadata
    capabilities: Dict[str, Any] = field(default_factory=dict) # R3 capability declaration
    children: List[str] = field(default_factory=list) # IDs of child artifacts
    is_activated: bool = False             # Whether deep analysis / L1 is activated
    custom_metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ArtifactTree:
    """Manages the hierarchical tree of artifacts with lazy activation and global search."""

    def __init__(self, root_id: str = "root"):
        self.root_id = root_id
        self.nodes: Dict[str, ArtifactNode] = {}
        self._content_cache: Dict[str, bytes] = {}

    def add_node(self, node: ArtifactNode, content: Optional[bytes] = None) -> ArtifactNode:
        """Adds a node to the tree and links it to its parent if present."""
        self.nodes[node.id] = node
        if content is not None:
            self._content_cache[node.id] = content
            if not node.sha256:
                node.sha256 = hashlib.sha256(content).hexdigest()
            if not node.size:
                node.size = len(content)

        if node.parent_id and node.parent_id in self.nodes:
            parent = self.nodes[node.parent_id]
            if node.id not in parent.children:
                parent.children.append(node.id)

        return node

    def get_node(self, artifact_id: str) -> Optional[ArtifactNode]:
        """Retrieves a node by its ID."""
        return self.nodes.get(artifact_id)

    def get_content(self, artifact_id: str, max_size: Optional[int] = None) -> Optional[bytes]:
        """Retrieves raw content for an artifact node."""
        if artifact_id in self._content_cache:
            return self._content_cache[artifact_id]

        node = self.nodes.get(artifact_id)
        if not node:
            return None

        # If backed by a standalone file
        if node.file_path and Path(node.file_path).is_file():
            try:
                read_sz = node.size
                if max_size is not None and (read_sz <= 0 or read_sz > max_size):
                    read_sz = max_size
                with open(node.file_path, "rb") as f:
                    f.seek(node.file_offset)
                    data = f.read(read_sz) if read_sz > 0 else f.read()
                return data
            except Exception:
                return None

        # If slice of parent
        if node.parent_id:
            parent_bytes = self.get_content(node.parent_id, max_size=max_size)
            if parent_bytes is not None:
                start = node.file_offset
                end = start + node.size if node.size > 0 else len(parent_bytes)
                return parent_bytes[start:end]

        return None

    def read_range(self, artifact_id: str, offset: int, length: int) -> bytes:
        """Reads a byte slice [offset:offset+length] from an artifact on demand (P0-1, streaming)."""
        if length <= 0 or offset < 0:
            return b""

        node = self.nodes.get(artifact_id)
        if not node:
            return b""

        if node.size > 0:
            if offset >= node.size:
                return b""
            length = min(length, node.size - offset)

        if artifact_id in self._content_cache:
            cache = self._content_cache[artifact_id]
            return cache[offset:offset + length]

        if node.file_path and Path(node.file_path).is_file():
            try:
                with open(node.file_path, "rb") as f:
                    f.seek(node.file_offset + offset)
                    return f.read(length)
            except Exception:
                return b""

        if node.parent_id:
            return self.read_range(node.parent_id, node.file_offset + offset, length)

        return b""

    def activate_node(self, artifact_id: str) -> bool:
        """Activates a node on demand (P0-3 lazy activation)."""
        node = self.nodes.get(artifact_id)
        if not node:
            return False
        node.is_activated = True
        return True

    def list_nodes(self, parent_id: Optional[str] = None, cursor: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Lists artifact nodes with cursor pagination (R2)."""
        all_nodes = [
            n for n in self.nodes.values()
            if parent_id is None or n.parent_id == parent_id
        ]
        total = len(all_nodes)
        paged = all_nodes[cursor:cursor + limit]
        next_cursor = (cursor + limit) if (cursor + limit < total) else None

        return {
            "total": total,
            "cursor": cursor,
            "limit": limit,
            "truncated": next_cursor is not None,
            "next_cursor": next_cursor,
            "artifacts": [n.to_dict() for n in paged],
        }

    def search_tree(
        self,
        query: str,
        search_type: str = "all", # "string", "constant", "bytes_hex", "all"
        cursor: int = 0,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Global search across the entire artifact tree for strings, constants, or bytes (P0-3)."""
        results: List[Dict[str, Any]] = []
        query_bytes = query.encode("utf-8", errors="ignore")
        hex_target = None
        if search_type in ("bytes_hex", "all"):
            try:
                clean_hex = query.replace(" ", "").replace("0x", "")
                if len(clean_hex) % 2 == 0 and len(clean_hex) >= 2:
                    hex_target = bytes.fromhex(clean_hex)
            except Exception:
                hex_target = None

        for art_id, node in self.nodes.items():
            # If large file backed on disk (>10MB), stream chunks to avoid memory spikes
            if node.file_path and Path(node.file_path).is_file() and node.size > 10 * 1024 * 1024 and art_id not in self._content_cache:
                chunk_size = 1024 * 1024  # 1MB chunk
                overlap = max(len(query_bytes), 32)
                try:
                    with open(node.file_path, "rb") as f:
                        f.seek(node.file_offset)
                        bytes_left = node.size
                        stream_offset = 0
                        prev_tail = b""
                        while bytes_left > 0 and len(results) < 500:
                            read_len = min(chunk_size, bytes_left)
                            buf = f.read(read_len)
                            if not buf:
                                break
                            combined = prev_tail + buf
                            block_start = stream_offset - len(prev_tail)

                            # String search
                            if search_type in ("string", "all") and query_bytes in combined:
                                c_idx = 0
                                while True:
                                    c_idx = combined.find(query_bytes, c_idx)
                                    if c_idx == -1 or len(results) >= 500:
                                        break
                                    abs_off = block_start + c_idx
                                    if 0 <= abs_off < node.size:
                                        ctx_start = max(0, c_idx - 16)
                                        ctx_end = min(len(combined), c_idx + len(query_bytes) + 16)
                                        results.append({
                                            "artifact_id": art_id,
                                            "artifact_name": node.name,
                                            "match_type": "string",
                                            "offset": abs_off,
                                            "match_text": query,
                                            "snippet_hex": combined[ctx_start:ctx_end].hex(),
                                        })
                                    c_idx += 1

                            # Hex target search
                            if hex_target and hex_target in combined:
                                h_idx = 0
                                while True:
                                    h_idx = combined.find(hex_target, h_idx)
                                    if h_idx == -1 or len(results) >= 500:
                                        break
                                    abs_off = block_start + h_idx
                                    if 0 <= abs_off < node.size:
                                        results.append({
                                            "artifact_id": art_id,
                                            "artifact_name": node.name,
                                            "match_type": "bytes_hex",
                                            "offset": abs_off,
                                            "match_hex": hex_target.hex(),
                                        })
                                    h_idx += 1

                            prev_tail = combined[-overlap:] if len(combined) >= overlap else combined
                            stream_offset += read_len
                            bytes_left -= read_len
                except Exception:
                    pass
                continue

            content = self.get_content(art_id)
            if not content:
                continue

            # String search
            if search_type in ("string", "all") and query_bytes in content:
                idx = 0
                while True:
                    idx = content.find(query_bytes, idx)
                    if idx == -1 or len(results) >= 500:
                        break
                    # Context snippet
                    ctx_start = max(0, idx - 16)
                    ctx_end = min(len(content), idx + len(query_bytes) + 16)
                    results.append({
                        "artifact_id": art_id,
                        "artifact_name": node.name,
                        "match_type": "string",
                        "offset": idx,
                        "match_text": query,
                        "snippet_hex": content[ctx_start:ctx_end].hex(),
                    })
                    idx += 1

            # Hex target search
            if hex_target and hex_target in content:
                idx = 0
                while True:
                    idx = content.find(hex_target, idx)
                    if idx == -1 or len(results) >= 500:
                        break
                    results.append({
                        "artifact_id": art_id,
                        "artifact_name": node.name,
                        "match_type": "bytes_hex",
                        "offset": idx,
                        "match_hex": hex_target.hex(),
                    })
                    idx += 1

        total = len(results)
        paged = results[cursor:cursor + limit]
        next_cursor = (cursor + limit) if (cursor + limit < total) else None

        return {
            "query": query,
            "total": total,
            "cursor": cursor,
            "limit": limit,
            "truncated": next_cursor is not None,
            "next_cursor": next_cursor,
            "matches": paged,
        }

    def summary_report(self) -> Dict[str, Any]:
        """Produces a holistic tree summary report."""
        family_counts: Dict[str, int] = {}
        for n in self.nodes.values():
            for f in n.families:
                family_counts[f] = family_counts.get(f, 0) + 1

        return {
            "root_id": self.root_id,
            "total_artifacts": len(self.nodes),
            "families_distribution": family_counts,
            "artifacts_overview": [
                {
                    "id": n.id,
                    "name": n.name,
                    "parent_id": n.parent_id,
                    "file_offset": n.file_offset,
                    "size": n.size,
                    "sha256": n.sha256,
                    "families": n.families,
                    "is_activated": n.is_activated,
                }
                for n in self.nodes.values()
            ],
        }

    @classmethod
    def build_tree_from_path(cls, path_str: str) -> 'ArtifactTree':
        """Builds a complete Artifact Tree from a directory (.app / bundle), archive (.vsix / .crx / .jar), or file."""
        from ..services.container_extractor import ContainerExtractor
        from ..services.polyglot_detector import PolyglotDetector
        p = Path(path_str).resolve()
        tree = cls(root_id="root")

        if p.is_dir():
            # Check if macOS .app bundle
            is_app = p.name.endswith(".app") or (p / "Contents" / "Info.plist").is_file() or (p / "Info.plist").is_file()
            families = ["macos_app", "bundle", "directory"] if is_app else ["directory_bundle", "filesystem"]
            root_node = ArtifactNode(
                id="root",
                name=p.name,
                file_path=str(p),
                families=families,
                is_activated=True,
            )
            tree.add_node(root_node)
            ContainerExtractor.extract_directory_bundle(p, root_node, tree)
            return tree

        if p.is_file():
            size = p.stat().st_size
            with open(p, "rb") as f:
                header = f.read(65536)

            # Stream SHA256 in 64KB chunks (never load full big file into memory)
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            sha = h.hexdigest()

            labels = PolyglotDetector.detect_labels(header)
            caps = PolyglotDetector.get_capabilities(labels)
            families = [l["name"].lower() for l in labels]

            root_node = ArtifactNode(
                id="root",
                name=p.name,
                file_path=str(p),
                file_offset=0,
                size=size,
                sha256=sha,
                families=families,
                capabilities=caps,
                is_activated=True,
            )
            content = None
            if size <= 10 * 1024 * 1024:
                with open(p, "rb") as f:
                    content = f.read()
                tree.add_node(root_node, content=content)
            else:
                tree.add_node(root_node)

            archive_exts = (".zip", ".jar", ".war", ".vsix", ".crx", ".xpi", ".whl", ".ipa")
            if p.name.lower().endswith(archive_exts) or header.startswith(b"PK\x03\x04") or header.startswith(b"Cr24"):
                ContainerExtractor.extract_archive_container(p, root_node, tree)
            elif any(f in ("bun", "javascript") for f in families) or b"---- Bun! ----" in header or (content and b"---- Bun! ----" in content):
                bun_data = content if content is not None else p.read_bytes()
                ContainerExtractor.extract_bun_standalone(bun_data, root_node, tree)

            return tree

        root_node = ArtifactNode(id="root", name=p.name, file_path=str(p))
        tree.add_node(root_node)
        return tree
