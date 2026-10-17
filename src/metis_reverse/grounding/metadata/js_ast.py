"""
metis_reverse.grounding.metadata.js_ast
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
JavaScript AST scope graph and identifier de-obfuscation extractor using Tree-sitter.
Recovers original class names, module exports, method names, and CLI option parsers
from minified/obfuscated JavaScript bundles.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import tree_sitter_javascript as ts_js
from tree_sitter import Language, Parser

from metis_reverse.core.models import (
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    Symbol,
    SymbolType,
    TargetType,
)

logger = logging.getLogger("metis_reverse.grounding.metadata.js_ast")


@dataclass
class JsEntityBinding:
    mangled_name: str
    original_name: str
    entity_type: str  # "class", "function", "method", "property"
    methods: list[str] = field(default_factory=list)
    properties: dict[str, str] = field(default_factory=dict)
    start_byte: int = 0
    end_byte: int = 0


class JsAstScopeExtractor:
    """Extracts scope hierarchies, class methods, and export de-anonymizations from JS AST."""

    DEFAULT_MAX_DEPTH: int = 10000

    def __init__(self, js_source: str | bytes, max_depth: int = DEFAULT_MAX_DEPTH):
        self.source_bytes = js_source.encode("utf-8") if isinstance(js_source, str) else js_source
        self.language = Language(ts_js.language())
        self.parser = Parser(self.language)
        self.max_depth = max_depth

    @classmethod
    def from_session(cls, session: BinarySession) -> JsAstScopeExtractor | None:
        artifact = session.artifact
        if not artifact or not os.path.exists(artifact.file_path):
            return None
        if not artifact.file_path.endswith((".js", ".mjs", ".cjs", ".ts")):
            return None
        try:
            with open(artifact.file_path, "rb") as f:
                content = f.read()
            return cls(content)
        except Exception:
            return None

    def analyze(self) -> list[JsEntityBinding]:
        bindings: list[JsEntityBinding] = []
        try:
            tree = self.parser.parse(self.source_bytes)
            root = tree.root_node

            # 1. Map exports to mangled identifiers
            # Search for module.exports = { Key: value } or exports.Key = value
            export_map: dict[str, str] = {}  # mangled_name -> original_name
            self._find_exports(root, export_map)

            # 2. Find classes and methods
            class_methods: dict[str, list[str]] = {}
            self._find_classes(root, class_methods)

            # Build entity bindings for exported classes
            for mangled, orig in export_map.items():
                methods = class_methods.get(mangled, [])
                bindings.append(
                    JsEntityBinding(
                        mangled_name=mangled,
                        original_name=orig,
                        entity_type="class",
                        methods=methods,
                    )
                )
                # Add bindings for methods
                for m in methods:
                    bindings.append(
                        JsEntityBinding(
                            mangled_name=f"{mangled}.{m}",
                            original_name=m,
                            entity_type="method",
                        )
                    )

            # 3. Find CLI option functions
            self._find_cli_functions(root, bindings)
        except RecursionError:
            logger.warning("Tree-sitter AST recursion limit reached, falling back to regex")
            return self._regex_fallback()
        except Exception as e:
            logger.warning("Tree-sitter parse or traversal failed, falling back to regex: %s", e)
            return self._regex_fallback()

        # If AST search was empty, use regex fallback
        if not bindings:
            return self._regex_fallback()

        return bindings

    def _iter_ast_nodes(self, root: Any, max_depth: int | None = None) -> Iterator[tuple[Any, int]]:
        """Iterative stack-based DFS traversal over tree-sitter AST nodes."""
        if root is None:
            return
        limit = self.max_depth if max_depth is None else max_depth
        stack = [(root, 0)]
        while stack:
            node, depth = stack.pop()
            yield node, depth
            if depth < limit:
                children = node.children
                for i in range(len(children) - 1, -1, -1):
                    stack.append((children[i], depth + 1))

    def _find_exports(self, node: Any, export_map: dict[str, str], max_depth: int | None = None) -> None:
        """Walk AST iteratively to locate module.exports assignments."""
        for n, _ in self._iter_ast_nodes(node, max_depth):
            if n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left and right:
                    left_text = self._node_text(left)
                    if "module.exports" in left_text and right.type == "object":
                        for child in right.children:
                            if child.type in ("pair", "shorthand_property_identifier_pattern"):
                                k = child.child_by_field_name("key")
                                v = child.child_by_field_name("value")
                                if k and v:
                                    orig = self._node_text(k)
                                    mangled = self._node_text(v)
                                    export_map[mangled] = orig

    def _find_classes(self, node: Any, class_methods: dict[str, list[str]], max_depth: int | None = None) -> None:
        """Walk AST iteratively to find class declarations and their methods."""
        for n, _ in self._iter_ast_nodes(node, max_depth):
            if n.type == "class_declaration":
                name_node = n.child_by_field_name("name")
                body_node = n.child_by_field_name("body")
                if name_node and body_node:
                    cls_name = self._node_text(name_node)
                    methods = []
                    for child in body_node.children:
                        if child.type == "method_definition":
                            m_name_node = child.child_by_field_name("name")
                            if m_name_node:
                                m_name = self._node_text(m_name_node)
                                if m_name != "constructor":
                                    methods.append(m_name)
                    class_methods[cls_name] = methods

    def _find_cli_functions(self, node: Any, bindings: list[JsEntityBinding], max_depth: int | None = None) -> None:
        """Identify option parsing and CLI dispatcher functions using iterative AST walk."""
        for n, _ in self._iter_ast_nodes(node, max_depth):
            if n.type == "function_declaration":
                name_node = n.child_by_field_name("name")
                body_node = n.child_by_field_name("body")
                if name_node and body_node:
                    fn_name = self._node_text(name_node)
                    body_text = self._node_text(body_node)
                    if "--action=" in body_text or "process.argv" in body_text:
                        bindings.append(
                            JsEntityBinding(
                                mangled_name=fn_name,
                                original_name="parseCommandLineArgs",
                                entity_type="function",
                            )
                        )
                    elif "Usage:" in body_text and "Options:" in body_text:
                        bindings.append(
                            JsEntityBinding(
                                mangled_name=fn_name,
                                original_name="runCLI",
                                entity_type="function",
                            )
                        )

    def _regex_fallback(self) -> list[JsEntityBinding]:
        """Regex-based fallback extraction if AST fails."""
        bindings: list[JsEntityBinding] = []
        text = self.source_bytes.decode("utf-8", errors="ignore")

        # Match module.exports = { Name: id }
        matches = re.findall(r'module\.exports\s*=\s*\{\s*([A-Za-z0-9_]+)\s*:\s*([A-Za-z0-9_]+)\s*\}', text)
        for orig, mangled in matches:
            bindings.append(
                JsEntityBinding(
                    mangled_name=mangled,
                    original_name=orig,
                    entity_type="class",
                )
            )

        # Match methods inside classes
        method_matches = re.findall(r'([A-Za-z0-9_]+)\s*\([^\)]*\)\s*\{', text)
        for m in set(method_matches):
            if m not in ('constructor', 'if', 'for', 'while', 'switch', 'catch'):
                bindings.append(
                    JsEntityBinding(
                        mangled_name=m,
                        original_name=m,
                        entity_type="method",
                    )
                )

        return bindings

    def _node_text(self, node: Any) -> str:
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def generate_evidence_tags(self, bindings: list[JsEntityBinding]) -> list[EvidenceTag]:
        tags: list[EvidenceTag] = []
        for b in bindings:
            confidence = 0.95 if b.entity_type == "class" else 0.85
            is_func = b.entity_type in ("function", "method")
            tags.append(
                EvidenceTag(
                    tag_id=f"ev_js_{b.original_name}",
                    target_type=TargetType.FUNCTION if is_func else TargetType.SYMBOL,
                    target_id=f"sym:{b.mangled_name}",
                    suggested_name=b.original_name,
                    suggested_type=b.entity_type,
                    source=EvidenceSource.JS_AST_PROPAGATION,
                    evidence_type="JS_AST_PROPAGATION",
                    confidence=confidence,
                    raw_anchor=f"JS AST scope binding: {b.original_name} -> {b.mangled_name}",
                    explanation=f"Recovered original identifier '{b.original_name}' from JavaScript AST scope analysis",
                    is_immutable=False,
                )
            )
        return tags

    @classmethod
    def ground(cls, session: BinarySession) -> list[EvidenceTag]:
        extractor = cls.from_session(session)
        if not extractor:
            return []

        bindings = extractor.analyze()
        if not bindings:
            return []

        tags = extractor.generate_evidence_tags(bindings)

        # Attach symbols
        for b in bindings:
            sym = Symbol(
                address=0,
                name=b.original_name,
                type=SymbolType.FUNCTION if b.entity_type in ("function", "method") else SymbolType.DATA,
                confidence=0.95 if b.entity_type == "class" else 0.85,
            )
            session.add_symbol(sym)
            if b.mangled_name not in session.symbols:
                session.symbols[b.mangled_name] = sym

        for t in tags:
            session.attach_evidence(t)

        return tags
