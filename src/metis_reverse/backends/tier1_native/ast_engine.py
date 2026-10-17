"""
metis_reverse.backends.tier1_native.ast_engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tree-sitter AST tokenization, scope mapping, and zero-hallucination semantic mutator.
"""

from __future__ import annotations

from typing import NamedTuple

import tree_sitter
import tree_sitter_c


class AstToken(NamedTuple):
    name: str
    start_byte: int
    end_byte: int
    start_point: tuple[int, int]  # (row, col)
    end_point: tuple[int, int]
    node_type: str
    parent_type: str
    scope_id: str


class TreeSitterAstEngine:
    """Parses and semantically mutates C decompilation source using Tree-sitter CST."""

    def __init__(self) -> None:
        # tree-sitter >= 0.24.0 API
        self.language = tree_sitter.Language(tree_sitter_c.language())
        self.parser = tree_sitter.Parser(self.language)

    def parse_c_code(self, source_code: str) -> tree_sitter.Tree:
        """Parse C source code into a Concrete Syntax Tree."""
        return self.parser.parse(source_code.encode("utf-8"))

    def extract_identifiers(self, source_code: str) -> list[AstToken]:
        """
        Extract all identifier tokens with exact byte spans and enclosing scopes.
        Ignores string literals, comments, and preprocessor directives.
        """
        source_bytes = source_code.encode("utf-8")
        tree = self.parse_c_code(source_code)
        tokens: list[AstToken] = []

        def walk(node: tree_sitter.Node, current_scope: str) -> None:
            if node.type == "function_definition":
                current_scope = f"func_{node.start_point[0]}"
            elif node.type == "compound_statement":
                current_scope = f"{current_scope}_block_{node.start_point[0]}"

            if node.type in ("identifier", "field_identifier"):
                token_name = source_bytes[node.start_byte:node.end_byte].decode("utf-8")
                tokens.append(
                    AstToken(
                        name=token_name,
                        start_byte=node.start_byte,
                        end_byte=node.end_byte,
                        start_point=node.start_point,
                        end_point=node.end_point,
                        node_type=node.type,
                        parent_type=node.parent.type if node.parent else "root",
                        scope_id=current_scope,
                    )
                )

            for child in node.children:
                walk(child, current_scope)

        walk(tree.root_node, "global")
        return tokens

    def rename_identifier(
        self,
        source_code: str,
        old_name: str,
        new_name: str,
        scope_prefix: str | None = None,
        include_fields: bool = False,
    ) -> str:
        """
        Semantically rename an identifier in C code with zero regex bugs.

        Args:
            source_code: Original C pseudocode string.
            old_name: Existing variable or parameter name.
            new_name: Desired new identifier name.
            scope_prefix: Optional scope filter (e.g. 'func_1'). If None, renames everywhere.
            include_fields: Whether to include struct/union field identifiers.

        Returns:
            Rewritten C pseudocode with exact AST token replacement.
        """
        source_bytes = bytearray(source_code.encode("utf-8"))
        tokens = self.extract_identifiers(source_code)

        matching = [
            t
            for t in tokens
            if t.name == old_name
            and (include_fields or t.node_type == "identifier")
            and (scope_prefix is None or t.scope_id.startswith(scope_prefix))
        ]

        if not matching:
            return source_code

        # Sort descending by start_byte for safe in-place replacement
        matching.sort(key=lambda t: t.start_byte, reverse=True)

        new_bytes = new_name.encode("utf-8")
        for token in matching:
            source_bytes[token.start_byte:token.end_byte] = new_bytes

        return source_bytes.decode("utf-8")
