"""JSService: JavaScript AST, bundle module decomposition, and string extraction.

Implements P1-1:
- Bun single-file and bundled JS module enumeration and slicing.
- AST / Regex lexical search and function signature extraction.
- Extraction of high-value strings (URLs, hostnames, env vars, config keys).
- JSC / V8 bytecode detection (reporting opaque_bytecode per R4).
"""

import re
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from ..storage.artifact_tree import ArtifactTree, ArtifactNode


class JSService:
    """Provides JavaScript bundle decompilation, module indexing, and AST analysis."""

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9_\-\.:]+(?:/[a-zA-Z0-9_\-\./\?%&=#]*)?", re.IGNORECASE)
    ENV_PATTERN = re.compile(r"process\.env\.([a-zA-Z0-9_]+)", re.IGNORECASE)
    CONFIG_KEY_PATTERN = re.compile(r"['\"]([a-zA-Z0-9_\-\.]{3,32})['\"]\s*:\s*", re.IGNORECASE)

    @classmethod
    def list_modules(cls, tree: ArtifactTree, artifact_id: str, cursor: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Lists all JavaScript modules extracted or embedded in an artifact."""
        node = tree.get_node(artifact_id)
        if not node:
            return {"status": "error", "message": f"Artifact '{artifact_id}' not found"}

        # Collect child JS modules from tree
        modules = []
        for child_id in node.children:
            child = tree.get_node(child_id)
            if child and "javascript" in child.families:
                content = tree.get_content(child_id) or b""
                lines_count = content.count(b"\n") + 1
                modules.append({
                    "artifact_id": child_id,
                    "name": child.name,
                    "size_bytes": child.size,
                    "lines_count": lines_count,
                    "sha256": child.sha256,
                    "module_path": child.custom_metadata.get("module_path", child.name),
                })

        # If the artifact itself is a JS file
        if not modules and "javascript" in node.families:
            content = tree.get_content(artifact_id) or b""
            lines_count = content.count(b"\n") + 1
            modules.append({
                "artifact_id": artifact_id,
                "name": node.name,
                "size_bytes": node.size,
                "lines_count": lines_count,
                "sha256": node.sha256,
                "module_path": node.name,
            })

        total = len(modules)
        paged = modules[cursor:cursor + limit]
        next_cursor = (cursor + limit) if (cursor + limit < total) else None

        return {
            "status": "success",
            "total": total,
            "cursor": cursor,
            "limit": limit,
            "truncated": next_cursor is not None,
            "next_cursor": next_cursor,
            "modules": paged,
        }

    MAX_SAFE_LINE_CHARS = 32768  # 32KB context safety threshold for single-line minified files

    @classmethod
    def extract_ast_closures(cls, text: str, max_closures: int = 500) -> List[Dict[str, Any]]:
        """Parses JavaScript code and extracts AST function closures with balanced-brace boundaries."""
        closures = []
        head_pattern = re.compile(
            r"""(?:
                (?:export\s+)?(?:async\s+)?function\s*([a-zA-Z0-9_\$]*)\s*\(([^)]*)\)\s*\{ |
                (?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_\$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{ |
                (?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_\$]+)\s*=\s*(?:async\s*)?function\s*([a-zA-Z0-9_\$]*)\s*\(([^)]*)\)\s*\{ |
                \((?:function\s*([a-zA-Z0-9_\$]*)\s*\(([^)]*)\)|(?:async\s*)?\(([^)]*)\)\s*=>)\s*\{ |
                !function\s*([a-zA-Z0-9_\$]*)\s*\(([^)]*)\)\s*\{
            )""",
            re.VERBOSE
        )

        for m in head_pattern.finditer(text):
            start_char = m.start()
            open_brace = m.end() - 1

            depth = 1
            pos = open_brace + 1
            in_str = None
            in_escape = False
            n = len(text)

            while pos < n and depth > 0:
                ch = text[pos]
                if in_str:
                    if in_escape:
                        in_escape = False
                    elif ch == "\\":
                        in_escape = True
                    elif ch == in_str:
                        in_str = None
                else:
                    if ch in ("\"", "'", "`"):
                        in_str = ch
                    elif ch == "/" and pos + 1 < n and text[pos+1] == "/":
                        pos = text.find("\n", pos)
                        if pos == -1: break
                    elif ch == "/" and pos + 1 < n and text[pos+1] == "*":
                        end_c = text.find("*/", pos + 2)
                        if end_c == -1: break
                        pos = end_c + 1
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                pos += 1

            if depth == 0:
                end_char = pos
                closure_code = text[start_char:end_char]
                groups = m.groups()
                name = groups[0] or groups[2] or groups[4] or groups[7] or groups[10] or "anonymous"
                params = groups[1] or groups[3] or groups[6] or groups[8] or groups[9] or ""
                kind = "FunctionDeclaration"
                if groups[2] is not None:
                    kind = "ArrowFunction"
                elif groups[4] is not None:
                    kind = "FunctionExpression"
                elif groups[7] is not None or groups[10] is not None:
                    kind = "IIFE"

                closures.append({
                    "closure_index": len(closures),
                    "name": name.strip(),
                    "kind": kind,
                    "params": [p.strip() for p in params.split(",") if p.strip()],
                    "start_char": start_char,
                    "end_char": end_char,
                    "char_length": len(closure_code),
                    "code": closure_code
                })
                if len(closures) >= max_closures:
                    break
        return closures

    @classmethod
    def get_closure_by_name(cls, text: str, name: str, max_chars: int = 4000) -> Optional[Dict[str, Any]]:
        """Fast targeted search and extraction of a specific named closure from minified or unminified JS."""
        esc_name = re.escape(name)
        pattern = re.compile(
            r"""(?:
                (?:export\s+)?(?:async\s+)?function\s+""" + esc_name + r"""\s*\(([^)]*)\)\s*\{ |
                (?:export\s+)?(?:const|let|var)\s+""" + esc_name + r"""\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{ |
                (?:export\s+)?(?:const|let|var)\s+""" + esc_name + r"""\s*=\s*(?:async\s*)?function\s*(?:[a-zA-Z0-9_\$]*)\s*\(([^)]*)\)\s*\{ |
                \b""" + esc_name + r"""\s*\(([^)]*)\)\s*\{
            )""",
            re.VERBOSE
        )
        m = pattern.search(text)
        if not m:
            return None

        start_char = m.start()
        open_brace = m.end() - 1
        depth = 1
        pos = open_brace + 1
        in_str = None
        in_escape = False
        n = len(text)

        while pos < n and depth > 0:
            ch = text[pos]
            if in_str:
                if in_escape:
                    in_escape = False
                elif ch == "\\":
                    in_escape = True
                elif ch == in_str:
                    in_str = None
            else:
                if ch in ("\"", "'", "`"):
                    in_str = ch
                elif ch == "/" and pos + 1 < n and text[pos+1] == "/":
                    pos = text.find("\n", pos)
                    if pos == -1: break
                elif ch == "/" and pos + 1 < n and text[pos+1] == "*":
                    end_c = text.find("*/", pos + 2)
                    if end_c == -1: break
                    pos = end_c + 1
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            pos += 1

        if depth == 0:
            end_char = pos
            closure_code = text[start_char:end_char]
            params = m.group(1) or m.group(2) or m.group(3) or m.group(4) or ""
            return {
                "name": name,
                "params": [p.strip() for p in params.split(",") if p.strip()],
                "start_char": start_char,
                "end_char": end_char,
                "char_length": len(closure_code),
                "code": closure_code[:max_chars],
                "truncated": len(closure_code) > max_chars,
            }
        return None

    @classmethod
    def list_closures(
        cls,
        tree: ArtifactTree,
        artifact_id: str,
        module_path: Optional[str] = None,
        cursor: int = 0,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Lists AST function closures in a JavaScript module without dumping full source code."""
        target_content = None
        target_name = ""
        node = tree.get_node(artifact_id)
        if node and ("javascript" in node.families or not node.children):
            target_content = tree.get_content(artifact_id)
            target_name = node.name

        if module_path and node:
            for child_id in node.children:
                child = tree.get_node(child_id)
                if child and (child.name == module_path or child.custom_metadata.get("module_path") == module_path):
                    target_content = tree.get_content(child_id)
                    target_name = child.name
                    break

        if not target_content:
            return {"status": "not_found", "message": f"Module '{module_path or artifact_id}' not found"}

        text = target_content.decode("utf-8", errors="replace")
        all_closures = cls.extract_ast_closures(text, max_closures=1000)
        total = len(all_closures)
        paged = all_closures[cursor:cursor + limit]
        next_cursor = (cursor + limit) if (cursor + limit < total) else None

        # Strip code body from list response to keep tokens minimal
        summary_list = [
            {
                "closure_index": c["closure_index"],
                "name": c["name"],
                "kind": c["kind"],
                "params": c["params"],
                "start_char": c["start_char"],
                "end_char": c["end_char"],
                "char_length": c["char_length"],
            }
            for c in paged
        ]

        return {
            "status": "success",
            "module_name": target_name,
            "total_closures": total,
            "cursor": cursor,
            "limit": limit,
            "truncated": next_cursor is not None,
            "next_cursor": next_cursor,
            "closures": summary_list,
        }

    @classmethod
    def get_module(
        cls,
        tree: ArtifactTree,
        artifact_id: str,
        module_path: Optional[str] = None,
        start_line: int = 1,
        end_line: Optional[int] = None,
        max_lines: int = 200,
        slice_mode: str = "line",  # "line", "closure", "range"
        closure_name: Optional[str] = None,
        closure_index: Optional[int] = None,
        start_char: Optional[int] = None,
        end_char: Optional[int] = None,
        max_chars: int = 4000,
    ) -> Dict[str, Any]:
        """Retrieves a bounded slice of a JavaScript module by line range, AST closure, or char offset."""
        target_content = None
        target_name = ""

        # Check if artifact_id itself matches
        node = tree.get_node(artifact_id)
        if node and ("javascript" in node.families or not node.children):
            target_content = tree.get_content(artifact_id)
            target_name = node.name

        # If module_path specified, look through children
        if module_path and node:
            for child_id in node.children:
                child = tree.get_node(child_id)
                if child and (child.name == module_path or child.custom_metadata.get("module_path") == module_path):
                    target_content = tree.get_content(child_id)
                    target_name = child.name
                    break

        if not target_content:
            return {"status": "not_found", "message": f"Module '{module_path or artifact_id}' not found"}

        # Check for JSC opaque bytecode (R4)
        if target_content.startswith(b"\x0b\x00\x00\x00") or b"JSC::Bytecode" in target_content[:64]:
            return {
                "status": "unsupported",
                "format": "jsc_bytecode",
                "opaque_bytecode": True,
                "size_bytes": len(target_content),
                "message": "Artifact contains compiled JSC (JavaScriptCore) bytecode, not source code.",
                "fallback": "Analyze via native strings extraction or custom Python sandbox probe.",
            }

        text = target_content.decode("utf-8", errors="replace")

        # 1. AST Closure extraction mode
        if slice_mode == "closure" or closure_name is not None or closure_index is not None:
            if closure_name:
                c = cls.get_closure_by_name(text, closure_name, max_chars=max_chars)
                if not c:
                    return {
                        "status": "not_found",
                        "module_name": target_name,
                        "message": f"Closure '{closure_name}' not found in module '{target_name}'",
                    }
                return {
                    "status": "success",
                    "slice_mode": "closure",
                    "module_name": target_name,
                    "closure_name": c["name"],
                    "params": c["params"],
                    "start_char": c["start_char"],
                    "end_char": c["end_char"],
                    "char_length": c["char_length"],
                    "code": c["code"],
                    "truncated": c.get("truncated", False),
                }
            elif closure_index is not None:
                all_c = cls.extract_ast_closures(text, max_closures=closure_index + 10)
                if 0 <= closure_index < len(all_c):
                    c = all_c[closure_index]
                    code_slice = c["code"][:max_chars]
                    return {
                        "status": "success",
                        "slice_mode": "closure",
                        "module_name": target_name,
                        "closure_index": closure_index,
                        "closure_name": c["name"],
                        "kind": c["kind"],
                        "params": c["params"],
                        "start_char": c["start_char"],
                        "end_char": c["end_char"],
                        "char_length": c["char_length"],
                        "code": code_slice,
                        "truncated": len(c["code"]) > max_chars,
                    }
                return {
                    "status": "not_found",
                    "module_name": target_name,
                    "message": f"Closure index {closure_index} out of range (found {len(all_c)} closures)",
                }

        # 2. Bounded character offset range mode
        if slice_mode == "range" or start_char is not None:
            s_c = max(0, start_char or 0)
            e_c = min(len(text), end_char if end_char is not None else s_c + max_chars)
            return {
                "status": "success",
                "slice_mode": "range",
                "module_name": target_name,
                "start_char": s_c,
                "end_char": e_c,
                "char_length": e_c - s_c,
                "total_chars": len(text),
                "code": text[s_c:e_c],
            }

        # 3. Traditional Line slice mode with Single-Line Context Safety Guard
        lines = text.splitlines()
        total_lines = len(lines)

        s_idx = max(0, start_line - 1)
        e_idx = min(total_lines, end_line if end_line is not None else s_idx + max_lines)
        sliced_lines = lines[s_idx:e_idx]

        # Check if line slice contains single lines exceeding the safety threshold (e.g. 30MB single line minified JS)
        oversized = [len(l) for l in sliced_lines if len(l) > cls.MAX_SAFE_LINE_CHARS]
        if oversized:
            sample_c = cls.extract_ast_closures(text[:65536], max_closures=10)
            avail = [c["name"] for c in sample_c if c["name"] != "anonymous"]
            return {
                "status": "guard_triggered",
                "module_name": target_name,
                "total_lines": total_lines,
                "line_length": oversized[0],
                "warning": (
                    f"Minified single-line JavaScript detected: line length is {oversized[0]:,} characters, "
                    f"exceeding safe LLM context threshold ({cls.MAX_SAFE_LINE_CHARS:,} chars). "
                    f"Raw line slice was suppressed to prevent context overflow."
                ),
                "suggested_action": "Use slice_mode='closure' with 'closure_name' or 'closure_index', or 'js_list_closures' for AST-bounded function extraction.",
                "sample_closures_available": avail,
            }

        return {
            "status": "success",
            "slice_mode": "line",
            "module_name": target_name,
            "total_lines": total_lines,
            "start_line": s_idx + 1,
            "end_line": e_idx,
            "line_count": len(sliced_lines),
            "code": "\n".join(sliced_lines),
        }

    @classmethod
    def search_js(
        cls,
        tree: ArtifactTree,
        artifact_id: str,
        query: str,
        is_regex: bool = False,
        cursor: int = 0,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Searches across JavaScript code using string matching or regular expressions."""
        matches: List[Dict[str, Any]] = []
        node = tree.get_node(artifact_id)
        if not node:
            return {"status": "error", "message": f"Artifact '{artifact_id}' not found"}

        pattern = None
        if is_regex:
            try:
                pattern = re.compile(query, re.IGNORECASE)
            except Exception as e:
                return {"status": "error", "message": f"Invalid regex pattern: {str(e)}"}

        targets = [artifact_id] + node.children
        for tid in targets:
            tnode = tree.get_node(tid)
            if not tnode or "javascript" not in tnode.families:
                continue
            content = tree.get_content(tid)
            if not content:
                continue
            text = content.decode("utf-8", errors="replace")
            lines = text.splitlines(keepends=True)

            char_cursor = 0
            for line_no, raw_line in enumerate(lines, 1):
                clean_line = raw_line.rstrip("\r\n")
                hit = False
                m_start_in_line = -1
                m_len = 0
                matched_val = ""

                if pattern:
                    m = pattern.search(clean_line)
                    if m:
                        hit = True
                        m_start_in_line = m.start()
                        m_len = m.end() - m.start()
                        matched_val = m.group(0)
                else:
                    idx = clean_line.lower().find(query.lower())
                    if idx != -1:
                        hit = True
                        m_start_in_line = idx
                        m_len = len(query)
                        matched_val = clean_line[idx:idx + len(query)]

                if hit:
                    global_char_offset = char_cursor + m_start_in_line
                    matches.append({
                        "artifact_id": tid,
                        "module_name": tnode.name,
                        "line_number": line_no,
                        "char_offset": global_char_offset,
                        "length": m_len,
                        "matched_text": matched_val,
                        "line_text": clean_line.strip()[:200],
                    })
                    if len(matches) >= 500:
                        break

                char_cursor += len(raw_line)

        total = len(matches)
        paged = matches[cursor:cursor + limit]
        next_cursor = (cursor + limit) if (cursor + limit < total) else None

        return {
            "status": "success",
            "query": query,
            "total": total,
            "cursor": cursor,
            "limit": limit,
            "truncated": next_cursor is not None,
            "next_cursor": next_cursor,
            "matches": paged,
        }

    @classmethod
    def extract_functions(cls, tree: ArtifactTree, artifact_id: str, module_path: Optional[str] = None) -> Dict[str, Any]:
        """Extracts declared function signatures and arrow functions from JavaScript source."""
        target_content = None
        target_id = artifact_id
        node = tree.get_node(artifact_id)
        if not node:
            return {"status": "error", "message": f"Artifact '{artifact_id}' not found"}

        if module_path and node:
            for child_id in node.children:
                child = tree.get_node(child_id)
                if child and (child.name == module_path or child.custom_metadata.get("module_path") == module_path):
                    target_content = tree.get_content(child_id)
                    target_id = child_id
                    break

        if target_content is None:
            target_content = tree.get_content(artifact_id) or b""

        text = target_content.decode("utf-8", errors="replace")

        # 1. First extract high-fidelity AST closures with balanced braces
        closures = cls.extract_ast_closures(text, max_closures=500)
        functions = []
        seen_names = set()

        for c in closures:
            start_c = c["start_char"]
            end_c = c["end_char"]
            start_line = text[:start_c].count("\n") + 1
            end_line = text[:end_c].count("\n") + 1
            decl = c["code"].splitlines()[0][:100] if c["code"] else ""
            functions.append({
                "name": c["name"],
                "params": ", ".join(c["params"]),
                "line_number": start_line,
                "start_line": start_line,
                "end_line": end_line,
                "start_char": start_c,
                "end_char": end_c,
                "char_length": c["char_length"],
                "declaration": decl,
                "kind": c["kind"],
            })
            if c["name"] != "anonymous":
                seen_names.add(c["name"])

        # 2. Also detect any line-level functions not captured by closures
        fn_patterns = [
            re.compile(r"(?:async\s+)?function\s+([a-zA-Z0-9_\$]+)\s*\(([^)]*)\)"),
            re.compile(r"(?:const|let|var)\s+([a-zA-Z0-9_\$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"),
            re.compile(r"([a-zA-Z0-9_\$]+)\s*\(([^)]*)\)\s*\{"), # class method
        ]
        lines = text.splitlines()
        for l_num, line in enumerate(lines, 1):
            for pat in fn_patterns:
                m = pat.search(line)
                if m:
                    fn_name = m.group(1)
                    params = m.group(2).strip()
                    if fn_name not in ("if", "for", "while", "switch", "catch") and fn_name not in seen_names:
                        functions.append({
                            "name": fn_name,
                            "params": params,
                            "line_number": l_num,
                            "start_line": l_num,
                            "end_line": l_num,
                            "start_char": None,
                            "end_char": None,
                            "char_length": None,
                            "declaration": line.strip()[:100],
                            "kind": "Declaration",
                        })
                        seen_names.add(fn_name)
                        break

        return {
            "status": "success",
            "artifact_id": target_id,
            "function_count": len(functions),
            "functions": functions[:200],
        }

    @classmethod
    def extract_strings(cls, tree: ArtifactTree, artifact_id: str, module_path: Optional[str] = None) -> Dict[str, Any]:
        """Extracts high-value strings (URLs, hostnames, env vars, config keys)."""
        target_content = None
        target_id = artifact_id
        node = tree.get_node(artifact_id)
        if not node:
            return {"status": "error", "message": f"Artifact '{artifact_id}' not found"}

        if module_path and node:
            for child_id in node.children:
                child = tree.get_node(child_id)
                if child and (child.name == module_path or child.custom_metadata.get("module_path") == module_path):
                    target_content = tree.get_content(child_id)
                    target_id = child_id
                    break

        if target_content is None:
            target_content = tree.get_content(artifact_id) or b""

        text = target_content.decode("utf-8", errors="replace")

        urls = list(set(cls.URL_PATTERN.findall(text)))
        env_vars = list(set(cls.ENV_PATTERN.findall(text)))
        config_keys = list(set(cls.CONFIG_KEY_PATTERN.findall(text)))

        occurrences = []
        for pat, kind in [(cls.URL_PATTERN, "url"), (cls.ENV_PATTERN, "env_var"), (cls.CONFIG_KEY_PATTERN, "config_key")]:
            for m in pat.finditer(text):
                val = m.group(1) if m.groups() and m.group(1) is not None else m.group(0)
                start_c = m.start(1) if m.groups() and m.group(1) is not None else m.start(0)
                end_c = m.end(1) if m.groups() and m.group(1) is not None else m.end(0)
                l_num = text[:start_c].count("\n") + 1
                occurrences.append({
                    "kind": kind,
                    "value": val,
                    "offset": start_c,
                    "length": end_c - start_c,
                    "line_number": l_num,
                })

        return {
            "status": "success",
            "artifact_id": target_id,
            "urls": urls[:50],
            "env_variables": env_vars[:50],
            "config_keys": config_keys[:50],
            "occurrences": occurrences[:100],
        }
