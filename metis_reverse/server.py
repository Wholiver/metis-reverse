"""Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for Metis Reverse."""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from .tools.handlers import MetisToolDispatcher
from .config import load_config
from . import __version__

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stderr)
logger = logging.getLogger("metis-reverse-mcp")

class MetisMCPServer:
    """Standard JSON-RPC 2.0 stdio server conforming to Model Context Protocol."""

    RESOURCE_MAP = {
        "metis://docs/skill-manual": {
            "name": "Metis Reverse MCP Skill Manual",
            "description": "Full skill manual and operational guidelines for Metis Reverse MCP",
            "mimeType": "text/markdown",
            "rel_path": "SKILL.md",
        },
        "metis://docs/tools-catalog": {
            "name": "Metis Reverse Tools Catalog & Schemas",
            "description": "Detailed schemas, parameter definitions and JSON examples for all 29 MCP tools",
            "mimeType": "text/markdown",
            "rel_path": "references/tools-catalog-and-schemas.md",
        },
        "metis://docs/probe-recipes": {
            "name": "Metis Reverse Escape Hatch Probe Recipes",
            "description": "Sandbox Python probe scripts and deobfuscation code recipes",
            "mimeType": "text/markdown",
            "rel_path": "references/escape-hatch-probe-recipes.md",
        },
        "metis://docs/polyglot-guide": {
            "name": "Metis Reverse Polyglot & Degradation Guide",
            "description": "Guide for polyglot software reversing and 4-tier degradation strategy",
            "mimeType": "text/markdown",
            "rel_path": "references/polyglot-and-degradation-guide.md",
        },
    }

    def __init__(self, dispatcher: Optional[MetisToolDispatcher] = None):
        self.config = load_config()
        self.dispatcher = dispatcher or MetisToolDispatcher(config=self.config)

    @staticmethod
    def get_skill_dir() -> Path:
        """Locates the skills/metis-reverse-mcp directory."""
        repo_root = Path(__file__).resolve().parent.parent
        skill_dir = repo_root / "skills" / "metis-reverse-mcp"
        if skill_dir.exists():
            return skill_dir
        cwd_skill = Path.cwd() / "skills" / "metis-reverse-mcp"
        if cwd_skill.exists():
            return cwd_skill
        return skill_dir

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handles a single JSON-RPC 2.0 request."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # Notifications (no response required)
        if req_id is None:
            if method == "notifications/initialized":
                logger.info("Client completed initialization handshake.")
            return None

        # Ping
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        # Initialize
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "metis-reverse",
                        "version": __version__
                    },
                    "capabilities": {
                        "tools": {
                            "listChanged": False
                        },
                        "resources": {
                            "subscribe": False,
                            "listChanged": False
                        },
                        "prompts": {
                            "listChanged": False
                        }
                    }
                }
            }

        # List tools
        if method == "tools/list":
            tools = self.dispatcher.get_tool_definitions()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": tools
                }
            }

        # Call tool
        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            try:
                result = self.dispatcher.dispatch(tool_name, tool_args)
            except Exception as e:
                logger.exception(f"Unhandled tool execution error in {tool_name}: {e}")
                result = {"status": "error", "error": f"Tool execution failed: {str(e)}"}
            is_error = result.get("status") == "error"

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, ensure_ascii=False)
                        }
                    ],
                    "isError": is_error
                }
            }

        # List resources
        if method == "resources/list":
            resources = [
                {
                    "uri": uri,
                    "name": info["name"],
                    "description": info["description"],
                    "mimeType": info["mimeType"],
                }
                for uri, info in self.RESOURCE_MAP.items()
            ]
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resources": resources
                }
            }

        # Read resource
        if method == "resources/read":
            uri = params.get("uri")
            if not uri or uri not in self.RESOURCE_MAP:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": f"Resource not found: {uri}"
                    }
                }

            info = self.RESOURCE_MAP[uri]
            skill_dir = self.get_skill_dir()
            target_path = skill_dir / info["rel_path"]

            if not target_path.exists():
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": f"Resource file missing on disk: {target_path}"
                    }
                }

            try:
                content = target_path.read_text(encoding="utf-8")
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": f"Failed to read resource file: {e}"
                    }
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": info["mimeType"],
                            "text": content
                        }
                    ]
                }
            }

        # List prompts
        if method == "prompts/list":
            prompts = [
                {
                    "name": "metis-reverse-skill",
                    "description": "Full operational manual and cardinal rules for AI Agents performing deterministic reverse engineering with Metis MCP",
                    "arguments": [
                        {
                            "name": "sample_path",
                            "description": "Optional physical path to target binary sample to reverse engineer",
                            "required": False
                        },
                        {
                            "name": "focus_area",
                            "description": "Optional focus area (e.g. polyglot, crypto, bridges, structs, cross-patch)",
                            "required": False
                        }
                    ]
                }
            ]
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "prompts": prompts
                }
            }

        # Get prompt
        if method == "prompts/get":
            prompt_name = params.get("name")
            if prompt_name != "metis-reverse-skill":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": f"Prompt not found: {prompt_name}"
                    }
                }

            arguments = params.get("arguments", {})
            sample_path = arguments.get("sample_path") or arguments.get("target_file")
            focus_area = arguments.get("focus_area")

            skill_dir = self.get_skill_dir()
            skill_manual_path = skill_dir / "SKILL.md"
            if skill_manual_path.exists():
                manual_text = skill_manual_path.read_text(encoding="utf-8")
            else:
                manual_text = "# Metis Reverse MCP Skill Manual\nEvidence-grounded deterministic reverse engineering."

            prompt_content = f"{manual_text}\n\n---\n\n## Current Analysis Task Guidance\n"
            if sample_path:
                prompt_content += f"- **Target Binary Sample**: `{sample_path}`\n"
                prompt_content += "- **Initial Step**: Call `re_session_manager(action='open', file_path=...)` to mount the sample read-only, then run `re_triage` and `re_tree_status`.\n"
            if focus_area:
                prompt_content += f"- **Primary Focus Area**: `{focus_area}`\n"
                prompt_content += "- Follow the corresponding Standard Operating Procedure (SOP) in the skill manual above.\n"
            if not sample_path and not focus_area:
                prompt_content += "- Provide a target binary path and analysis objective, and strictly follow the Five Cardinal Rules.\n"

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "description": "Metis Reverse MCP Skill Manual & Guidance",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": prompt_content
                            }
                        }
                    ]
                }
            }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            }
        }

    def run_stdio(self) -> None:
        """Main stdio loop."""
        logger.info("Metis Reverse MCP server started on stdio.")
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            req_id = None
            try:
                request = json.loads(line)
                if isinstance(request, dict):
                    req_id = request.get("id")
                response = self.handle_request(request)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                logger.error(f"Error handling line: {e}")
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": f"Internal RPC error: {str(e)}"
                    }
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

def main():
    if "--version" in sys.argv:
        print(f"metis-reverse version {__version__}")
        sys.exit(0)
    server = MetisMCPServer()
    server.run_stdio()

if __name__ == "__main__":
    main()
