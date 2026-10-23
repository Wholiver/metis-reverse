"""PromptShield: Defending AI Agents against Indirect Prompt Injections in Binaries.

Malicious binaries increasingly embed natural language instructions into .rdata,
PDB paths, exports, or debug strings designed to subvert or jailbreak LLM agents
(e.g., Check Point CPR 2025 findings).
"""

import re
import html
from typing import Dict, Any, List, Optional, Tuple

# Suspicious instruction patterns targeting LLMs
SUSPICIOUS_PROMPT_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous\s+)?instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous\s+)?(prompts?|instructions?)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+|an\s+)?(unrestricted|developer|jailbroken)", re.IGNORECASE),
    re.compile(r"(system\s+prompt|new\s+system\s+directive)\s*:", re.IGNORECASE),
    re.compile(r"(return|classify|mark|output)\s+(that\s+)?(this\s+file|this\s+binary|sample)\s+(is\s+)?(safe|benign|clean)", re.IGNORECASE),
    re.compile(r"do\s+not\s+(report|analyze|decompile|flag)", re.IGNORECASE),
    re.compile(r"override\s+(all\s+)?rules", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
]

# Invisible unicode characters often used for evasion (zero-width spaces, directional marks)
INVISIBLE_UNICODE_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u202A-\u202E]")

class PromptShield:
    """Detects and isolates untrusted natural language data extracted from binaries."""

    def __init__(self, aggressive_filter: bool = True):
        self.aggressive_filter = aggressive_filter

    def inspect_text(self, text: str) -> Tuple[bool, List[str]]:
        """Inspects text for prompt injection keywords and evasion artifacts.
        
        Returns:
            (has_injection, matched_patterns)
        """
        if not text:
            return False, []

        clean = INVISIBLE_UNICODE_CHARS.sub("", text)
        matched = []
        for pat in SUSPICIOUS_PROMPT_PATTERNS:
            found = pat.findall(clean)
            if found:
                matched.append(pat.pattern)

        return len(matched) > 0, matched

    def sanitize_untrusted_text(self, text: str) -> str:
        """Strips dangerous characters and escapes HTML/XML tags."""
        if not text:
            return ""
        # Remove zero-width / invisible chars
        sanitized = INVISIBLE_UNICODE_CHARS.sub("", text)
        # HTML/XML escape to prevent breaking LLM fence tags
        sanitized = html.escape(sanitized, quote=True)
        return sanitized

    def wrap_evidence(
        self,
        content: str,
        va: str = "N/A",
        evidence_type: str = "binary_data",
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Wraps untrusted binary content in structured evidence fences.
        
        Outputs both safe fenced representation and security audit metadata.
        """
        has_injection, matched = self.inspect_text(content)
        sanitized = self.sanitize_untrusted_text(content)

        risk_level = "HIGH" if has_injection else "LOW"
        attrs = [
            f'type="{evidence_type}"',
            f'va="{va}"',
            f'risk="{risk_level}"'
        ]
        if extra_attrs:
            for k, v in extra_attrs.items():
                attrs.append(f'{k}="{html.escape(str(v), quote=True)}"')

        attr_str = " ".join(attrs)
        fenced_str = f"<untrusted_binary_evidence {attr_str}>{sanitized}</untrusted_binary_evidence>"

        is_instruction_like = has_injection or bool(
            re.search(r"(\"name\":\s*\"|\"arguments\":\s*\{|re_[a-z_]+\(|call_tool|system:)", content, re.IGNORECASE)
        )

        return {
            "fenced_text": fenced_str,
            "raw_sanitized": sanitized,
            "va": va,
            "type": evidence_type,
            "injection_detected": has_injection,
            "suspicious_instruction_like": is_instruction_like,
            "matched_injection_patterns": matched,
            "security_warning": "POTENTIAL_PROMPT_INJECTION_DETECTED" if has_injection else None
        }

_default_shield = PromptShield()

def wrap_untrusted(content: str, va: str = "N/A", evidence_type: str = "string", **kwargs) -> Dict[str, Any]:
    return _default_shield.wrap_evidence(content, va=va, evidence_type=evidence_type, extra_attrs=kwargs)
