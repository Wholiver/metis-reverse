"""CryptoService: Task-level cryptographic primitive and API hash detection."""

import struct
from typing import Dict, Any, List, Optional
from ..storage.models import EvidencePointer

# Well-known cryptographic constant patterns
KNOWN_CRYPTO_CONSTANTS = {
    0x637c777b: {"algorithm": "AES", "type": "S-Box prefix", "confidence": 0.98},
    0x67452301: {"algorithm": "MD5 / SHA-1", "type": "Init vector IV_A", "confidence": 0.95},
    0xefcdab89: {"algorithm": "MD5 / SHA-1", "type": "Init vector IV_B", "confidence": 0.95},
    0x6a09e667: {"algorithm": "SHA-256", "type": "Init vector H0", "confidence": 0.99},
    0xbb67ae85: {"algorithm": "SHA-256", "type": "Init vector H1", "confidence": 0.99},
    0x61707865: {"algorithm": "ChaCha20", "type": "Constant 'expa'", "confidence": 0.99},
    0xedb88320: {"algorithm": "CRC32", "type": "Reversed polynomial", "confidence": 0.95},
    0x9e3779b9: {"algorithm": "TEA / XTEA", "type": "Golden ratio constant", "confidence": 0.96},
}

# Common ROR13 API hash mapping table for Windows APIs
KNOWN_ROR13_API_HASHES = {
    "0x0726774c": "LoadLibraryA",
    "0x7802f749": "GetProcAddress",
    "0xe553a458": "VirtualAlloc",
    "0x302f46db": "VirtualProtect",
    "0x16b3fe72": "CreateProcessA",
    "0x7c0dfcaa": "ExitProcess",
    "0xec0e4e8e": "InternetOpenA",
    "0x2e06f848": "InternetOpenUrlA",
}

class CryptoService:
    """Detects cryptographic signatures, S-Boxes, and API hashes bound to specific VAs."""

    def analyze_constants(self, constants_by_va: Dict[str, List[int]]) -> List[Dict[str, Any]]:
        """Scans constant values extracted from functions for cryptographic constants."""
        findings = []
        for va, const_list in constants_by_va.items():
            for c in const_list:
                c_val = c & 0xFFFFFFFF
                if c_val in KNOWN_CRYPTO_CONSTANTS:
                    meta = KNOWN_CRYPTO_CONSTANTS[c_val]
                    findings.append({
                        "va": va,
                        "constant_hex": hex(c_val),
                        "algorithm": meta["algorithm"],
                        "constant_type": meta["type"],
                        "confidence": meta["confidence"],
                        "evidence_pointer": EvidencePointer(
                            va=va,
                            evidence_type="crypto_constant",
                            description=f"Matched {meta['algorithm']} ({meta['type']}) constant {hex(c_val)}",
                            confidence=meta["confidence"],
                        ).to_dict()
                    })
        return findings

    def resolve_api_hash(self, hash_value: int, algorithm: str = "ror13") -> Optional[str]:
        """Resolves known API hash values to function names."""
        h_hex = hex(hash_value & 0xFFFFFFFF).lower()
        if algorithm.lower() == "ror13":
            return KNOWN_ROR13_API_HASHES.get(h_hex)
        return None

    def scan_memory_for_sboxes(self, memory_slice: bytes, base_va: str = "0x0") -> List[Dict[str, Any]]:
        """Scans a byte slice for Rijndael (AES) S-Box sequences."""
        aes_sbox_prefix = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
        findings = []
        idx = memory_slice.find(aes_sbox_prefix)
        while idx != -1:
            try:
                base_int = int(base_va, 16)
                va = hex(base_int + idx)
            except ValueError:
                va = f"{base_va}+{hex(idx)}"

            findings.append({
                "va": va,
                "algorithm": "AES",
                "primitive": "AES Forward S-Box table",
                "offset": idx,
                "confidence": 1.0,
                "evidence_pointer": EvidencePointer(
                    va=va,
                    evidence_type="const_sbox",
                    description=f"AES Forward S-Box (256-byte substitution box) found at {va}",
                    confidence=1.0,
                    raw_bytes_hex=aes_sbox_prefix.hex(),
                ).to_dict()
            })
            idx = memory_slice.find(aes_sbox_prefix, idx + 1)
        return findings
