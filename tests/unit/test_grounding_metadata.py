"""
Unit tests for language metadata grounding: Go pclntab parser, C++ Itanium RTTI,
and JavaScript AST scope graph de-obfuscation.
"""

from __future__ import annotations

import struct

from metis_reverse.core.models import (
    EvidenceSource,
)
from metis_reverse.grounding.metadata.cpp_rtti import CppDemangler
from metis_reverse.grounding.metadata.go_pclntab import GoPclntabParser
from metis_reverse.grounding.metadata.js_ast import JsAstScopeExtractor


def test_go_pclntab_synthetic_header_and_function_parsing():
    """Verify Go 1.20+ pclntab layout parsing and GoFunctionSymbol extraction."""
    # Synthesize Go 1.20 header
    # magic: 0xfffffff1, pad1: 0, pad2: 0, minLC: 1, ptrSize: 8
    # nfunc: 1, nfiles: 1, textStart: 0x401000
    # funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset
    header = bytearray()
    header += struct.pack("<I", 0xFFFFFFF1)
    header += b"\x00\x00"  # pad
    header += b"\x01\x08"  # minLC=1, ptrSize=8
    header += struct.pack("<Q", 1)  # nfunc=1
    header += struct.pack("<Q", 1)  # nfiles=1
    header += struct.pack("<Q", 0x401000)  # textStart
    header += struct.pack("<Q", 72)  # funcnameOffset
    header += struct.pack("<Q", 120)  # cuOffset
    header += struct.pack("<Q", 128)  # filetabOffset
    header += struct.pack("<Q", 160)  # pctabOffset
    header += struct.pack("<Q", 200)  # pclnOffset

    # Pad to funcnameOffset (72)
    header += b"\x00" * (72 - len(header))
    # Write function name at offset 72: "main.main\x00"
    header += b"main.main\x00"

    # Pad to pclnOffset (200)
    header += b"\x00" * (200 - len(header))
    # Functab entry 0: entryOff=0, funcDataOff=16
    header += struct.pack("<II", 0, 16)
    # Next functab entry (boundary): entryOff=64, funcDataOff=0
    header += struct.pack("<II", 64, 0)

    # At pclnOffset + 16 (216): _func record
    # entryOff: 0, nameOff: 0, args: 0, deferreturn: 0, pcsp: 0, pcfile: 0, pcln: 0
    header += struct.pack("<IiiIIII", 0, 0, 0, 0, 0, 0, 0)

    parser = GoPclntabParser(raw_bytes=bytes(header), text_base_address=0x401000)
    symbols = parser.extract_symbols()

    assert len(symbols) == 1
    assert symbols[0].name == "main.main"
    assert symbols[0].address == 0x401000
    assert symbols[0].size == 64

    tags = parser.generate_evidence_tags(symbols)
    assert len(tags) == 1
    assert tags[0].source == EvidenceSource.GO_PCLNTAB
    assert tags[0].confidence == 1.0
    assert tags[0].is_immutable is True


def test_cpp_demangler_itanium_names():
    """Verify Itanium C++ ABI symbol demangling."""
    # VTables
    demangled_vt = CppDemangler.demangle("_ZTVN5metis7ServiceE")
    assert "metis::Service" in demangled_vt

    # TypeInfo
    demangled_ti = CppDemangler.demangle("_ZTIN5metis7ServiceE")
    assert "metis::Service" in demangled_ti

    # Nested functions
    demangled_fn = CppDemangler.demangle("_ZN5metis7Service4InitEv")
    assert "metis::Service" in demangled_fn


def test_js_ast_scope_extractor_module_exports():
    """Verify JS AST scope extraction of obfuscated classes, methods, and exports."""
    js_code = """
    class s {
        constructor() { this.secret = "metis"; }
        computeHash(data) { return "hash"; }
        signToken(payload) { return "sig"; }
    }
    class o {
        constructor(crypto) { this.c = crypto; }
        createSession(user) { return "session"; }
    }
    module.exports = { CryptoUtil: s, SessionManager: o };
    function i() { const s = { action: "help", secret: "metis" }; return s; }
    function c() { console.log("Usage: node bundle.min.js"); }
    """

    extractor = JsAstScopeExtractor(js_code)
    bindings = extractor.analyze()

    assert len(bindings) > 0
    orig_names = [b.original_name for b in bindings]

    assert "CryptoUtil" in orig_names
    assert "SessionManager" in orig_names
    assert "computeHash" in orig_names
    assert "signToken" in orig_names
    assert "createSession" in orig_names

    tags = extractor.generate_evidence_tags(bindings)
    assert len(tags) > 0
    for t in tags:
        assert t.source == EvidenceSource.JS_AST_PROPAGATION
        assert t.confidence >= 0.85
