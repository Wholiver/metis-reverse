"""
metis_reverse.grounding
~~~~~~~~~~~~~~~~~~~~~~~
Multi-Evidence Grounding Engine coordinating format strings, assert macros,
system call semantic propagation, and language metadata extraction.
"""

from __future__ import annotations

import logging

from metis_reverse.core.models import BinarySession, EvidenceTag
from metis_reverse.grounding.assert_macros import AssertMacroGrounder
from metis_reverse.grounding.format_strings import FormatStringGrounder
from metis_reverse.grounding.metadata.cpp_rtti import CppRttiExtractor
from metis_reverse.grounding.metadata.go_pclntab import GoPclntabParser
from metis_reverse.grounding.metadata.js_ast import JsAstScopeExtractor
from metis_reverse.grounding.syscalls import SyscallPropagator

logger = logging.getLogger("metis_reverse.grounding")

__all__ = [
    "AssertMacroGrounder",
    "CppRttiExtractor",
    "FormatStringGrounder",
    "GoPclntabParser",
    "JsAstScopeExtractor",
    "SyscallPropagator",
    "ground_session",
]


def ground_session(session: BinarySession) -> list[EvidenceTag]:
    """
    Execute all deterministic evidence grounding modules against the active session.
    Populates immutable EvidenceTags and enriches functions and symbols with grounded facts.
    """
    collected_tags: list[EvidenceTag] = []

    # 1. Go pclntab metadata extraction
    try:
        pcln_tags = GoPclntabParser.ground(session)
        collected_tags.extend(pcln_tags)
    except Exception as e:
        logger.debug("Go pclntab grounding skipped: %s", e)

    # 2. C++ Itanium RTTI & VTables
    try:
        rtti_tags = CppRttiExtractor.ground(session)
        collected_tags.extend(rtti_tags)
    except Exception as e:
        logger.debug("C++ RTTI grounding skipped: %s", e)

    # 3. JavaScript AST Scope Graph
    try:
        js_tags = JsAstScopeExtractor.ground(session)
        collected_tags.extend(js_tags)
    except Exception as e:
        logger.debug("JS AST grounding skipped: %s", e)

    # 4. Format string reverse inference (printf / spdlog / fmt)
    try:
        fmt_tags = FormatStringGrounder.ground(session)
        collected_tags.extend(fmt_tags)
    except Exception as e:
        logger.debug("Format string grounding skipped: %s", e)

    # 5. Assert macro condition and diagnostic tag inference
    try:
        assert_tags = AssertMacroGrounder.ground(session)
        collected_tags.extend(assert_tags)
    except Exception as e:
        logger.debug("Assert macro grounding skipped: %s", e)

    # 6. Syscall & standard libc semantic propagation
    try:
        syscall_tags = SyscallPropagator.propagate_session(session)
        collected_tags.extend(syscall_tags)
    except Exception as e:
        logger.debug("Syscall propagation skipped: %s", e)

    logger.info("Grounding complete for session %s: %d tags generated", session.session_id, len(collected_tags))
    return collected_tags
