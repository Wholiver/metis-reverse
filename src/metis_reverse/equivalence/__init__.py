"""
Metis Reverse - Equivalence and Mutation Package
Module providing interactive database mutation, target recompilation sandbox,
and black-box differential testing.
"""

from __future__ import annotations

from metis_reverse.equivalence.differential import (
    DifferentialTester,
)
from metis_reverse.equivalence.mutator import (
    SessionMutator,
    TypeLayoutEngine,
)
from metis_reverse.equivalence.recompilation import (
    CompilationOutput,
    CompilerDiagnostic,
    RecompilationSandbox,
    recompile_and_verify,
)

__all__ = [
    "CompilationOutput",
    "CompilerDiagnostic",
    "DifferentialTester",
    "RecompilationSandbox",
    "SessionMutator",
    "TypeLayoutEngine",
    "recompile_and_verify",
]
