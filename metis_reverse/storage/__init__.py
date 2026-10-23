"""Storage models and sidecar manager for persistent, decoupled reverse engineering annotations."""

from .models import (
    EvidencePointer,
    VariableAnnotation,
    StructField,
    StructDefinition,
    FunctionAnnotation,
    SidecarDatabase,
)
from .sidecar_store import SidecarStore

__all__ = [
    "EvidencePointer",
    "VariableAnnotation",
    "StructField",
    "StructDefinition",
    "FunctionAnnotation",
    "SidecarDatabase",
    "SidecarStore",
]
