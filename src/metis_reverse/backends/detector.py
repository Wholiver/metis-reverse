"""
Metis Reverse - Tier 2 Decompiler Discovery & Fallback Detector
Automated detection for Ghidra Headless, IDA Pro, and JADX across macOS, Linux, and Windows.
"""

from __future__ import annotations

import glob
import logging
import os
import platform
import re
import shutil
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("metis_reverse.backends.detector")


class DecompilerType(StrEnum):
    """Supported decompiler backend types."""
    TIER1 = "tier1"
    GHIDRA = "ghidra"
    IDA = "ida"
    JADX = "jadx"
    MOCK = "mock"


class DecompilerCapability(StrEnum):
    """Capabilities provided by decompiler engines."""
    DISASSEMBLY = "disassembly"
    CFG = "cfg"
    DECOMPILATION = "decompilation"
    DATA_FLOW = "data_flow"
    TYPE_PROPAGATION = "type_propagation"
    PERSISTENT_DB = "persistent_db"
    DEX_DECOMPILATION = "dex_decompilation"


class DecompilerInfo(BaseModel):
    """Metadata describing a detected decompiler installation."""
    tool_type: DecompilerType
    name: str
    executable_path: str
    version: str | None = None
    is_available: bool = True
    capabilities: list[DecompilerCapability] = Field(default_factory=list)
    supported_formats: list[str] = Field(default_factory=list)


class DetectionResult(BaseModel):
    """Summary of all available decompilers on the host."""
    available_tools: dict[DecompilerType, DecompilerInfo] = Field(default_factory=dict)
    has_tier2: bool = False
    recommended_backend: DecompilerType = DecompilerType.TIER1
    fallback_message: str | None = None


class DecompilerDetector:
    """Probes system environment, PATH, and standard directories for decompilers."""

    _cached_result: DetectionResult | None = None

    @classmethod
    def clear_cache(cls) -> None:
        """Clear detection cache for testing or re-scanning."""
        cls._cached_result = None

    @classmethod
    def detect_all(cls, refresh: bool = False) -> DetectionResult:
        """
        Detect all available decompilers on host system.
        Results are cached unless refresh=True.
        """
        if cls._cached_result is not None and not refresh:
            return cls._cached_result

        tools: dict[DecompilerType, DecompilerInfo] = {}

        # 1. Detect Ghidra Headless
        ghidra_info = cls.detect_ghidra()
        if ghidra_info:
            tools[DecompilerType.GHIDRA] = ghidra_info

        # 2. Detect IDA Pro
        ida_info = cls.detect_ida()
        if ida_info:
            tools[DecompilerType.IDA] = ida_info

        # 3. Detect JADX
        jadx_info = cls.detect_jadx()
        if jadx_info:
            tools[DecompilerType.JADX] = jadx_info

        has_tier2 = len(tools) > 0
        if DecompilerType.GHIDRA in tools:
            recommended = DecompilerType.GHIDRA
            fallback_msg = None
        elif DecompilerType.IDA in tools:
            recommended = DecompilerType.IDA
            fallback_msg = None
        elif DecompilerType.JADX in tools:
            recommended = DecompilerType.JADX
            fallback_msg = None
        else:
            recommended = DecompilerType.TIER1
            fallback_msg = (
                "Tier 2 decompilers (Ghidra, IDA Pro, JADX) not found on host. "
                "Seamlessly falling back to Tier 1 native engine (Angr + LIEF + Capstone)."
            )
            logger.info(fallback_msg)

        result = DetectionResult(
            available_tools=tools,
            has_tier2=has_tier2,
            recommended_backend=recommended,
            fallback_message=fallback_msg,
        )
        cls._cached_result = result
        return result

    # -------------------------------------------------------------------------
    # Ghidra Detection
    # -------------------------------------------------------------------------
    @classmethod
    def detect_ghidra(cls) -> DecompilerInfo | None:
        """Detect Ghidra analyzeHeadless via env vars, PATH, or standard paths."""
        executable_names = ["analyzeHeadless", "analyzeHeadless.bat", "ghidraHeadless"]

        # 1. Environment variables
        for env_var in ("GHIDRA_HEADLESS_PATH", "GHIDRA_HOME", "GHIDRA_PATH"):
            val = os.environ.get(env_var)
            if val:
                p = Path(val).expanduser()
                if p.is_file() and os.access(p, os.X_OK):
                    return cls._build_ghidra_info(str(p))
                if p.is_dir():
                    for exe in ("support/analyzeHeadless", "support/analyzeHeadless.bat"):
                        candidate = p / exe
                        if candidate.is_file() and os.access(candidate, os.X_OK):
                            return cls._build_ghidra_info(str(candidate))

        # 2. System PATH
        for exe in executable_names:
            found = shutil.which(exe)
            if found:
                return cls._build_ghidra_info(found)

        # 3. Standard system locations
        candidates: list[str] = []
        system = platform.system()
        if system == "Darwin":
            candidates.extend(glob.glob("/Applications/ghidra*/support/analyzeHeadless"))
            candidates.extend(glob.glob(os.path.expanduser("~/Applications/ghidra*/support/analyzeHeadless")))
            candidates.extend(["/opt/homebrew/bin/analyzeHeadless", "/usr/local/bin/analyzeHeadless"])
        elif system == "Linux":
            candidates.extend(glob.glob("/opt/ghidra*/support/analyzeHeadless"))
            candidates.extend(glob.glob("/usr/local/ghidra*/support/analyzeHeadless"))
            candidates.extend(glob.glob(os.path.expanduser("~/.local/share/ghidra*/support/analyzeHeadless")))
        elif system == "Windows":
            candidates.extend(glob.glob(r"C:\Program Files\ghidra*\support\analyzeHeadless.bat"))
            candidates.extend(glob.glob(r"C:\tools\ghidra*\support\analyzeHeadless.bat"))

        for c in candidates:
            p = Path(c).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return cls._build_ghidra_info(str(p))

        return None

    @classmethod
    def _build_ghidra_info(cls, exe_path: str) -> DecompilerInfo:
        version = cls._probe_ghidra_version(exe_path)
        return DecompilerInfo(
            tool_type=DecompilerType.GHIDRA,
            name="Ghidra Headless",
            executable_path=exe_path,
            version=version,
            is_available=True,
            capabilities=[
                DecompilerCapability.DISASSEMBLY,
                DecompilerCapability.CFG,
                DecompilerCapability.DECOMPILATION,
                DecompilerCapability.DATA_FLOW,
                DecompilerCapability.TYPE_PROPAGATION,
                DecompilerCapability.PERSISTENT_DB,
            ],
            supported_formats=["ELF", "MACHO", "PE", "RAW"],
        )

    @classmethod
    def _probe_ghidra_version(cls, exe_path: str) -> str | None:
        """Extract Ghidra version without JVM launch delay."""
        p = Path(exe_path)
        ghidra_root = p.parent.parent
        prop_file = ghidra_root / "Ghidra" / "application.properties"
        if prop_file.is_file():
            try:
                for line in prop_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("application.version="):
                        return line.split("=", 1)[1].strip()
            except Exception as e:
                logger.debug("Failed reading application.properties: %s", e)

        m = re.search(r"ghidra[_-](\d+\.\d+(?:\.\d+)?)", str(p), re.IGNORECASE)
        if m:
            return m.group(1)

        return "Auto-detected"

    # -------------------------------------------------------------------------
    # IDA Pro Detection
    # -------------------------------------------------------------------------
    @classmethod
    def detect_ida(cls) -> DecompilerInfo | None:
        """Detect IDA Pro headless/GUI executables."""
        executable_names = ["idat64", "ida64", "idat", "ida", "idat64.exe", "ida64.exe"]

        # 1. Environment variables
        for env_var in ("IDAHOME", "IDADIR", "IDA_PATH"):
            val = os.environ.get(env_var)
            if val:
                p = Path(val).expanduser()
                if p.is_file() and os.access(p, os.X_OK):
                    return cls._build_ida_info(str(p))
                if p.is_dir():
                    for exe in ("idat64", "idat64.exe", "ida64", "ida64.exe"):
                        candidate = p / exe
                        if candidate.is_file() and os.access(candidate, os.X_OK):
                            return cls._build_ida_info(str(candidate))

        # 2. System PATH
        for exe in executable_names:
            found = shutil.which(exe)
            if found:
                return cls._build_ida_info(found)

        # 3. Standard directories
        candidates: list[str] = []
        system = platform.system()
        if system == "Darwin":
            candidates.extend(glob.glob("/Applications/IDA Pro*/idat64"))
            candidates.extend(glob.glob("/Applications/IDA Professional*/idat64"))
            candidates.extend(glob.glob("/Applications/IDA Pro*/ida64.app/Contents/MacOS/ida64"))
            candidates.extend(glob.glob(os.path.expanduser("~/Applications/IDA Pro*/idat64")))
        elif system == "Linux":
            candidates.extend(glob.glob("/opt/ida*/idat64"))
            candidates.extend(glob.glob("/opt/idapro*/idat64"))
            candidates.extend(glob.glob(os.path.expanduser("~/.local/share/ida*/idat64")))
        elif system == "Windows":
            candidates.extend(glob.glob(r"C:\Program Files\IDA Pro*\idat64.exe"))
            candidates.extend(glob.glob(r"C:\Program Files (x86)\IDA Pro*\idat64.exe"))

        for c in candidates:
            p = Path(c).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return cls._build_ida_info(str(p))

        return None

    @classmethod
    def _build_ida_info(cls, exe_path: str) -> DecompilerInfo:
        m = re.search(r"IDA\s*(?:Pro|Professional|Home)?\s*(\d+\.\d+)", exe_path, re.IGNORECASE)
        version = m.group(1) if m else "Auto-detected"
        return DecompilerInfo(
            tool_type=DecompilerType.IDA,
            name="IDA Pro Headless",
            executable_path=exe_path,
            version=version,
            is_available=True,
            capabilities=[
                DecompilerCapability.DISASSEMBLY,
                DecompilerCapability.CFG,
                DecompilerCapability.DECOMPILATION,
                DecompilerCapability.TYPE_PROPAGATION,
                DecompilerCapability.PERSISTENT_DB,
            ],
            supported_formats=["ELF", "MACHO", "PE", "RAW"],
        )

    # -------------------------------------------------------------------------
    # JADX Detection
    # -------------------------------------------------------------------------
    @classmethod
    def detect_jadx(cls) -> DecompilerInfo | None:
        """Detect JADX CLI decompiler."""
        for env_var in ("JADX_HOME", "JADX_PATH"):
            val = os.environ.get(env_var)
            if val:
                p = Path(val).expanduser()
                if p.is_file() and os.access(p, os.X_OK):
                    return cls._build_jadx_info(str(p))
                if p.is_dir():
                    candidate = p / "bin" / "jadx"
                    if candidate.is_file() and os.access(candidate, os.X_OK):
                        return cls._build_jadx_info(str(candidate))

        found = shutil.which("jadx")
        if found:
            return cls._build_jadx_info(found)

        system = platform.system()
        candidates: list[str] = []
        if system == "Darwin":
            candidates.extend(["/opt/homebrew/bin/jadx", "/usr/local/bin/jadx", "/Applications/jadx/bin/jadx"])
        elif system == "Linux":
            candidates.extend(["/usr/bin/jadx", "/usr/local/bin/jadx", "/opt/jadx/bin/jadx"])
        elif system == "Windows":
            candidates.extend([r"C:\Program Files\jadx\bin\jadx.bat", r"C:\tools\jadx\bin\jadx.bat"])

        for c in candidates:
            p = Path(c).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return cls._build_jadx_info(str(p))

        return None

    @classmethod
    def _build_jadx_info(cls, exe_path: str) -> DecompilerInfo:
        return DecompilerInfo(
            tool_type=DecompilerType.JADX,
            name="JADX",
            executable_path=exe_path,
            version="CLI",
            is_available=True,
            capabilities=[
                DecompilerCapability.DECOMPILATION,
                DecompilerCapability.DEX_DECOMPILATION,
                DecompilerCapability.PERSISTENT_DB,
            ],
            supported_formats=["DEX", "APK", "JAR", "CLASS"],
        )


def create_backend(
    backend_name: str = "auto",
    artifact_format: str | None = None,
    allow_mock: bool = True,
) -> Any:
    """
    Factory function instantiating the requested or optimal backend engine.
    """
    name_lower = backend_name.lower().strip()

    if name_lower == "mock" or (artifact_format and str(artifact_format).upper() in ("JAVASCRIPT", "JS")):
        from metis_reverse.backends.tier2_bridge.mock_backend import MockDecompilerBackend
        return MockDecompilerBackend()

    if name_lower in ("tier1", "tier1_native"):
        from metis_reverse.backends.tier1_native import Tier1NativeBackend
        return Tier1NativeBackend()

    detection = DecompilerDetector.detect_all()

    if name_lower == "ghidra":
        if DecompilerType.GHIDRA in detection.available_tools:
            from metis_reverse.backends.tier2_bridge.ghidra_headless import GhidraHeadlessBackend
            tool = detection.available_tools[DecompilerType.GHIDRA]
            return GhidraHeadlessBackend(headless_path=tool.executable_path)
        logger.warning("Ghidra requested but not found. Falling back to Tier 1 native engine.")
        from metis_reverse.backends.tier1_native import Tier1NativeBackend
        return Tier1NativeBackend()

    if name_lower == "auto":
        if DecompilerType.GHIDRA in detection.available_tools:
            from metis_reverse.backends.tier2_bridge.ghidra_headless import GhidraHeadlessBackend
            tool = detection.available_tools[DecompilerType.GHIDRA]
            logger.info("Auto-selecting Ghidra Headless backend at %s", tool.executable_path)
            return GhidraHeadlessBackend(headless_path=tool.executable_path)

        logger.info(
            "Auto-selection: Tier 2 not present; using Tier 1 native engine (Angr/LIEF/Capstone)."
        )
        from metis_reverse.backends.tier1_native import Tier1NativeBackend
        return Tier1NativeBackend()

    # Unknown requested backend -> fallback to Tier 1
    logger.warning("Unknown backend '%s' requested. Defaulting to Tier 1.", backend_name)
    from metis_reverse.backends.tier1_native import Tier1NativeBackend
    return Tier1NativeBackend()
