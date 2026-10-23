"""Configuration settings for Metis Reverse."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

def _find_default_ghidra() -> str:
    env_dir = os.getenv("GHIDRA_INSTALL_DIR", "")
    if env_dir and Path(env_dir).exists():
        return env_dir
    local_env = Path.home() / ".local" / "share" / "metis_env"
    candidates = sorted(local_env.glob("ghidra*"), reverse=True) + [local_env / "ghidra"]
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "support" / "analyzeHeadless").is_file():
            return str(candidate)
    return ""

def _ensure_java_env() -> None:
    # 1. Auto-link self-contained Temurin JDK
    temurin_home = Path.home() / ".local" / "share" / "metis_env" / "jdk-21" / "Contents" / "Home"
    if temurin_home.exists():
        os.environ["JAVA_HOME"] = str(temurin_home)
        java_bin = str(temurin_home / "bin")
        paths = [p for p in os.environ.get("PATH", "").split(":") if p and p != java_bin]
        os.environ["PATH"] = f"{java_bin}:{':'.join(paths)}"

    # 2. Auto-link .NET root & tools
    dotnet_root = Path.home() / ".dotnet"
    if dotnet_root.exists():
        os.environ["DOTNET_ROOT"] = str(dotnet_root)
        dotnet_tools = str(dotnet_root / "tools")
        paths = [p for p in os.environ.get("PATH", "").split(":") if p]
        if dotnet_tools not in paths:
            paths.insert(0, dotnet_tools)
        if str(dotnet_root) not in paths:
            paths.insert(0, str(dotnet_root))
        os.environ["PATH"] = ":".join(paths)

    # 3. Ensure ~/.local/bin and Homebrew bin are in PATH
    local_bin = str(Path.home() / ".local" / "bin")
    brew_bin = "/Users/huchenrui/homebrew/bin"
    current_paths = [p for p in os.environ.get("PATH", "").split(":") if p]
    for b in [local_bin, brew_bin]:
        if b not in current_paths:
            current_paths.insert(0, b)
    os.environ["PATH"] = ":".join(current_paths)

    # 4. Ensure libmagic is discoverable for unblob
    brew_lib = "/Users/huchenrui/homebrew/lib"
    dyld = os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "")
    if brew_lib not in dyld.split(":"):
        os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = f"{brew_lib}:{dyld}" if dyld else brew_lib

@dataclass
class MetisConfig:
    """Metis runtime configuration."""
    ghidra_install_dir: str = field(
        default_factory=_find_default_ghidra
    )
    sidecar_dir: Path = field(
        default_factory=lambda: Path(os.getenv("METIS_SIDECAR_DIR", ".metis_sidecars"))
    )
    sandbox_timeout_seconds: float = 5.0
    sandbox_max_memory_mb: int = 128
    enable_prompt_shield: bool = True
    prefer_headless_ghidra: bool = True
    auto_create_dirs: bool = True

    def __post_init__(self):
        _ensure_java_env()
        if self.auto_create_dirs and not self.sidecar_dir.exists():
            self.sidecar_dir.mkdir(parents=True, exist_ok=True)

    @property
    def has_ghidra(self) -> bool:
        if not self.ghidra_install_dir:
            return False
        path = Path(self.ghidra_install_dir)
        # Check standard Ghidra headless launcher
        launcher_unix = path / "support" / "analyzeHeadless"
        launcher_win = path / "support" / "analyzeHeadless.bat"
        return launcher_unix.is_file() or launcher_win.is_file()

    @classmethod
    def check_ghidra_version(cls, install_dir: Optional[str] = None, min_version: str = "12.1.1") -> Dict[str, Any]:
        """Validates that installed Ghidra satisfies the minimum version baseline (>= 12.1.1).
        
        Reads Ghidra/application.properties directly from the installation directory.
        """
        dir_to_check = install_dir or _find_default_ghidra()
        if not dir_to_check:
            return {
                "installed": False,
                "version": None,
                "required_version": f">= {min_version}",
                "status": "not_installed",
                "message": "Ghidra installation directory not found. Native fallback engine will be used.",
            }
        
        props_path = Path(dir_to_check) / "Ghidra" / "application.properties"
        if not props_path.is_file():
            # Check root
            props_path = Path(dir_to_check) / "application.properties"
        
        version_str = "0.0.0"
        if props_path.is_file():
            try:
                for line in props_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("application.version="):
                        version_str = line.split("=", 1)[1].strip()
                        break
            except Exception:
                pass

        def _ver_tuple(v: str) -> tuple:
            parts = []
            for p in v.split(".")[:3]:
                digits = "".join(c for c in p if c.isdigit())
                parts.append(int(digits) if digits else 0)
            while len(parts) < 3:
                parts.append(0)
            return tuple(parts)

        is_supported = _ver_tuple(version_str) >= _ver_tuple(min_version)
        req_ver_str = f">= {min_version}"
        return {
            "installed": True,
            "version": version_str,
            "required_version": req_ver_str,
            "is_supported": is_supported,
            "status": "valid" if is_supported else "version_rejected",
            "message": (
                f"Ghidra {version_str} is compatible ({req_ver_str})"
                if is_supported else
                f"Ghidra version {version_str} is below required baseline {min_version}. Native fallback will be engaged."
            ),
        }

def load_config() -> MetisConfig:
    return MetisConfig()
