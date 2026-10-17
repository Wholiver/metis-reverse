"""
Unit tests for metis_reverse.backends.detector
Validates environment variable resolution, PATH lookup, standard path globbing,
and seamless fallback to Tier 1 native engine.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from metis_reverse.backends.detector import (
    DecompilerCapability,
    DecompilerDetector,
    DecompilerInfo,
    DecompilerType,
    create_backend,
)
from metis_reverse.core.models import TargetArtifact


@pytest.fixture(autouse=True)
def reset_detector_cache():
    """Ensure clean detector state for each test."""
    DecompilerDetector.clear_cache()
    yield
    DecompilerDetector.clear_cache()


class TestDecompilerDetector:
    def test_decompiler_type_values(self):
        assert DecompilerType.GHIDRA.value == "ghidra"
        assert DecompilerType.IDA.value == "ida"
        assert DecompilerType.JADX.value == "jadx"
        assert DecompilerType.TIER1.value == "tier1"
        assert DecompilerType.MOCK.value == "mock"

    def test_decompiler_info_model_serialization(self):
        info = DecompilerInfo(
            tool_type=DecompilerType.GHIDRA,
            name="Ghidra Headless",
            executable_path="/opt/ghidra/support/analyzeHeadless",
            version="11.1.2",
            capabilities=[DecompilerCapability.DECOMPILATION, DecompilerCapability.CFG],
            supported_formats=["ELF", "MACHO"],
        )
        data = info.model_dump()
        assert data["tool_type"] == "ghidra"
        assert data["version"] == "11.1.2"
        assert "decompilation" in data["capabilities"]

    @patch.dict(os.environ, {"GHIDRA_HOME": "/opt/ghidra"})
    @patch("pathlib.Path.is_file", return_value=True)
    @patch("os.access", return_value=True)
    def test_detect_ghidra_from_env_var(self, mock_access, mock_is_file):
        info = DecompilerDetector.detect_ghidra()
        assert info is not None
        assert info.tool_type == DecompilerType.GHIDRA
        assert "/opt/ghidra" in info.executable_path

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which")
    def test_detect_ghidra_from_path(self, mock_which):
        mock_which.side_effect = lambda x: "/usr/local/bin/analyzeHeadless" if x == "analyzeHeadless" else None
        info = DecompilerDetector.detect_ghidra()
        assert info is not None
        assert info.executable_path == "/usr/local/bin/analyzeHeadless"
        assert info.tool_type == DecompilerType.GHIDRA

    @patch.dict(os.environ, {"IDADIR": "/opt/ida"})
    @patch("pathlib.Path.is_file", return_value=True)
    @patch("os.access", return_value=True)
    def test_detect_ida_from_env_var(self, mock_access, mock_is_file):
        info = DecompilerDetector.detect_ida()
        assert info is not None
        assert info.tool_type == DecompilerType.IDA
        assert "/opt/ida" in info.executable_path

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which")
    def test_detect_ida_from_path(self, mock_which):
        mock_which.side_effect = lambda x: "/usr/bin/idat64" if x == "idat64" else None
        info = DecompilerDetector.detect_ida()
        assert info is not None
        assert info.executable_path == "/usr/bin/idat64"
        assert info.tool_type == DecompilerType.IDA

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which")
    def test_detect_jadx_from_path(self, mock_which):
        mock_which.side_effect = lambda x: "/usr/local/bin/jadx" if x == "jadx" else None
        info = DecompilerDetector.detect_jadx()
        assert info is not None
        assert info.tool_type == DecompilerType.JADX
        assert info.executable_path == "/usr/local/bin/jadx"

    @patch.dict(os.environ, {}, clear=True)
    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file", return_value=False)
    def test_detect_all_when_none_installed(self, mock_is_file, mock_which):
        result = DecompilerDetector.detect_all(refresh=True)
        assert result.has_tier2 is False
        assert result.recommended_backend == DecompilerType.TIER1
        assert len(result.available_tools) == 0
        assert result.fallback_message is not None
        assert "Tier 1 native engine" in result.fallback_message

    def test_create_backend_explicit_mock(self):
        backend = create_backend(backend_name="mock")
        from metis_reverse.backends.tier2_bridge.mock_backend import MockDecompilerBackend
        assert isinstance(backend, MockDecompilerBackend)

    @patch("metis_reverse.backends.detector.DecompilerDetector.detect_all")
    def test_create_backend_auto_fallback(self, mock_detect_all):
        from metis_reverse.backends.detector import DetectionResult
        mock_detect_all.return_value = DetectionResult(
            available_tools={},
            has_tier2=False,
            recommended_backend=DecompilerType.TIER1,
        )
        TargetArtifact(
            path="/tmp/test.bin",
            architecture="arm64",
            format="MACHO",
            entry_point=0x1000,
            size=1024,
        )
        backend = create_backend(backend_name="auto", artifact_format="MACHO")
        assert backend is not None
