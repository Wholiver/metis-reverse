"""
Unit tests for metis_reverse.backends.tier2_bridge.mock_backend
Validates high-fidelity simulation of disassembly, CFG, decompilation,
symbol/type mutations, call logging, and failure injection.
"""

from __future__ import annotations

import pytest

from metis_reverse.backends.tier2_bridge.mock_backend import MockDecompilerBackend
from metis_reverse.core.models import TargetArtifact


@pytest.fixture
def mock_artifact():
    return TargetArtifact(
        path="/tmp/mock_target",
        architecture="arm64",
        format="MACHO",
        entry_point=0x100003F10,
        size=4096,
    )


class TestMockDecompilerBackend:
    def test_load_artifact_populates_session(self, mock_artifact):
        backend = MockDecompilerBackend()
        session = backend.load_artifact(mock_artifact)

        assert session.session_id.startswith("mock-session-")
        assert session.backend_type == "mock"
        assert len(session.functions) >= 3
        assert 0x100003F10 in session.functions
        assert "main" in session.symbols
        assert backend.has_called("load_artifact", artifact_path=mock_artifact.path)

    def test_disassemble_range_arm64(self, mock_artifact):
        backend = MockDecompilerBackend()
        session = backend.load_artifact(mock_artifact)
        instructions = backend.disassemble_range(session, start_addr=0x100003F10, size=16)

        assert len(instructions) == 4
        assert instructions[0].address == 0x100003F10
        assert instructions[0].mnemonic == "stp"
        assert instructions[0].size == 4
        assert backend.has_called("disassemble_range", start_addr=0x100003F10, size=16)

    def test_get_cfg_structure(self, mock_artifact):
        backend = MockDecompilerBackend()
        session = backend.load_artifact(mock_artifact)
        cfg = backend.get_cfg(session)

        assert "nodes" in cfg
        assert "edges" in cfg
        assert cfg["total_blocks"] >= 4
        assert any(n["function"] == "main" for n in cfg["nodes"])

    def test_decompile_function(self, mock_artifact):
        backend = MockDecompilerBackend()
        session = backend.load_artifact(mock_artifact)
        decomp_result = backend.decompile_function(session, func_addr=0x100003F10)

        assert decomp_result.function_address == 0x100003F10
        assert decomp_result.function_name == "main"
        assert "int main(int argc, char **argv)" in decomp_result.code
        assert "verify_license" in decomp_result.code

    def test_mutate_symbol_cascade(self, mock_artifact):
        backend = MockDecompilerBackend()
        session = backend.load_artifact(mock_artifact)

        # Mutate verify_license -> check_serial
        success = backend.mutate_symbol(session, addr=0x100003E40, new_name="check_serial")
        assert success is True

        # Check function name updated
        fn = session.functions[0x100003E40]
        assert fn.name == "check_serial"

        # Check symbol updated
        assert "check_serial" in session.symbols
        assert "verify_license" not in session.symbols

        # Check cross-function decompile update: main's decompiled code should now call check_serial
        main_fn = session.functions[0x100003F10]
        code_str = (
            main_fn.decompiled_code.source_code
            if hasattr(main_fn.decompiled_code, "source_code")
            else str(main_fn.decompiled_code)
        )
        assert "check_serial(argv[1], 16)" in code_str
        assert "verify_license" not in code_str

        # Check audit log
        assert len(backend.mutations_log) == 1
        assert backend.mutations_log[0]["old_name"] == "verify_license"
        assert backend.mutations_log[0]["new_name"] == "check_serial"

    def test_mutate_type(self, mock_artifact):
        backend = MockDecompilerBackend()
        session = backend.load_artifact(mock_artifact)

        success = backend.mutate_type(session, addr=0x100003E40, new_type="bool")
        assert success is True

        fn = session.functions[0x100003E40]
        assert fn.return_type == "bool"
        code_str = (
            fn.decompiled_code.source_code
            if hasattr(fn.decompiled_code, "source_code")
            else str(fn.decompiled_code)
        )
        assert "bool verify_license" in code_str

    def test_failure_simulation(self, mock_artifact):
        backend = MockDecompilerBackend(fail_addresses={0xDEADBEEF})
        session = backend.load_artifact(mock_artifact)

        with pytest.raises(RuntimeError, match="Decompilation failed"):
            backend.decompile_function(session, func_addr=0xDEADBEEF)

        with pytest.raises(RuntimeError, match="Mock disassembly failure"):
            backend.disassemble_range(session, start_addr=0xDEADBEEF, size=16)

    def test_custom_function_fixture(self, mock_artifact):
        backend = MockDecompilerBackend()
        backend.register_function_fixture(
            address=0x2000,
            name="custom_decrypt",
            decompiled_code="char *custom_decrypt(const char *cipher) { return strdup(cipher); }",
            return_type="char *",
        )
        session = backend.load_artifact(mock_artifact)
        assert 0x2000 in session.functions
        assert session.functions[0x2000].name == "custom_decrypt"
        code = backend.decompile_function(session, func_addr=0x2000)
        assert "custom_decrypt" in code.code
