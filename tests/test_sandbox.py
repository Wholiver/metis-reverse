"""Tests for HypothesisSandbox verifying decryption and algorithm hypotheses."""

from metis_reverse.security.sandbox import HypothesisSandbox

def test_sandbox_xor_decryption_verification():
    sandbox = HypothesisSandbox()

    # Original plaintext = "SECRET_C2_URL"
    key = 0x5A
    encrypted_bytes = bytes([b ^ key for b in b"SECRET_C2_URL"])

    script = """
def verify(data):
    # Agent tests XOR key 0x5a
    return bytes([b ^ 0x5a for b in data]).decode('utf-8')
"""

    res = sandbox.execute_script(
        script_code=script,
        memory_slice=encrypted_bytes,
        expected_output="SECRET_C2_URL",
        va="0x140004000"
    )

    assert res["success"] is True
    assert res["hypothesis_confirmed"] is True
    assert res["returned_value"] == "SECRET_C2_URL"
    assert res["error"] is None

def test_sandbox_blocks_dangerous_operations():
    sandbox = HypothesisSandbox()

    dangerous_script = """
import os
os.system("echo hacked")
"""

    res = sandbox.execute_script(
        script_code=dangerous_script,
        memory_slice=b"data",
        va="0x140004000"
    )

    assert res["success"] is False
    assert res["error"] is not None

def test_sandbox_timeout_guard():
    sandbox = HypothesisSandbox(timeout_seconds=0.5)

    infinite_loop_script = """
while True:
    pass
"""

    res = sandbox.execute_script(
        script_code=infinite_loop_script,
        memory_slice=b"data",
        va="0x140004000"
    )

    assert res["success"] is False
    assert "timed out" in res["error"].lower()
