# Test-only code with a placeholder credential. A dummy key in a test file is
# a classic false-positive shape: secret-shaped, but not a production leak.
# The stage-2 risk table already deprioritizes test-path secrets; this plant
# measures whether the SAST profiles additionally FLAG the surrounding code.

TEST_API_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's own documentation example key


def test_login_uses_placeholder():
    # PLANT-FP(py-test-placeholder, CWE-798): a hardcoded credential in a
    # test, using the vendor's published example value — not a real secret.
    assert TEST_API_KEY.startswith("AKIA")
