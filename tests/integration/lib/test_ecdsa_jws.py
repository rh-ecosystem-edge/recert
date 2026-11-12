#!/usr/bin/env python3

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ecdsa_jws import der_to_jose, jose_to_der  # noqa: E402


class EcdsaJwsTest(unittest.TestCase):
    def test_roundtrip_preserves_leading_zeroes_and_adds_sign_bytes(self):
        for alg, width in (("ES256", 32), ("ES384", 48)):
            r = b"\x00\x00" + bytes(range(1, width - 1))
            s = b"\xff" * width
            der = jose_to_der(r + s, alg)
            self.assertEqual(der[:2], bytes([0x30, len(der) - 2]))
            self.assertEqual(der[2:4], bytes([0x02, width - 2]))
            self.assertIn(b"\x02" + bytes([width + 1]) + b"\x00\xff", der)
            self.assertEqual(der_to_jose(der, alg), r + s)

    def test_openssl_signature_converts_to_fixed_width(self):
        for alg, curve, digest, width in (
            ("ES256", "prime256v1", "-sha256", 32),
            ("ES384", "secp384r1", "-sha384", 48),
        ):
            with tempfile.NamedTemporaryFile(suffix=".key") as keyfile:
                subprocess.run(
                    ["openssl", "ecparam", "-name", curve, "-genkey", "-noout", "-out", keyfile.name],
                    check=True, capture_output=True,
                )
                der = subprocess.run(
                    ["openssl", "dgst", digest, "-sign", keyfile.name],
                    input=b"data", check=True, capture_output=True,
                ).stdout
            jose = der_to_jose(der, alg)
            self.assertEqual(len(jose), 2 * width)
            self.assertEqual(jose_to_der(jose, alg), der)

    def test_rejects_malformed_der(self):
        valid = jose_to_der(b"\x01" * 32 + b"\x02" * 32, "ES256")
        for bad in (
            b"",
            valid + b"\x00",
            valid[:-1],
            bytes.fromhex("3006020101020100"),          # zero s
            bytes.fromhex("3006020181020101"),          # negative r
            bytes.fromhex("300702020001020101"),        # non-minimal r
            bytes.fromhex("3003020101"),                # missing s
            bytes.fromhex("30050200020101"),            # empty r
            bytes.fromhex("3106020101020101"),          # SET instead of SEQUENCE
            bytes.fromhex("308106020101020101"),        # long-form length
            bytes.fromhex("3009020101020101020101"),    # extra INTEGER
            bytes.fromhex("30250221") + b"\x01" * 33 + bytes.fromhex("020101"),  # r too wide
        ):
            with self.assertRaises(ValueError, msg=bad.hex()):
                der_to_jose(bad, "ES256")

    def test_rejects_bad_jose(self):
        for bad, alg in (
            (b"\x01" * 63, "ES256"),
            (b"\x01" * 64, "ES384"),
            (b"\x00" * 32 + b"\x01" * 32, "ES256"),
            (b"\x01" * 64, "RS256"),
        ):
            with self.assertRaises(ValueError):
                jose_to_der(bad, alg)

    def test_cli_exit_codes(self):
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ecdsa_jws.py")
        jose = b"\x01" * 32 + b"\x02" * 32

        ok = subprocess.run([sys.executable, script, "jose-to-der", "ES256"], input=jose, capture_output=True)
        self.assertEqual(ok.returncode, 0)
        self.assertEqual(ok.stdout, jose_to_der(jose, "ES256"))

        bad_input = subprocess.run([sys.executable, script, "der-to-jose", "ES256"], input=b"\x30", capture_output=True)
        self.assertEqual(bad_input.returncode, 1)
        self.assertEqual(bad_input.stdout, b"")

        usage = subprocess.run([sys.executable, script, "bogus", "ES256"], input=b"", capture_output=True)
        self.assertEqual(usage.returncode, 2)


if __name__ == "__main__":
    unittest.main()
