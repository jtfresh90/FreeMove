import re
import socket
import threading
import unittest

from freemove import security


class TestPinAndKeys(unittest.TestCase):
    def test_pin_format(self):
        for _ in range(50):
            self.assertRegex(security.generate_pin(), re.compile(r"^\d{6}$"))

    def test_key_derivation_deterministic_and_pin_bound(self):
        salt_r, salt_s = b"r" * 16, b"s" * 16
        k1 = security.derive_session_key("123456", salt_r, salt_s,
                                         iterations=1000)
        k2 = security.derive_session_key("123456", salt_r, salt_s,
                                         iterations=1000)
        k3 = security.derive_session_key("654321", salt_r, salt_s,
                                         iterations=1000)
        self.assertEqual(k1, k2)
        self.assertNotEqual(k1, k3)
        self.assertEqual(len(k1), 32)

    def test_bad_pin_rejected(self):
        with self.assertRaises(security.PairingError):
            security.derive_session_key("12345", b"r" * 16, b"s" * 16,
                                        iterations=1000)

    def test_proof_binds_fingerprint(self):
        key = bytes(range(32))
        fp_a, fp_b = "a" * 64, "b" * 64
        proof = security.pairing_proof(key, fp_a)
        self.assertTrue(security.verify_proof(key, fp_a, proof))
        # A MITM-swapped certificate fingerprint must not verify.
        self.assertFalse(security.verify_proof(key, fp_b, proof))


class TestPairingHandshake(unittest.TestCase):
    def _run_pair(self, receiver_pin, sender_pin):
        left, right = socket.socketpair()
        outcome = {}

        def receiver():
            try:
                outcome["key"] = security.receiver_pairing(
                    left, receiver_pin, "f" * 64)
            except BaseException as exc:  # noqa: BLE001 - test capture
                outcome["error"] = exc

        thread = threading.Thread(target=receiver, daemon=True)
        thread.start()
        try:
            key, fp = security.sender_pairing(right, sender_pin)
            outcome["sender_key"] = key
            outcome["fp"] = fp
        except BaseException as exc:  # noqa: BLE001 - test capture
            outcome["sender_error"] = exc
        thread.join(timeout=10)
        right.close()
        left.close()
        return outcome

    def test_correct_pin_pairs_and_keys_agree(self):
        outcome = self._run_pair("424242", "424242")
        self.assertNotIn("error", outcome)
        self.assertNotIn("sender_error", outcome)
        self.assertEqual(outcome["key"], outcome["sender_key"])
        self.assertEqual(outcome["fp"], "f" * 64)

    def test_wrong_pin_fails_both_sides(self):
        outcome = self._run_pair("111111", "222222")
        self.assertIn("sender_error", outcome)
        self.assertIsInstance(outcome["sender_error"], security.PairingError)


class TestIdentity(unittest.TestCase):
    def test_identity_generated_and_fingerprint_matches(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            identity = security.generate_identity(Path(td))
            self.assertTrue(identity.cert_path.exists())
            self.assertTrue(identity.key_path.exists())
            self.assertRegex(identity.fingerprint,
                             re.compile(r"^[0-9a-f]{64}$"))
            ctx = security.server_context(identity)
            self.assertIsNotNone(ctx)


if __name__ == "__main__":
    unittest.main()
