"""End-to-end loopback tests: transfer, resume, tamper detection."""

import random
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from freemove import protocol
from freemove.client import Sender
from freemove.collector import expand_selection
from freemove.server import PARTIAL_DIRNAME, Receiver

BIG_SIZE = 3 * 1024 * 1024


def make_tree(base: Path) -> dict[str, bytes]:
    rng = random.Random(20261030)
    contents = {
        "big.bin": rng.randbytes(BIG_SIZE),
        "hello.txt": b"hello from the old PC\n" * 40,
        "empty.txt": b"",
        "nested/deep.bin": rng.randbytes(200_000),
        "nested/notes.md": b"# migrated notes\n" * 25,
    }
    for rel, data in contents.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return contents


def start_receiver(dest: Path) -> tuple[Receiver, threading.Thread]:
    receiver = Receiver(dest, host="127.0.0.1", port=0)
    receiver.prepare()
    thread = threading.Thread(target=receiver.serve_once, daemon=True)
    thread.start()
    return receiver, thread


class LoopbackBase(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        root = Path(self._tmp.name)
        self.src = root / "src"
        self.dest = root / "dest"
        self.src.mkdir()
        self.contents = make_tree(self.src)
        self.entries = expand_selection([(self.src, "data")])

    def tearDown(self):
        self._tmp.cleanup()

    def assert_tree_identical(self):
        for rel, data in self.contents.items():
            placed = self.dest / "data" / rel
            self.assertTrue(placed.is_file(), f"missing {rel}")
            self.assertEqual(placed.read_bytes(), data, f"corrupt {rel}")


class TestEndToEnd(LoopbackBase):
    def test_loopback_transfer_byte_identical_and_verified(self):
        receiver, thread = start_receiver(self.dest)
        report = Sender().send("127.0.0.1", receiver.port, receiver.pin,
                               self.entries)
        thread.join(timeout=30)
        self.assertIsNone(receiver.error)
        self.assertTrue(report["verified"])
        self.assertEqual(len(report["received"]), len(self.contents))
        self.assert_tree_identical()
        reports = list(self.dest.glob("freemove-report-*.json"))
        self.assertEqual(len(reports), 1)


class TestResume(LoopbackBase):
    def _dropped_first_attempt(self) -> Path:
        receiver, thread = start_receiver(self.dest)
        with self.assertRaises(ConnectionError):
            Sender().send("127.0.0.1", receiver.port, receiver.pin,
                          self.entries, simulate_drop_after_bytes=1_000_000)
        thread.join(timeout=30)
        self.assertIsNotNone(receiver.error)
        partial = (self.dest / PARTIAL_DIRNAME / "data" / "big.bin.part")
        self.assertTrue(partial.is_file())
        size = partial.stat().st_size
        self.assertGreater(size, 0)
        self.assertLess(size, BIG_SIZE)
        return partial

    def test_resume_after_drop_completes_and_sends_less(self):
        self._dropped_first_attempt()
        receiver2, thread2 = start_receiver(self.dest)
        sender2 = Sender()
        report = sender2.send("127.0.0.1", receiver2.port, receiver2.pin,
                              self.entries)
        thread2.join(timeout=30)
        self.assertIsNone(receiver2.error)
        self.assertTrue(report["verified"])
        self.assert_tree_identical()
        total = sum(e.size for e in self.entries)
        # The resumed send must not re-send the bytes already received.
        self.assertLess(sender2.bytes_sent, total)

    def test_tampered_partial_fails_verification_loudly(self):
        partial = self._dropped_first_attempt()
        data = bytearray(partial.read_bytes())
        data[10] ^= 0xFF  # flip one byte in the stored partial data
        partial.write_bytes(bytes(data))

        receiver2, thread2 = start_receiver(self.dest)
        with self.assertRaises(Exception):
            Sender().send("127.0.0.1", receiver2.port, receiver2.pin,
                          self.entries)
        thread2.join(timeout=30)
        self.assertIsInstance(receiver2.error, protocol.VerificationError)
        # The tampered file must never have been placed.
        self.assertFalse((self.dest / "data" / "big.bin").exists())


if __name__ == "__main__":
    unittest.main()
