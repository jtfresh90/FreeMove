import io
import json
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from freemove import archive, protocol
from freemove.collector import expand_selection


def make_entries(base: Path):
    (base / "docs").mkdir(parents=True)
    (base / "docs" / "a.txt").write_bytes(b"alpha" * 100)
    (base / "b.bin").write_bytes(bytes(range(256)) * 64)
    return expand_selection([(base, "data")])


class TestArchiveRoundTrip(unittest.TestCase):
    def test_export_import_roundtrip_verified(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            entries = make_entries(src)
            image = root / "move.fmimg"
            report = archive.export_image(entries, image)
            self.assertFalse(report.encrypted)
            out = root / "out"
            result = archive.import_image(image, out)
            self.assertEqual(sorted(result.placed),
                             sorted(e.path for e in entries))
            for entry in entries:
                placed = out / entry.path
                self.assertEqual(
                    protocol.sha256_file(placed), entry.sha256)

    def test_tampered_image_rejected(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            entries = make_entries(src)
            image = root / "move.fmimg"
            archive.export_image(entries, image)
            # Rewrite the image with one file's bytes altered but the
            # original manifest kept: import must catch the mismatch.
            with zipfile.ZipFile(image) as zf:
                manifest = zf.read("manifest.json")
                payload = {name: zf.read(name) for name in zf.namelist()}
            payload["files/data/docs/a.txt"] = b"tampered!"
            tampered = root / "tampered.fmimg"
            with zipfile.ZipFile(tampered, "w") as zf:
                for name, data in payload.items():
                    zf.writestr(name, data)
            with self.assertRaises(protocol.VerificationError):
                archive.import_image(tampered, root / "out")


@unittest.skipUnless(archive.crypto_available(),
                     "cryptography package not installed")
class TestArchiveEncryption(unittest.TestCase):
    def test_encrypted_roundtrip_and_wrong_passphrase(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            entries = make_entries(src)
            image = root / "secret.fmimg"
            report = archive.export_image(entries, image,
                                          passphrase="hunter2-correct")
            self.assertTrue(report.encrypted)
            self.assertTrue(image.read_bytes().startswith(archive.MAGIC))
            result = archive.import_image(image, root / "out",
                                          passphrase="hunter2-correct")
            self.assertTrue(result.encrypted)
            self.assertEqual(len(result.placed), len(entries))
            with self.assertRaises(Exception):
                archive.import_image(image, root / "out2",
                                     passphrase="wrong-passphrase")


class TestMissingCryptoHonesty(unittest.TestCase):
    def test_unencrypted_export_is_plain_zip_with_manifest(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            entries = make_entries(src)
            image = root / "plain.fmimg"
            archive.export_image(entries, image)
            with zipfile.ZipFile(image) as zf:
                manifest = json.loads(zf.read("manifest.json"))
            self.assertEqual(len(manifest["files"]), len(entries))


if __name__ == "__main__":
    unittest.main()
