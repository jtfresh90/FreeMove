import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from freemove import apps, protocol

FIXTURE_ENTRIES = [
    {
        "DisplayName": "Widget Studio",
        "DisplayVersion": "4.2",
        "Publisher": "WidgetCo",
        "InstallLocation": "C:\\Program Files\\Widget Studio",
        "UninstallString": "C:\\Program Files\\Widget Studio\\uninstall.exe",
        "ProductKey": "WIDGT-12345-ABCDE-67890",
        "__registry_path__": "HKLM\\Software\\Microsoft\\Windows\\"
                             "CurrentVersion\\Uninstall\\WidgetStudio",
    },
    {  # the same app seen through the 32-bit registry view: deduped
        "DisplayName": "Widget Studio",
        "DisplayVersion": "4.2",
        "Publisher": "WidgetCo",
        "InstallLocation": "C:\\Program Files\\Widget Studio",
        "__registry_path__": "HKLM\\Software\\Microsoft\\Windows\\"
                             "CurrentVersion\\Uninstall\\WidgetStudio",
    },
    {
        "DisplayName": "Plain Tool",
        "DisplayVersion": "1.0",
        "Publisher": "",
        "InstallLocation": "",
        "__registry_path__": "HKCU\\Software\\Microsoft\\Windows\\"
                             "CurrentVersion\\Uninstall\\PlainTool",
    },
    {"DisplayVersion": "9.9"},  # no DisplayName: skipped
]


class TestInventory(unittest.TestCase):
    def test_inventory_dedupes_and_skips_nameless(self):
        reader = apps.FakeRegistryReader(FIXTURE_ENTRIES)
        found = apps.list_installed_apps(reader)
        self.assertEqual([a.name for a in found],
                         ["Plain Tool", "Widget Studio"])
        widget = found[1]
        self.assertEqual(widget.version, "4.2")
        self.assertEqual(widget.publisher, "WidgetCo")

    def test_scan_and_export_program_keys(self):
        reader = apps.FakeRegistryReader(FIXTURE_ENTRIES)
        keys = apps.scan_program_keys(apps.list_installed_apps(reader))
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].app, "Widget Studio")
        self.assertEqual(keys[0].key, "WIDGT-12345-ABCDE-67890")
        with TemporaryDirectory() as td:
            out = apps.export_keys_report(keys, Path(td) / "keys.txt")
            self.assertIn("WIDGT-12345-ABCDE-67890",
                          out.read_text(encoding="utf-8"))


def make_app_dir(base: Path) -> Path:
    app_dir = base / "WidgetApp"
    (app_dir / "bin").mkdir(parents=True)
    (app_dir / "bin" / "widget.exe").write_bytes(b"MZ" + b"\x90" * 500)
    (app_dir / "data.db").write_bytes(b"sqlite-ish" * 100)
    (app_dir / "bin" / "config.ini").write_text("[widget]\nport=9\n")
    return app_dir


class TestLocalMove(unittest.TestCase):
    def test_move_verifies_and_links_original_path(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            source = make_app_dir(root / "driveC")
            result = apps.local_move_app(source, root / "driveD")
            target = root / "driveD" / "WidgetApp"
            self.assertTrue(result.verified)
            self.assertTrue(target.is_dir())
            # Original path still resolves to the app's files
            # (junction on Windows, symlink stand-in on POSIX).
            self.assertTrue(source.is_symlink() or source.is_dir())
            self.assertEqual((source / "data.db").read_bytes(),
                             b"sqlite-ish" * 100)
            self.assertTrue(apps.verify_tree(target, target))

    def test_verification_failure_leaves_original_untouched(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            source = make_app_dir(root / "driveC")
            with self.assertRaises(protocol.VerificationError):
                apps.local_move_app(source, root / "driveD",
                                    verify_fn=lambda s, t: False)
            self.assertTrue(source.is_dir())
            self.assertFalse(source.is_symlink())
            self.assertEqual((source / "data.db").read_bytes(),
                             b"sqlite-ish" * 100)
            self.assertFalse((root / "driveD" / "WidgetApp").exists())

    def test_junction_failure_rolls_back_original(self):
        with TemporaryDirectory() as td:
            root = Path(td)
            source = make_app_dir(root / "driveC")

            def boom(link, target):
                raise OSError("junction creation failed")

            with self.assertRaises(OSError):
                apps.local_move_app(source, root / "driveD",
                                    junction_fn=boom)
            self.assertTrue(source.is_dir())
            self.assertFalse(source.is_symlink())
            self.assertEqual((source / "bin" / "config.ini").read_text(),
                             "[widget]\nport=9\n")


class TestCollectorSelection(unittest.TestCase):
    def test_standard_selection_and_expansion(self):
        from freemove import collector
        with TemporaryDirectory() as td:
            home = Path(td)
            (home / "Documents").mkdir()
            (home / "Documents" / "letter.txt").write_text("dear diary")
            (home / "Downloads").mkdir()
            items = collector.standard_selection(
                include_profile=True, include_browsers=False,
                include_mail=False, home=home)
            prefixes = {prefix for _src, prefix in items}
            self.assertIn("profile/Documents", prefixes)
            entries = collector.expand_selection(items)
            paths = [e.path for e in entries]
            self.assertIn("profile/Documents/letter.txt", paths)


class TestDiscovery(unittest.TestCase):
    def test_unicast_discovery_finds_service(self):
        import socket as _socket
        # Some sandboxes (including this dev box) forbid UDP sends at
        # the syscall level, even on loopback.  Probe first and skip
        # honestly there; on normal networks and the Windows CI
        # runner this test exercises the real query/reply path.
        probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        try:
            probe.sendto(b"probe", ("127.0.0.1", 9))
        except PermissionError:
            self.skipTest("UDP sends are blocked in this environment")
        finally:
            probe.close()
        from freemove import discovery
        service = discovery.DiscoveryService(transfer_port=40120,
                                             fingerprint="ab12")
        service.start()
        try:
            peers = discovery.discover(
                timeout=3.0,
                targets=[("127.0.0.1", discovery.DISCOVERY_PORT)])
        finally:
            service.stop()
        self.assertTrue(any(p.host == "127.0.0.1" and p.port == 40120
                            for p in peers))


if __name__ == "__main__":
    unittest.main()
