"""Installed-application inventory, bundles and local moves.

Honesty note: no migration tool can guarantee an arbitrary installed
program survives being copied to another PC — services, drivers,
shell extensions, licensing and DRM all tie apps to the machine.
What FreeMove does is the same thing the commercial tools do, done
carefully:

* **Inventory** — enumerate the registry Uninstall keys (both 64-bit
  and 32-bit views, HKLM and HKCU).
* **Transfer bundle** — the app's install directory, its matching
  AppData folders, and its exported registry keys (``.reg`` files),
  so common self-contained apps arrive ready to run.
* **Local move** — move an app's folder to another drive on the *same*
  PC, verify the copy hash-for-hash, then replace the original path
  with an NTFS junction so the app (and every shortcut/registry entry
  pointing at the old path) keeps working while the space is freed.
  Any failure rolls back to the untouched original.
* **Program keys scan** — export license keys/serials that apps store
  in plain registry values under their own keys.  Keys that live in
  encrypted blobs or vendor clouds cannot be recovered by any tool;
  FreeMove reports what is actually there and nothing more.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import collector, protocol

IS_WINDOWS = os.name == "nt"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"

# Registry value names under which apps commonly store a license key
# in plain text.
KEY_VALUE_NAMES = (
    "ProductKey", "SerialNumber", "Serial", "LicenseKey",
    "CDKey", "Key", "RegistrationKey", "ActivationKey",
)


@dataclass
class InstalledApp:
    name: str
    version: str = ""
    publisher: str = ""
    install_location: str = ""
    uninstall_string: str = ""
    registry_path: str = ""       # full key path, e.g. HKLM\...\Uninstall\X
    values: dict = field(default_factory=dict)  # all raw values of the key

    def label(self) -> str:
        ver = f" {self.version}" if self.version else ""
        return f"{self.name}{ver}"


# --------------------------------------------------------------------------
# Registry readers (winreg on Windows; fixtures in tests)
# --------------------------------------------------------------------------

class FakeRegistryReader:
    """In-memory reader used by tests and non-Windows dry runs."""

    def __init__(self, entries: list[dict]):
        self._entries = entries

    def iter_uninstall_entries(self) -> list[dict]:
        return list(self._entries)


class WinRegReader:
    """Reads Uninstall keys from HKLM/HKCU in both registry views."""

    def iter_uninstall_entries(self) -> list[dict]:  # pragma: no cover - Windows
        import winreg  # type: ignore

        entries: list[dict] = []
        views = [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, "HKLM", winreg.KEY_WOW64_32KEY),
            (winreg.HKEY_CURRENT_USER, "HKCU", winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_CURRENT_USER, "HKCU", winreg.KEY_WOW64_32KEY),
        ]
        seen: set[str] = set()
        for hive, hive_name, view in views:
            try:
                root = winreg.OpenKey(hive, UNINSTALL_KEY, 0,
                                      winreg.KEY_READ | view)
            except OSError:
                continue
            with root:
                i = 0
                while True:
                    try:
                        subname = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    full = f"{hive_name}\\{UNINSTALL_KEY}\\{subname}"
                    if full in seen:
                        continue
                    seen.add(full)
                    try:
                        sub = winreg.OpenKey(root, subname, 0,
                                             winreg.KEY_READ | view)
                    except OSError:
                        continue
                    values: dict = {}
                    with sub:
                        j = 0
                        while True:
                            try:
                                vname, vdata, _vtype = winreg.EnumValue(sub, j)
                            except OSError:
                                break
                            j += 1
                            values[vname] = vdata
                    values["__registry_path__"] = full
                    entries.append(values)
        return entries


def default_reader():
    return WinRegReader() if IS_WINDOWS else FakeRegistryReader([])


def list_installed_apps(reader=None) -> list[InstalledApp]:
    reader = reader or default_reader()
    apps: dict[tuple[str, str], InstalledApp] = {}
    for raw in reader.iter_uninstall_entries():
        name = str(raw.get("DisplayName", "")).strip()
        if not name:
            continue
        app = InstalledApp(
            name=name,
            version=str(raw.get("DisplayVersion", "") or ""),
            publisher=str(raw.get("Publisher", "") or ""),
            install_location=str(raw.get("InstallLocation", "") or ""),
            uninstall_string=str(raw.get("UninstallString", "") or ""),
            registry_path=str(raw.get("__registry_path__", "")),
            values={k: v for k, v in raw.items()
                    if not k.startswith("__")},
        )
        apps.setdefault((name.lower(), app.install_location.lower()), app)
    return sorted(apps.values(), key=lambda a: a.name.lower())


# --------------------------------------------------------------------------
# Program-keys scan
# --------------------------------------------------------------------------

@dataclass
class ProgramKey:
    app: str
    value_name: str
    key: str


def scan_program_keys(apps: list[InstalledApp]) -> list[ProgramKey]:
    """Keys stored in plain registry values under the apps' own keys."""
    found: list[ProgramKey] = []
    for app in apps:
        for value_name in KEY_VALUE_NAMES:
            value = app.values.get(value_name)
            if isinstance(value, str) and len(value.strip()) >= 5:
                found.append(ProgramKey(app=app.name,
                                        value_name=value_name,
                                        key=value.strip()))
        # Some apps stash keys in a nested dict of extra values.
        extra = app.values.get("Keys")
        if isinstance(extra, dict):
            for value_name, value in extra.items():
                if isinstance(value, str) and len(value.strip()) >= 5:
                    found.append(ProgramKey(app=app.name,
                                            value_name=str(value_name),
                                            key=value.strip()))
    return found


def export_keys_report(keys: list[ProgramKey], out_path) -> Path:
    out_path = Path(out_path)
    lines = ["FreeMove — exported program keys",
             "(only keys stored in plain registry values are recoverable)",
             ""]
    for k in keys:
        lines.append(f"{k.app}\t{k.value_name}\t{k.key}")
    if not keys:
        lines.append("(no plain-text program keys found)")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


# --------------------------------------------------------------------------
# App transfer bundles
# --------------------------------------------------------------------------

def find_appdata_folders(app: InstalledApp,
                         home: Path | None = None) -> list[Path]:
    """AppData folders that plausibly belong to ``app``."""
    home = home or collector.profile_dir()
    roaming = collector._env_path("APPDATA") or home / "AppData" / "Roaming"
    local = collector._env_path("LOCALAPPDATA") or home / "AppData" / "Local"
    needles = {app.name.lower()}
    if app.publisher:
        needles.add(app.publisher.lower())
    found: list[Path] = []
    for base in (roaming, local):
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if child.is_dir() and child.name.lower() in needles:
                found.append(child)
    return found


def export_app_registry(app: InstalledApp, out_dir: Path) -> Path | None:
    """Export the app's Uninstall key to a .reg file (Windows).

    On other platforms (tests/dry runs) a JSON snapshot of the key's
    values is written instead, clearly named as such.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in app.name)
    if IS_WINDOWS and app.registry_path:  # pragma: no cover - Windows
        target = out_dir / f"{safe}.reg"
        result = subprocess.run(
            ["reg", "export", app.registry_path, str(target), "/y"],
            capture_output=True, timeout=60,
        )
        return target if result.returncode == 0 and target.exists() else None
    target = out_dir / f"{safe}.registry.json"
    target.write_text(json.dumps(
        {"registry_path": app.registry_path, "values": app.values},
        indent=2, default=str), encoding="utf-8")
    return target


def build_app_bundle(app: InstalledApp, staging_dir: Path,
                     home: Path | None = None) -> list[tuple[Path, str]]:
    """Selection items for transferring one app to another PC."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in app.name)
    items: list[tuple[Path, str]] = []
    if app.install_location and Path(app.install_location).is_dir():
        items.append((Path(app.install_location), f"apps/{safe}/program"))
    for folder in find_appdata_folders(app, home):
        kind = "Roaming" if "Roaming" in str(folder) else "Local"
        items.append((folder, f"apps/{safe}/appdata-{kind}"))
    reg_file = export_app_registry(app, Path(staging_dir) / safe)
    if reg_file is not None:
        items.append((reg_file, f"apps/{safe}/registry"))
    return items


# --------------------------------------------------------------------------
# Local move (same PC, C: -> D:) with junction + rollback
# --------------------------------------------------------------------------

def _tree_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            fpath = Path(dirpath) / fname
            hashes[fpath.relative_to(root).as_posix()] = \
                protocol.sha256_file(fpath)
    return hashes


def verify_tree(source: Path, target: Path) -> bool:
    """True when ``target`` is a hash-identical copy of ``source``."""
    return _tree_hashes(source) == _tree_hashes(target)


def create_junction(link: Path, target: Path) -> None:
    """Point ``link`` at directory ``target``.

    Windows: NTFS junction via ``mklink /J`` (no admin needed).
    POSIX (tests/dev): a symbolic link stands in for the junction.
    """
    if IS_WINDOWS:  # pragma: no cover - Windows
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise OSError(f"mklink failed: {result.stderr.strip()}")
    else:
        os.symlink(target, link, target_is_directory=True)


@dataclass
class MoveResult:
    source: str
    target: str
    files: int
    bytes_moved: int
    verified: bool


def local_move_app(source, dest_root, *,
                   junction_fn=create_junction,
                   verify_fn=verify_tree) -> MoveResult:
    """Move ``source`` dir under ``dest_root`` and junction the old path.

    Steps: copy -> verify hashes -> rename original aside -> create
    junction -> drop the aside copy.  A verification failure deletes
    the copy and leaves the original untouched; a junction failure
    restores the original name.  Nothing is deleted until the new
    location is verified *and* linked.
    """
    source = Path(source)
    dest_root = Path(dest_root)
    if not source.is_dir() or source.is_symlink():
        raise ValueError(f"not a real directory: {source}")
    target = dest_root / source.name
    if target.exists():
        raise FileExistsError(f"destination already exists: {target}")
    dest_root.mkdir(parents=True, exist_ok=True)

    shutil.copytree(source, target)
    if not verify_fn(source, target):
        shutil.rmtree(target, ignore_errors=True)
        raise protocol.VerificationError(
            f"copy of {source} failed hash verification; original untouched")

    total_bytes = sum(
        (Path(dirpath) / f).stat().st_size
        for dirpath, _d, files in os.walk(target) for f in files
    )
    file_count = len(_tree_hashes(target))

    backup = source.with_name(source.name + ".freemove-backup")
    if backup.exists():
        raise FileExistsError(f"backup path already exists: {backup}")
    source.rename(backup)
    try:
        junction_fn(source, target)
    except Exception:
        if source.exists() or source.is_symlink():
            source.unlink() if source.is_symlink() else None
        backup.rename(source)
        raise
    shutil.rmtree(backup)
    return MoveResult(source=str(source), target=str(target),
                      files=file_count, bytes_moved=total_bytes,
                      verified=True)
