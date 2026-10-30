"""Selection builders: *what* to transfer.

A "selection" is a list of ``(source_path, archive_prefix)`` pairs.
Expanding a selection walks directories and produces the
:class:`~freemove.protocol.FileEntry` list that the sender, the image
exporter and the local-move code all share.

Nothing here is Windows-only at import time; Windows locations are
resolved from environment variables / the home directory so the same
code runs (and is tested) on any platform.
"""

from __future__ import annotations

import configparser
import json
import os
import platform
import subprocess
from pathlib import Path

from . import protocol

IS_WINDOWS = os.name == "nt"

# Standard user-profile folders, in display order.
PROFILE_FOLDERS = [
    "Desktop", "Documents", "Downloads", "Pictures",
    "Music", "Videos", "Favorites", "Saved Games",
]


def _env_path(var: str) -> Path | None:
    val = os.environ.get(var)
    return Path(val) if val else None


def profile_dir() -> Path:
    return Path(os.environ.get("USERPROFILE", "")) if IS_WINDOWS and \
        os.environ.get("USERPROFILE") else Path.home()


def profile_folders(home: Path | None = None) -> dict[str, Path]:
    """Standard profile folders that actually exist."""
    home = home or profile_dir()
    found: dict[str, Path] = {}
    for name in PROFILE_FOLDERS:
        candidate = home / name
        if candidate.is_dir():
            found[name] = candidate
    return found


def browser_profiles(home: Path | None = None) -> dict[str, Path]:
    """Browser profile roots (Chrome, Edge, Firefox) that exist.

    The *whole profile* is what gets copied — bookmarks, history,
    extensions and cookies travel with it.  Saved passwords inside a
    profile are encrypted to the original Windows user account
    (DPAPI) and generally will not decrypt on the new PC; see the
    README's honest-limits section.
    """
    home = home or profile_dir()
    local = _env_path("LOCALAPPDATA") or home / "AppData" / "Local"
    roaming = _env_path("APPDATA") or home / "AppData" / "Roaming"
    candidates: dict[str, Path] = {}
    if IS_WINDOWS:
        candidates = {
            "Chrome": local / "Google" / "Chrome" / "User Data",
            "Edge": local / "Microsoft" / "Edge" / "User Data",
            "Firefox": roaming / "Mozilla" / "Firefox" / "Profiles",
        }
    else:  # dev/test parity on POSIX
        config = home / ".config"
        candidates = {
            "Chrome": config / "google-chrome",
            "Edge": config / "microsoft-edge",
            "Firefox": home / ".mozilla" / "firefox",
        }
    return {k: v for k, v in candidates.items() if v.is_dir()}


def mail_stores(home: Path | None = None) -> list[Path]:
    """Outlook PST/OST files and Thunderbird mail dirs that exist.

    FreeMove copies the store *files*; the new PC's mail client picks
    them up when the account is added there.  (Live Exchange/IMAP mail
    re-syncs from the server anyway — the stores matter most for
    POP/local archives.)
    """
    home = home or profile_dir()
    local = _env_path("LOCALAPPDATA") or home / "AppData" / "Local"
    search_roots = [
        home / "Documents" / "Outlook Files",
        local / "Microsoft" / "Outlook",
    ]
    found: list[Path] = []
    for root in search_roots:
        if root.is_dir():
            for ext in ("*.pst", "*.ost"):
                found.extend(sorted(root.rglob(ext)))
    tb = browser_profiles(home)  # Thunderbird lives beside Firefox data
    thunderbird = (home / "AppData" / "Roaming" / "Thunderbird") if IS_WINDOWS \
        else (home / ".thunderbird")
    if thunderbird.is_dir():
        found.append(thunderbird)
    return found


# --------------------------------------------------------------------------
# Settings bundle
# --------------------------------------------------------------------------

def _current_wallpaper() -> str | None:
    if IS_WINDOWS:
        try:
            import winreg  # type: ignore
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Control Panel\Desktop") as key:
                value, _ = winreg.QueryValueEx(key, "Wallpaper")
                return str(value) or None
        except OSError:
            return None
    return None


def collect_settings(out_dir: Path) -> Path:
    """Write a small settings bundle (JSON + optional power plan).

    Captures the portable personalisation facts: wallpaper path,
    computer/user names, and — on Windows — the active power plan
    exported with ``powercfg`` so it can be re-imported on the
    target PC.  This is a report-and-reapply bundle, not a registry
    transplant: blindly copying personalisation registry hives
    between machines is how migrations corrupt profiles.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    settings: dict = {
        "computer_name": platform.node(),
        "user_name": os.environ.get("USERNAME") or os.environ.get("USER", ""),
        "platform": platform.platform(),
        "wallpaper": _current_wallpaper(),
        "power_plan_file": None,
    }
    if IS_WINDOWS:
        plan_path = out_dir / "powerplan.pow"
        try:
            # Export the *active* scheme; GUID discovered via /getactivescheme.
            result = subprocess.run(
                ["powercfg", "/getactivescheme"],
                capture_output=True, text=True, timeout=30,
            )
            guid = None
            for token in result.stdout.replace(":", " ").split():
                if len(token) == 36 and token.count("-") == 4:
                    guid = token
                    break
            if guid:
                subprocess.run(["powercfg", "/export", str(plan_path), guid],
                               capture_output=True, timeout=30, check=True)
                settings["power_plan_file"] = plan_path.name
                settings["power_plan_guid"] = guid
        except (OSError, subprocess.SubprocessError):
            pass
    target = out_dir / "freemove-settings.json"
    target.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    return target


# --------------------------------------------------------------------------
# Selection expansion
# --------------------------------------------------------------------------

def expand_selection(items: list[tuple[Path, str]]) -> list[protocol.FileEntry]:
    """Expand ``(source, prefix)`` pairs into a flat FileEntry list.

    Directories are walked recursively; files are taken as-is.  The
    manifest path is ``<prefix>/<relative path>``.  Unreadable files
    are skipped with the rest of the walk continuing — the sender's
    manifest is built from what was actually readable.
    """
    entries: list[protocol.FileEntry] = []
    for source, prefix in items:
        source = Path(source)
        if source.is_file():
            entries.append(protocol.make_entry(
                source, f"{prefix}/{source.name}"))
        elif source.is_dir():
            for dirpath, _dirnames, filenames in os.walk(source):
                for fname in sorted(filenames):
                    fpath = Path(dirpath) / fname
                    rel = fpath.relative_to(source).as_posix()
                    try:
                        entries.append(protocol.make_entry(
                            fpath, f"{prefix}/{rel}"))
                    except OSError:
                        continue
    return entries


def standard_selection(include_profile: bool = True,
                       include_browsers: bool = True,
                       include_mail: bool = True,
                       extra_folders: list[Path] | None = None,
                       home: Path | None = None) -> list[tuple[Path, str]]:
    """The checkbox bundles the GUI/CLI offer by default."""
    items: list[tuple[Path, str]] = []
    if include_profile:
        for name, folder in profile_folders(home).items():
            items.append((folder, f"profile/{name}"))
    if include_browsers:
        for name, folder in browser_profiles(home).items():
            items.append((folder, f"browser/{name}"))
    if include_mail:
        for store in mail_stores(home):
            prefix = "mail/Thunderbird" if store.is_dir() else "mail"
            items.append((store, prefix))
    for folder in extra_folders or []:
        folder = Path(folder)
        items.append((folder, f"folders/{folder.name}"))
    return items
