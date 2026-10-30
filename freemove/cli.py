"""FreeMove command line — full parity with the GUI, scriptable.

    freemove discover
    freemove receive --dest D:\\Incoming [--port N]
    freemove send --host 192.168.1.50 --pin 123456 --profile --browsers --mail --path C:\\Data
    freemove export-image --out move.fmimg --profile --path C:\\Data [--passphrase ...]
    freemove import-image move.fmimg --dest C:\\Users\\me [--passphrase ...]
    freemove apps list
    freemove apps move "C:\\Program Files\\SomeApp" --to D:\\Apps
    freemove keys export --out keys.txt
    freemove gui
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__, apps as apps_mod, archive, collector, discovery
from .client import Sender
from .server import Receiver


def _log(kind, data):
    if kind == "listening":
        print(f"Listening on port {data['port']}", flush=True)
        print(f"Pairing PIN: {data['pin']}", flush=True)
        print(f"Certificate fingerprint (check it matches the sender): "
              f"{data['fingerprint']}", flush=True)
    elif kind == "paired":
        print("Paired ✓ — secure connection established")
    elif kind == "file_start":
        print(f"  {data['path']} ({data['size']} bytes"
              + (f", resuming at {data['offset']}" if data.get("offset") else "")
              + ")")
    elif kind == "error":
        print(f"ERROR: {data['error']}", file=sys.stderr)


def _selection_args(parser):
    parser.add_argument("--profile", action="store_true",
                        help="user profile folders")
    parser.add_argument("--browsers", action="store_true",
                        help="browser profiles (Chrome/Edge/Firefox)")
    parser.add_argument("--mail", action="store_true",
                        help="mail stores (Outlook PST/OST, Thunderbird)")
    parser.add_argument("--path", action="append", default=[],
                        metavar="DIR", help="extra folder (repeatable)")
    parser.add_argument("--app", action="append", default=[],
                        metavar="NAME",
                        help="installed app to bundle (repeatable)")


def _build_items(args, staging: Path) -> list[tuple[Path, str]]:
    items: list[tuple[Path, str]] = []
    nothing = not (args.profile or args.browsers or args.mail
                   or args.path or args.app)
    items += collector.standard_selection(
        include_profile=args.profile or nothing,
        include_browsers=args.browsers or nothing,
        include_mail=args.mail or nothing,
        extra_folders=[Path(p) for p in args.path],
    )
    if args.app:
        installed = {a.name.lower(): a for a in apps_mod.list_installed_apps()}
        for name in args.app:
            app = installed.get(name.lower())
            if app is None:
                print(f"warning: app not found: {name}", file=sys.stderr)
                continue
            items += apps_mod.build_app_bundle(app, staging)
    return items


def cmd_discover(args) -> int:
    peers = discovery.discover(timeout=args.timeout)
    if not peers:
        print("No FreeMove receivers found on this network.")
        return 0
    for peer in peers:
        print(peer.label())
    return 0


def cmd_receive(args) -> int:
    receiver = Receiver(args.dest, port=args.port, announce=True,
                        on_event=_log)
    receiver.prepare()
    print("Waiting for a sender… (Ctrl+C to stop)", flush=True)
    try:
        report = receiver.serve_once()
    except KeyboardInterrupt:
        receiver.close()
        return 130
    print(f"Done: {len(report['received'])} files, "
          f"{report['bytes']} bytes, verified={report['verified']}")
    return 0


def cmd_send(args) -> int:
    import tempfile
    # Staged files (exported .reg bundles) live in the temp dir, so the
    # send itself must happen before it is cleaned up.
    with tempfile.TemporaryDirectory(prefix="freemove-stage-") as stage:
        items = _build_items(args, Path(stage))
        entries = collector.expand_selection(items)
        if not entries:
            print("Nothing selected to send.", file=sys.stderr)
            return 2
        total = sum(e.size for e in entries)
        print(f"Sending {len(entries)} files ({total} bytes) "
              f"to {args.host}:{args.port}")
        sender = Sender(on_event=_log)
        report = sender.send(args.host, args.port, args.pin, entries)
    print(f"Receiver verified {len(report['received'])} files ✓")
    return 0


def cmd_export_image(args) -> int:
    import tempfile
    passphrase = None
    if args.passphrase:
        passphrase = getpass.getpass("Image passphrase: ")
    with tempfile.TemporaryDirectory(prefix="freemove-stage-") as stage:
        items = _build_items(args, Path(stage))
        entries = collector.expand_selection(items)
        if not entries:
            print("Nothing selected to export.", file=sys.stderr)
            return 2
        report = archive.export_image(entries, args.out,
                                      passphrase=passphrase)
    state = "AES-256-GCM encrypted" if report.encrypted else "UNENCRYPTED"
    print(f"Wrote {report.image}: {report.files} files, "
          f"{report.total_bytes} bytes, {state}")
    return 0


def cmd_import_image(args) -> int:
    passphrase = None
    if args.passphrase:
        passphrase = getpass.getpass("Image passphrase: ")
    report = archive.import_image(args.image, args.dest,
                                  passphrase=passphrase)
    print(f"Imported {len(report.placed)} files into {args.dest} "
          f"(all hashes verified ✓)")
    return 0


def cmd_apps_list(args) -> int:
    installed = apps_mod.list_installed_apps()
    for app in installed:
        loc = f"  [{app.install_location}]" if app.install_location else ""
        print(f"{app.label()}{loc}")
    print(f"{len(installed)} apps")
    return 0


def cmd_apps_move(args) -> int:
    result = apps_mod.local_move_app(Path(args.source), Path(args.to))
    print(f"Moved {result.files} files ({result.bytes_moved} bytes) "
          f"from {result.source} to {result.target}; original path is "
          "now a junction to the new location. Verified ✓")
    return 0


def cmd_keys_export(args) -> int:
    keys = apps_mod.scan_program_keys(apps_mod.list_installed_apps())
    apps_mod.export_keys_report(keys, args.out)
    print(f"Exported {len(keys)} program keys to {args.out}")
    return 0


def cmd_gui(args) -> int:
    from . import gui
    return gui.main()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="freemove",
        description="FreeMove — free, secure PC migration")
    parser.add_argument("--version", action="version",
                        version=f"FreeMove {__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("discover", help="find receivers on the LAN")
    p.add_argument("--timeout", type=float, default=3.0)
    p.set_defaults(fn=cmd_discover)

    p = sub.add_parser("receive", help="listen for an incoming transfer")
    p.add_argument("--dest", required=True, help="destination folder")
    p.add_argument("--port", type=int, default=discovery.TRANSFER_PORT)
    p.set_defaults(fn=cmd_receive)

    p = sub.add_parser("send", help="send to a receiver")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=discovery.TRANSFER_PORT)
    p.add_argument("--pin", required=True, help="6-digit PIN shown by receiver")
    _selection_args(p)
    p.set_defaults(fn=cmd_send)

    p = sub.add_parser("export-image", help="pack a selection into a .fmimg")
    p.add_argument("--out", required=True)
    p.add_argument("--passphrase", action="store_true",
                   help="prompt for an encryption passphrase")
    _selection_args(p)
    p.set_defaults(fn=cmd_export_image)

    p = sub.add_parser("import-image", help="extract a .fmimg (verified)")
    p.add_argument("image")
    p.add_argument("--dest", required=True)
    p.add_argument("--passphrase", action="store_true",
                   help="prompt for the image passphrase")
    p.set_defaults(fn=cmd_import_image)

    p = sub.add_parser("apps", help="installed-app tools")
    apps_sub = p.add_subparsers(dest="apps_command")
    pl = apps_sub.add_parser("list", help="list installed apps")
    pl.set_defaults(fn=cmd_apps_list)
    pm = apps_sub.add_parser("move", help="move an app folder to another "
                                        "drive on this PC (junction)")
    pm.add_argument("source")
    pm.add_argument("--to", required=True, help="destination root folder")
    pm.set_defaults(fn=cmd_apps_move)

    p = sub.add_parser("keys", help="program-key tools")
    keys_sub = p.add_subparsers(dest="keys_command")
    pk = keys_sub.add_parser("export", help="export recoverable program keys")
    pk.add_argument("--out", required=True)
    pk.set_defaults(fn=cmd_keys_export)

    p = sub.add_parser("gui", help="open the graphical interface")
    p.set_defaults(fn=cmd_gui)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    fn = getattr(args, "fn", None)
    if fn is None:
        return cmd_gui(args)
    return fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
