"""FreeMove graphical interface (Tkinter — stdlib, no dependencies).

Functional over fancy: pick a mode, pick what to move, watch progress.
All network/disk work runs on worker threads; the UI thread only
handles events delivered through a queue.
"""

from __future__ import annotations

import queue
import tempfile
import threading
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover - headless dev boxes
    tk = None  # type: ignore

from . import collector, discovery
from .client import Sender
from .server import Receiver


class FreeMoveApp:
    def __init__(self, root):
        self.root = root
        self.events: queue.Queue = queue.Queue()
        self.receiver: Receiver | None = None
        self.extra_folders: list[Path] = []
        root.title("FreeMove — free, secure PC migration")
        root.geometry("720x560")
        self._build()
        self.root.after(100, self._drain_events)

    # -- layout -------------------------------------------------------

    def _build(self):
        pad = {"padx": 8, "pady": 4}
        mode_frame = ttk.LabelFrame(self.root, text="Mode")
        mode_frame.pack(fill="x", **pad)
        self.mode = tk.StringVar(value="receive")
        for value, text in [
            ("receive", "Receive (this is the new PC)"),
            ("send", "Send (this is the old PC)"),
            ("export", "Export image (.fmimg)"),
            ("import", "Import image"),
            ("move", "Local move app (C: → D:)"),
        ]:
            ttk.Radiobutton(mode_frame, text=text, value=value,
                            variable=self.mode,
                            command=self._mode_changed).pack(
                                side="left", padx=4)

        conn = ttk.LabelFrame(self.root, text="Connection")
        conn.pack(fill="x", **pad)
        ttk.Label(conn, text="Receiver IP:").grid(row=0, column=0, sticky="e")
        self.host_var = tk.StringVar()
        ttk.Entry(conn, textvariable=self.host_var, width=18).grid(
            row=0, column=1, sticky="w")
        ttk.Button(conn, text="Find receivers",
                   command=self._discover).grid(row=0, column=2, padx=4)
        self.peer_var = tk.StringVar()
        self.peer_box = ttk.Combobox(conn, textvariable=self.peer_var,
                                     width=34, state="readonly")
        self.peer_box.grid(row=0, column=3, sticky="w")
        self.peer_box.bind("<<ComboboxSelected>>", self._peer_chosen)
        ttk.Label(conn, text="Pairing PIN:").grid(row=1, column=0, sticky="e")
        self.pin_var = tk.StringVar()
        ttk.Entry(conn, textvariable=self.pin_var, width=10).grid(
            row=1, column=1, sticky="w")
        self.status_var = tk.StringVar(
            value="Receive mode: press Start, then read the PIN + "
                  "fingerprint to the sender.")
        ttk.Label(conn, textvariable=self.status_var,
                  foreground="#225522").grid(row=1, column=2,
                                             columnspan=2, sticky="w")

        sel = ttk.LabelFrame(self.root, text="What to transfer")
        sel.pack(fill="x", **pad)
        self.opt_profile = tk.BooleanVar(value=True)
        self.opt_browsers = tk.BooleanVar(value=True)
        self.opt_mail = tk.BooleanVar(value=True)
        ttk.Checkbutton(sel, text="User profile (Desktop, Documents, "
                        "Downloads, Pictures, …)",
                        variable=self.opt_profile).pack(anchor="w")
        ttk.Checkbutton(sel, text="Browser profiles (Chrome / Edge / "
                        "Firefox)", variable=self.opt_browsers).pack(anchor="w")
        ttk.Checkbutton(sel, text="Mail stores (Outlook PST/OST, "
                        "Thunderbird)", variable=self.opt_mail).pack(anchor="w")
        row = ttk.Frame(sel)
        row.pack(fill="x")
        ttk.Button(row, text="Add folder…",
                   command=self._add_folder).pack(side="left")
        self.folders_var = tk.StringVar(value="(no extra folders)")
        ttk.Label(row, textvariable=self.folders_var).pack(side="left", padx=6)

        paths = ttk.LabelFrame(self.root, text="Folders / files")
        paths.pack(fill="x", **pad)
        ttk.Label(paths, text="Destination / image / app path:").grid(
            row=0, column=0, sticky="e")
        self.path_var = tk.StringVar()
        ttk.Entry(paths, textvariable=self.path_var, width=52).grid(
            row=0, column=1, sticky="w")
        ttk.Button(paths, text="Browse…",
                   command=self._browse_path).grid(row=0, column=2, padx=4)
        ttk.Label(paths, text="Local move target drive root:").grid(
            row=1, column=0, sticky="e")
        self.move_to_var = tk.StringVar()
        ttk.Entry(paths, textvariable=self.move_to_var, width=52).grid(
            row=1, column=1, sticky="w")

        ttk.Button(self.root, text="Start", command=self._start).pack(pady=6)
        self.overall = ttk.Progressbar(self.root, mode="determinate")
        self.overall.pack(fill="x", **pad)
        self.current = ttk.Progressbar(self.root, mode="determinate")
        self.current.pack(fill="x", **pad)
        self.log = tk.Text(self.root, height=12, state="disabled")
        self.log.pack(fill="both", expand=True, **pad)
        self._peers: list[discovery.Peer] = []
        self._totals: dict[str, int] = {}

    # -- helpers --------------------------------------------------------

    def _say(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _mode_changed(self):
        hints = {
            "receive": "Path = destination folder for incoming files.",
            "send": "Set the receiver IP + PIN, choose what to send.",
            "export": "Path = the .fmimg file to write.",
            "import": "Path = the .fmimg file to read; destination is "
                      "asked on start.",
            "move": "Path = the app's folder; target = the other "
                    "drive's root folder.",
        }
        self.status_var.set(hints.get(self.mode.get(), ""))

    def _discover(self):
        def work():
            peers = discovery.discover(timeout=3.0)
            self.events.put(("peers", peers))
        threading.Thread(target=work, daemon=True).start()
        self._say("Searching the LAN for FreeMove receivers…")

    def _peer_chosen(self, _event=None):
        idx = self.peer_box.current()
        if 0 <= idx < len(self._peers):
            self.host_var.set(self._peers[idx].host)

    def _add_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.extra_folders.append(Path(folder))
            self.folders_var.set(", ".join(str(p) for p in self.extra_folders))

    def _browse_path(self):
        if self.mode.get() in ("export",):
            path = filedialog.asksaveasfilename(
                defaultextension=".fmimg",
                filetypes=[("FreeMove image", "*.fmimg")])
        elif self.mode.get() in ("import",):
            path = filedialog.askopenfilename(
                filetypes=[("FreeMove image", "*.fmimg")])
        else:
            path = filedialog.askdirectory()
        if path:
            self.path_var.set(path)

    # -- event pump -----------------------------------------------------

    def _on_event(self, kind, data):
        self.events.put((kind, data))

    def _drain_events(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                self._handle(kind, data)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_events)

    def _handle(self, kind, data):
        if kind == "peers":
            self._peers = data
            self.peer_box["values"] = [p.label() for p in data]
            self._say(f"Found {len(data)} receiver(s)." if data
                      else "No receivers found — check both PCs are on "
                           "the same network, or type the IP manually.")
        elif kind == "listening":
            self.status_var.set(
                f"PIN: {data['pin']}   Fingerprint: {data['fingerprint']}")
            self._say(f"Listening on port {data['port']}. Give the "
                      "sender the PIN above and confirm the fingerprint "
                      "matches what their screen shows.")
        elif kind == "paired":
            self._say("Paired ✓ — encrypted connection established.")
        elif kind == "file_start":
            self._totals[data["path"]] = data["size"]
            total = sum(self._totals.values()) or 1
            self.overall["maximum"] = total
            self.current["maximum"] = max(data["size"], 1)
            self.current["value"] = data.get("offset", 0)
        elif kind == "progress":
            done_key = "received" if "received" in data else "sent"
            self.current["value"] = data[done_key]
            finished = sum(s for p, s in self._totals.items()
                           if p != data["path"])
            self.overall["value"] = finished + data[done_key]
        elif kind == "file_done":
            self._say(f"✓ {data['path']}")
        elif kind == "done":
            self._say(data)
            messagebox.showinfo("FreeMove", data)
        elif kind == "error":
            self._say(f"ERROR: {data.get('error', data)}")
            messagebox.showerror("FreeMove", str(data.get("error", data)))

    # -- actions ----------------------------------------------------------

    def _selection_items(self, staging: Path):
        return collector.standard_selection(
            include_profile=self.opt_profile.get(),
            include_browsers=self.opt_browsers.get(),
            include_mail=self.opt_mail.get(),
            extra_folders=self.extra_folders,
        )

    def _start(self):
        mode = self.mode.get()
        try:
            if mode == "receive":
                self._start_receive()
            elif mode == "send":
                self._start_send()
            elif mode == "export":
                self._start_export()
            elif mode == "import":
                self._start_import()
            elif mode == "move":
                self._start_move()
        except Exception as exc:  # surfaced, never swallowed
            messagebox.showerror("FreeMove", str(exc))

    def _start_receive(self):
        dest = self.path_var.get().strip()
        if not dest:
            raise ValueError("choose a destination folder first")
        self.receiver = Receiver(dest, announce=True, on_event=self._on_event)
        self.receiver.prepare()
        self.pin_var.set(self.receiver.pin)
        self.status_var.set(
            f"PIN: {self.receiver.pin}   "
            f"Fingerprint: {self.receiver.identity.short_fingerprint()}")
        threading.Thread(target=self._receive_work, daemon=True).start()
        self._say(f"Receiving into {dest} — waiting for the sender…")

    def _receive_work(self):
        try:
            report = self.receiver.serve_once()
            self.events.put(("done", f"Received {len(report['received'])} "
                                     "files, all hash-verified ✓"))
        except Exception as exc:
            self.events.put(("error", {"error": str(exc)}))

    def _start_send(self):
        host = self.host_var.get().strip()
        pin = self.pin_var.get().strip()
        if not host or len(pin) != 6:
            raise ValueError("enter the receiver's IP and its 6-digit PIN")

        def work():
            try:
                with tempfile.TemporaryDirectory(
                        prefix="freemove-stage-") as stage:
                    items = self._selection_items(Path(stage))
                    entries = collector.expand_selection(items)
                    if not entries:
                        raise ValueError("nothing selected to send")
                    self._totals = {e.path: e.size for e in entries}
                    report = Sender(on_event=self._on_event).send(
                        host, discovery.TRANSFER_PORT, pin, entries)
                self.events.put(("done", f"Sent {len(report['received'])} "
                                         "files; receiver verified them ✓"))
            except Exception as exc:
                self.events.put(("error", {"error": str(exc)}))
        threading.Thread(target=work, daemon=True).start()

    def _start_export(self):
        from . import archive
        out = self.path_var.get().strip()
        if not out:
            raise ValueError("choose where to write the .fmimg file")

        def work():
            try:
                with tempfile.TemporaryDirectory(
                        prefix="freemove-stage-") as stage:
                    items = self._selection_items(Path(stage))
                    entries = collector.expand_selection(items)
                    report = archive.export_image(entries, out)
                note = "encrypted" if report.encrypted else "unencrypted"
                self.events.put(("done", f"Wrote {out}: {report.files} "
                                         f"files ({note})"))
            except Exception as exc:
                self.events.put(("error", {"error": str(exc)}))
        threading.Thread(target=work, daemon=True).start()

    def _start_import(self):
        from . import archive
        image = self.path_var.get().strip()
        dest = filedialog.askdirectory(title="Import into which folder?")
        if not image or not dest:
            return

        def work():
            try:
                report = archive.import_image(image, dest)
                self.events.put(("done", f"Imported "
                                         f"{len(report.placed)} files, "
                                         "all hashes verified ✓"))
            except Exception as exc:
                self.events.put(("error", {"error": str(exc)}))
        threading.Thread(target=work, daemon=True).start()

    def _start_move(self):
        from . import apps as apps_mod
        source = self.path_var.get().strip()
        target = self.move_to_var.get().strip()
        if not source or not target:
            raise ValueError("set the app folder and the target drive root")

        def work():
            try:
                result = apps_mod.local_move_app(source, target)
                self.events.put(("done",
                                 f"Moved {result.files} files "
                                 f"({result.bytes_moved} bytes) to "
                                 f"{result.target}; the original path now "
                                 "points there, so the app keeps working."))
            except Exception as exc:
                self.events.put(("error", {"error": str(exc)}))
        threading.Thread(target=work, daemon=True).start()


def main() -> int:
    if tk is None:
        print("Tkinter is not available on this system; use the CLI "
              "(`freemove --help`).")
        return 1
    root = tk.Tk()
    FreeMoveApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
