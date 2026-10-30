"""FreeMove graphical interface (Tkinter/ttk — stdlib, no dependencies).

The layout follows the classic PC-migration flow: a home screen with
one card per job (PC to PC, Image File, App Migration, Program Keys);
the PC-to-PC screen shows *this* computer and the *other* computer
side by side with a connect step; the sender then picks what to move
in category cards (Files & Folders / Applications / User Profile)
with sizes, and watches a progress screen with a completion summary.

All network/disk work runs on worker threads; the UI thread only
handles events delivered through a queue, exactly as the backend's
``on_event`` callbacks produce them.
"""

from __future__ import annotations

import os
import platform
import queue
import socket
import tempfile
import threading
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, font as tkfont, messagebox, ttk
except ImportError:  # pragma: no cover - headless dev boxes
    tk = None  # type: ignore

from . import __version__, apps as apps_mod, archive, collector, discovery
from .client import Sender
from .server import Receiver

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

BG = "#eef1f4"          # window background
CARD = "#ffffff"        # card background
ACCENT = "#1f6fb2"      # the one accent colour (header, primary buttons)
ACCENT_DARK = "#175a91"
TEXT = "#1c2733"
MUTED = "#5a6b7a"
BORDER = "#c9d3dc"


def fmt_size(n: int | None) -> str:
    if n is None:
        return "—"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else \
                f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def short_fingerprint(fingerprint: str) -> str:
    """Same short form the receiver shows (see security.Identity)."""
    fp = fingerprint.upper()
    return " ".join(fp[i:i + 4] for i in range(0, 16, 4)) + " …"


def dir_size(path: Path) -> int:
    """Total bytes under ``path`` (file size for a plain file)."""
    path = Path(path)
    try:
        if path.is_file():
            return path.stat().st_size
        total = 0
        for dirpath, _dirs, filenames in os.walk(path):
            for name in filenames:
                try:
                    total += (Path(dirpath) / name).stat().st_size
                except OSError:
                    continue
        return total
    except OSError:
        return 0


def local_ip() -> str:
    """Best-effort LAN address of this PC (for the 'this computer' card)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "unknown"


# ---------------------------------------------------------------------------
# Shared widgets
# ---------------------------------------------------------------------------

class ProgressPanel(ttk.Frame):
    """Overall bar + current-file bar + scrolling log + summary line.

    Fed by the backend's file_start / progress / file_done events,
    which the sender and receiver produce in the same shapes.
    """

    def __init__(self, master):
        super().__init__(master, style="Card.TFrame", padding=10)
        self._totals: dict[str, int] = {}
        ttk.Label(self, text="Overall progress",
                  style="Card.TLabel").pack(anchor="w")
        self.overall = ttk.Progressbar(self, mode="determinate")
        self.overall.pack(fill="x", pady=(0, 6))
        self.current_label = ttk.Label(self, text="Current file: —",
                                       style="Card.TLabel")
        self.current_label.pack(anchor="w")
        self.current = ttk.Progressbar(self, mode="determinate")
        self.current.pack(fill="x", pady=(0, 6))
        self.log = tk.Text(self, height=9, state="disabled",
                           background="#fbfcfd", foreground=TEXT,
                           relief="solid", borderwidth=1)
        self.log.pack(fill="both", expand=True)
        self.summary = ttk.Label(self, text="", style="Summary.TLabel",
                                 wraplength=900, justify="left")
        self.summary.pack(anchor="w", pady=(6, 0))

    def reset(self):
        self._totals = {}
        self.overall["value"] = 0
        self.overall["maximum"] = 1
        self.current["value"] = 0
        self.current["maximum"] = 1
        self.current_label.configure(text="Current file: —")
        self.summary.configure(text="")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def say(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_summary(self, text: str):
        self.summary.configure(text=text)
        if text:
            self.say(text)

    def handle(self, kind, data) -> bool:
        if kind == "file_start":
            self._totals[data["path"]] = data["size"]
            self.overall["maximum"] = max(sum(self._totals.values()), 1)
            self.current["maximum"] = max(data["size"], 1)
            self.current["value"] = data.get("offset", 0)
            note = f" (resuming at {fmt_size(data['offset'])})" \
                if data.get("offset") else ""
            self.current_label.configure(
                text=f"Current file: {data['path']} "
                     f"({fmt_size(data['size'])}){note}")
        elif kind == "progress":
            done = data["sent"] if "sent" in data else data.get("received", 0)
            self.current["value"] = done
            finished = sum(s for p, s in self._totals.items()
                           if p != data["path"])
            self.overall["value"] = finished + done
        elif kind == "file_done":
            self.say(f"✓ {data['path']}")
        elif kind == "paired":
            self.say("Paired ✓ — encrypted connection established.")
        else:
            return False
        return True


class SelectionPanel(ttk.Frame):
    """The three PCTrans-style category cards with Edit pickers.

    Categories: Files & Folders (profile folders + extra folders),
    Applications (installed apps, bundled with their data), and
    User Profile (settings bundle, browser profiles, mail stores).
    Sizes are measured on a background thread and posted back through
    the app event queue; nothing here touches the disk on the UI
    thread beyond building the widgets.
    """

    CATEGORIES = ("files", "apps", "profile")

    def __init__(self, master, app: "FreeMoveApp", token: str):
        super().__init__(master, style="TFrame")
        self.app = app
        self.token = token
        app.register_panel(token, self)

        self.file_items: list[dict] = []     # profile folders + extras
        self.app_items: list[dict] = []      # installed apps
        self.browser_items: list[dict] = []
        self.mail_items: list[dict] = []
        self.opt_settings = tk.BooleanVar(value=True)
        self._apps_loaded = False
        self._sizes_started = False

        for name, folder in collector.profile_folders().items():
            self.file_items.append({
                "path": folder, "prefix": f"profile/{name}",
                "label": name, "var": tk.BooleanVar(value=True),
                "size": None, "extra": False})
        for name, folder in collector.browser_profiles().items():
            self.browser_items.append({
                "path": folder, "prefix": f"browser/{name}",
                "label": name, "var": tk.BooleanVar(value=True),
                "size": None})
        for store in collector.mail_stores():
            is_dir = store.is_dir()
            self.mail_items.append({
                "path": store,
                "prefix": "mail/Thunderbird" if is_dir else "mail",
                "label": "Thunderbird" if is_dir else store.name,
                "var": tk.BooleanVar(value=True), "size": None})
        for group in (self.file_items + self.browser_items + self.mail_items):
            group["var"].trace_add("write", lambda *_: self._summaries())
        self.opt_settings.trace_add("write", lambda *_: self._summaries())

        self._cards: dict[str, ttk.Label] = {}
        titles = {
            "files": "Files & Folders",
            "apps": "Applications",
            "profile": "User Profile",
        }
        hints = {
            "files": "Desktop, Documents, Downloads… plus any folders "
                     "you add.",
            "apps": "Installed programs, with their settings and data.",
            "profile": "Personalisation, browser profiles and mail.",
        }
        for col, key in enumerate(self.CATEGORIES):
            card = ttk.Frame(self, style="Card.TFrame", padding=10,
                             borderwidth=1, relief="solid")
            card.grid(row=0, column=col, sticky="nsew", padx=4)
            self.columnconfigure(col, weight=1)
            ttk.Label(card, text=titles[key],
                      style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card, text=hints[key], style="CardMuted.TLabel",
                      wraplength=260).pack(anchor="w", pady=(2, 6))
            summary = ttk.Label(card, text="…", style="Card.TLabel",
                                wraplength=260)
            summary.pack(anchor="w")
            self._cards[key] = summary
            ttk.Button(card, text="Edit…",
                       command=lambda k=key: self.open_edit(k)).pack(
                           anchor="w", pady=(8, 0))
        self.total_label = ttk.Label(self, text="", style="TLabel")
        self.total_label.grid(row=1, column=0, columnspan=3,
                              sticky="w", pady=(6, 0))
        self._summaries()

    # -- data loading (background) ------------------------------------

    def refresh(self):
        """Kick off size measurement + the installed-apps scan once."""
        if not self._sizes_started:
            self._sizes_started = True
            threading.Thread(target=self._measure_sizes,
                             daemon=True).start()
        if not self._apps_loaded:
            threading.Thread(target=self._load_apps,
                             daemon=True).start()

    def _measure_sizes(self):
        sizes: dict[str, int] = {}
        for item in self.file_items + self.browser_items + self.mail_items:
            sizes[str(item["path"])] = dir_size(item["path"])
        self.app.post("sel_sizes", (self.token, sizes))

    def _load_apps(self):
        loaded = []
        for app in apps_mod.list_installed_apps():
            size = dir_size(Path(app.install_location)) \
                if app.install_location else 0
            loaded.append((app, size))
        self.app.post("sel_apps", (self.token, loaded))

    def handle_app_event(self, kind, data) -> bool:
        token, payload = data
        if token != self.token:
            return False
        if kind == "sel_sizes":
            for item in self.file_items + self.browser_items \
                    + self.mail_items:
                if str(item["path"]) in payload:
                    item["size"] = payload[str(item["path"])]
            self._summaries()
            return True
        if kind == "sel_apps":
            self.app_items = [{
                "app": app, "size": size,
                "var": tk.BooleanVar(value=False)} for app, size in payload]
            for item in self.app_items:
                item["var"].trace_add("write",
                                       lambda *_: self._summaries())
            self._apps_loaded = True
            self._summaries()
            return True
        return False

    # -- summaries ------------------------------------------------------

    def _checked(self, items):
        return [i for i in items if i["var"].get()]

    def _sum(self, items):
        return sum(i["size"] or 0 for i in items)

    def _summaries(self):
        files = self._checked(self.file_items)
        self._cards["files"].configure(
            text=f"{len(files)} folder(s) · {fmt_size(self._sum(files))}")
        apps = self._checked(self.app_items)
        if not self._apps_loaded:
            apps_text = "Scanning installed apps…"
        else:
            apps_text = f"{len(apps)} app(s) · " \
                        f"{fmt_size(self._sum(apps))}"
        self._cards["apps"].configure(text=apps_text)
        profile_bits = []
        if self.opt_settings.get():
            profile_bits.append("settings")
        browsers = self._checked(self.browser_items)
        mail = self._checked(self.mail_items)
        psize = self._sum(browsers) + self._sum(mail)
        if browsers:
            profile_bits.append(f"{len(browsers)} browser(s)")
        if mail:
            profile_bits.append(f"{len(mail)} mail store(s)")
        self._cards["profile"].configure(
            text=(" · ".join(profile_bits) if profile_bits else "nothing")
            + f" · {fmt_size(psize)}")
        total = self._sum(files) + self._sum(apps) + psize
        count = len(files) + len(apps) + len(browsers) + len(mail) \
            + (1 if self.opt_settings.get() else 0)
        self.total_label.configure(
            text=f"Selected: {count} group(s), about {fmt_size(total)}")

    def any_selected(self) -> bool:
        return bool(self._checked(self.file_items)
                    or self._checked(self.app_items)
                    or self._checked(self.browser_items)
                    or self._checked(self.mail_items)
                    or self.opt_settings.get())

    # -- edit dialogs ---------------------------------------------------

    def open_edit(self, category: str):
        dialog = tk.Toplevel(self)
        dialog.title({"files": "Files & Folders",
                      "apps": "Applications",
                      "profile": "User Profile"}[category])
        dialog.transient(self.winfo_toplevel())
        body = ttk.Frame(dialog, padding=12)
        body.pack(fill="both", expand=True)

        def check_row(parent, var, label, size):
            row = ttk.Frame(parent)
            row.pack(fill="x", pady=1)
            ttk.Checkbutton(row, text=label, variable=var).pack(side="left")
            ttk.Label(row, text=fmt_size(size)).pack(side="right")

        if category == "files":
            if not self.file_items:
                ttk.Label(body, text="No standard profile folders found "
                          "on this PC.").pack(anchor="w")
            for item in self.file_items:
                check_row(body, item["var"], item["label"], item["size"])

            def add_folder():
                folder = filedialog.askdirectory(
                    title="Add a folder to transfer", parent=dialog)
                if not folder:
                    return
                path = Path(folder)
                item = {"path": path, "prefix": f"folders/{path.name}",
                        "label": f"{path.name}  ({path})",
                        "var": tk.BooleanVar(value=True),
                        "size": None, "extra": True}
                item["var"].trace_add("write",
                                      lambda *_: self._summaries())
                self.file_items.append(item)
                check_row(body, item["var"], item["label"], item["size"])
                threading.Thread(
                    target=lambda: self.app.post(
                        "sel_sizes", (self.token,
                                      {str(path): dir_size(path)})),
                    daemon=True).start()
                self._summaries()
            ttk.Button(body, text="Add folder…",
                       command=add_folder).pack(anchor="w", pady=(8, 0))
        elif category == "apps":
            if not self._apps_loaded:
                ttk.Label(body, text="Scanning installed apps… reopen "
                          "in a moment.").pack(anchor="w")
            elif not self.app_items:
                ttk.Label(body, text="No installed apps found.").pack(
                    anchor="w")
            canvas_frame = ttk.Frame(body)
            canvas_frame.pack(fill="both", expand=True)
            canvas = tk.Canvas(canvas_frame, height=320, width=460,
                               highlightthickness=0)
            scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical",
                                      command=canvas.yview)
            inner = ttk.Frame(canvas)
            inner.bind("<Configure>", lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")))
            canvas.create_window((0, 0), window=inner, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            for item in self.app_items:
                check_row(inner, item["var"], item["app"].label(),
                          item["size"])
        else:  # profile
            check_row(body, self.opt_settings,
                      "Personalisation settings bundle (wallpaper, "
                      "power plan, names)", None)
            if self.browser_items:
                ttk.Label(body, text="Browser profiles",
                          style="CardTitle.TLabel").pack(
                              anchor="w", pady=(10, 2))
                for item in self.browser_items:
                    check_row(body, item["var"], item["label"],
                              item["size"])
            if self.mail_items:
                ttk.Label(body, text="Mail stores",
                          style="CardTitle.TLabel").pack(
                              anchor="w", pady=(10, 2))
                for item in self.mail_items:
                    check_row(body, item["var"], item["label"],
                              item["size"])
            if not self.browser_items and not self.mail_items:
                ttk.Label(body, text="No browser profiles or mail "
                          "stores found on this PC.").pack(
                              anchor="w", pady=(8, 0))
        ttk.Button(body, text="Done", style="Accent.TButton",
                   command=dialog.destroy).pack(pady=(12, 0))
        dialog.minsize(420, 200)
        return dialog

    # -- selection -> backend items --------------------------------------

    def collect_items(self, staging: Path) -> list[tuple[Path, str]]:
        """Build the (source, prefix) list for the checked categories.

        App bundles and the settings bundle write staged files, so —
        like the CLI — this must run inside the caller's staging-dir
        lifetime, on its worker thread.
        """
        items: list[tuple[Path, str]] = []
        for item in self._checked(self.file_items):
            items.append((item["path"], item["prefix"]))
        if self.opt_settings.get():
            settings = collector.collect_settings(staging / "settings")
            items.append((settings, "settings"))
        for item in self._checked(self.browser_items):
            items.append((item["path"], item["prefix"]))
        for item in self._checked(self.mail_items):
            items.append((item["path"], item["prefix"]))
        for item in self._checked(self.app_items):
            items += apps_mod.build_app_bundle(item["app"], staging)
        return items


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------

class Screen(ttk.Frame):
    """Base class: a full-window page managed by FreeMoveApp."""

    title = ""

    def __init__(self, master, app: "FreeMoveApp"):
        super().__init__(master, style="TFrame", padding=14)
        self.app = app

    def on_show(self):
        pass

    def on_hide(self):
        pass

    def handle_event(self, kind, data) -> bool:
        return False


class HomeScreen(Screen):
    title = "Home"

    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="What would you like to do?",
                  style="Title.TLabel").pack(anchor="w", pady=(2, 4))
        ttk.Label(self, text="FreeMove moves your files, apps and "
                  "settings to a new PC — free, encrypted, and with no "
                  "accounts, cloud or size limits.",
                  style="Muted.TLabel", wraplength=900).pack(
                      anchor="w", pady=(0, 12))
        grid = ttk.Frame(self)
        grid.pack(fill="both", expand=True)
        cards = [
            ("pcp", "PC to PC",
             "Transfer everything to another computer over your local "
             "network. The two PCs pair with a PIN and the transfer is "
             "encrypted end to end."),
            ("image", "Image File",
             "Pack a computer into a single .fmimg file — on a USB "
             "drive, for a PC that no longer boots, or as a backup — "
             "and restore it anywhere. Optional AES-256 encryption."),
            ("move", "App Migration",
             "Move an installed app from a full drive to another one "
             "(C: → D:) on this PC. The original path keeps working, "
             "so the app never notices."),
            ("keys", "Program Keys",
             "Scan this PC for recoverable software license keys and "
             "export them — do this before you wipe or retire the "
             "old machine."),
        ]
        self.card_buttons: dict[str, ttk.Button] = {}
        for idx, (target, heading, blurb) in enumerate(cards):
            card = ttk.Frame(grid, style="Card.TFrame", padding=16,
                             borderwidth=1, relief="solid")
            card.grid(row=idx // 2, column=idx % 2, sticky="nsew",
                      padx=6, pady=6)
            grid.columnconfigure(idx % 2, weight=1)
            grid.rowconfigure(idx // 2, weight=1)
            ttk.Label(card, text=heading,
                      style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card, text=blurb, style="CardMuted.TLabel",
                      wraplength=400).pack(anchor="w", pady=(4, 10))
            button = ttk.Button(card, text="Open →",
                                style="Accent.TButton",
                                command=lambda t=target: app.show(t))
            button.pack(anchor="w")
            self.card_buttons[target] = button


class PcScreen(Screen):
    """PC to PC: connect view -> select view (sender) -> progress."""

    title = "PC to PC"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.receiver: Receiver | None = None
        self._closing_receiver = False
        self.peer_list: list[discovery.Peer] = []
        self.peer_port = discovery.TRANSFER_PORT
        self.send_host = ""
        self.send_pin = ""
        self.busy = False

        # -- views container -------------------------------------------
        self.views = ttk.Frame(self)
        self.views.pack(fill="both", expand=True)
        self.connect_view = ttk.Frame(self.views)
        self.select_view = ttk.Frame(self.views)
        self.progress_view = ttk.Frame(self.views)
        self._build_connect()
        self._build_select()
        self._build_progress()
        self._show_view("connect")

    # -- connect view ---------------------------------------------------

    def _build_connect(self):
        view = self.connect_view
        panes = ttk.Frame(view)
        panes.pack(fill="x")
        left = ttk.Frame(panes, style="Card.TFrame", padding=14,
                         borderwidth=1, relief="solid")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        right = ttk.Frame(panes, style="Card.TFrame", padding=14,
                          borderwidth=1, relief="solid")
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        panes.columnconfigure(0, weight=1)
        panes.columnconfigure(1, weight=1)

        ttk.Label(left, text="This computer",
                  style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(left, text=f"Name: {platform.node() or socket.gethostname()}",
                  style="Card.TLabel").pack(anchor="w", pady=(4, 0))
        ttk.Label(left, text=f"Network address: {local_ip()}",
                  style="Card.TLabel").pack(anchor="w")
        ttk.Label(left, text="This PC is the:",
                  style="Card.TLabel").pack(anchor="w", pady=(12, 2))
        self.role = tk.StringVar(value="send")
        ttk.Radiobutton(left, text="Old PC — send my stuff",
                        value="send", variable=self.role,
                        command=self._apply_role).pack(anchor="w")
        ttk.Radiobutton(left, text="New PC — receive here",
                        value="receive", variable=self.role,
                        command=self._apply_role).pack(anchor="w")

        # Receive controls live under the role choice, PCTrans-style:
        # this side shows the PIN the sender must type.
        self.recv_box = ttk.Frame(left, style="Card.TFrame")
        ttk.Label(self.recv_box, text="Save incoming files in:",
                  style="Card.TLabel").pack(anchor="w", pady=(10, 2))
        dest_row = ttk.Frame(self.recv_box, style="Card.TFrame")
        dest_row.pack(fill="x")
        self.dest_var = tk.StringVar()
        ttk.Entry(dest_row, textvariable=self.dest_var).pack(
            side="left", fill="x", expand=True)
        ttk.Button(dest_row, text="Browse…",
                   command=self._browse_dest).pack(side="left", padx=4)
        self.start_btn = ttk.Button(
            self.recv_box, text="Start receiving",
            style="Accent.TButton", command=self._start_receive)
        self.start_btn.pack(anchor="w", pady=(10, 4))
        ttk.Label(self.recv_box, text="Then, on the old PC, pick this "
                  "computer and type this PIN:", style="CardMuted.TLabel",
                  wraplength=380).pack(anchor="w")
        self.pin_label = ttk.Label(self.recv_box, text="PIN: — — —",
                                   style="Pin.TLabel")
        self.pin_label.pack(anchor="w", pady=2)
        self.fp_label = ttk.Label(self.recv_box, text="",
                                  style="CardMuted.TLabel", wraplength=380)
        self.fp_label.pack(anchor="w")

        # Right pane, sender variant: find + connect to a receiver.
        self.send_box = ttk.Frame(right, style="Card.TFrame")
        ttk.Label(self.send_box, text="The other computer",
                  style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(self.send_box, text="Receivers on your network:",
                  style="Card.TLabel").pack(anchor="w", pady=(6, 2))
        list_row = ttk.Frame(self.send_box, style="Card.TFrame")
        list_row.pack(fill="x")
        self.peer_box = tk.Listbox(list_row, height=5,
                                   activestyle="none")
        self.peer_box.pack(side="left", fill="x", expand=True)
        self.peer_box.bind("<<ListboxSelect>>", self._peer_selected)
        ttk.Button(list_row, text="Search", command=self._discover).pack(
            side="left", padx=4, anchor="n")
        ttk.Label(self.send_box, text="…or type its address:",
                  style="Card.TLabel").pack(anchor="w", pady=(8, 2))
        self.host_var = tk.StringVar()
        ttk.Entry(self.send_box, textvariable=self.host_var).pack(
            fill="x")
        ttk.Label(self.send_box, text="PIN shown on the other PC:",
                  style="Card.TLabel").pack(anchor="w", pady=(8, 2))
        self.pin_var = tk.StringVar()
        ttk.Entry(self.send_box, textvariable=self.pin_var,
                  width=10).pack(anchor="w")
        self.connect_btn = ttk.Button(
            self.send_box, text="Connect", style="Accent.TButton",
            command=self._connect)
        self.connect_btn.pack(anchor="w", pady=(12, 0))

        # Right pane, receiver variant: instructions for the sender side.
        self.recv_info = ttk.Frame(right, style="Card.TFrame")
        ttk.Label(self.recv_info, text="The other computer",
                  style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(self.recv_info,
                  text="On the old PC, open FreeMove and choose "
                       "“Old PC — send my stuff”. This computer appears "
                       "in its list automatically while receiving is on. "
                       "The sender types the PIN shown here; before "
                       "anything is sent, both screens show a certificate "
                       "fingerprint — they must match, so a stranger on "
                       "the network can't intercept the transfer.",
                  style="CardMuted.TLabel", wraplength=400).pack(
                      anchor="w", pady=(6, 0))
        self.hint = ttk.Label(view, text="", style="Muted.TLabel",
                              wraplength=920)
        self.hint.pack(anchor="w", pady=(12, 0))
        self._apply_role()

    def _apply_role(self):
        if self.role.get() == "send":
            self.recv_box.pack_forget()
            self.recv_info.pack_forget()
            self.send_box.pack(fill="both", expand=True)
            self.hint.configure(
                text="Tip: the other PC must be running FreeMove with "
                     "“Start receiving” pressed.")
        else:
            self.send_box.pack_forget()
            self.recv_box.pack(fill="x")
            self.recv_info.pack(fill="both", expand=True)
            self.hint.configure(
                text="Receiving writes only into the folder you picked, "
                     "and every file is hash-verified before it lands.")

    def _browse_dest(self):
        folder = filedialog.askdirectory(
            title="Folder to save incoming files in")
        if folder:
            self.dest_var.set(folder)

    def _discover(self):
        self.hint.configure(text="Searching the LAN for receivers…")

        def work():
            try:
                peers = discovery.discover(timeout=3.0)
                self.app.post("peers", peers)
            except Exception as exc:
                self.app.post("peers_error", str(exc))
        threading.Thread(target=work, daemon=True).start()

    def _peer_selected(self, _event=None):
        selection = self.peer_box.curselection()
        if selection and selection[0] < len(self.peer_list):
            peer = self.peer_list[selection[0]]
            self.host_var.set(peer.host)
            self.peer_port = peer.port

    # -- connect (sender) -------------------------------------------------

    def _connect(self):
        host = self.host_var.get().strip()
        pin = self.pin_var.get().strip()
        if not host:
            messagebox.showerror("FreeMove", "Pick a receiver from the "
                                 "list or type its network address.")
            return
        if len(pin) != 6 or not pin.isdigit():
            messagebox.showerror("FreeMove", "Type the 6-digit PIN "
                                 "shown on the other PC.")
            return
        self.connect_btn.configure(state="disabled")
        self.app.set_status("Pairing — checking the PIN…")

        def work():
            try:
                fingerprint = Sender().connect_pairing(
                    host, self.peer_port, pin)
                self.app.post("connected", {
                    "host": host, "port": self.peer_port, "pin": pin,
                    "fingerprint": fingerprint})
            except Exception as exc:
                self.app.post("pair_failed", str(exc))
        threading.Thread(target=work, daemon=True).start()

    # -- select view ------------------------------------------------------

    def _build_select(self):
        view = self.select_view
        self.connected_label = ttk.Label(view, text="",
                                         style="Title.TLabel")
        self.connected_label.pack(anchor="w")
        self.connected_fp = ttk.Label(view, text="", style="Muted.TLabel",
                                      wraplength=920)
        self.connected_fp.pack(anchor="w", pady=(2, 10))
        self.panel = SelectionPanel(view, self.app, "pc-select")
        self.panel.pack(fill="x")
        row = ttk.Frame(view)
        row.pack(fill="x", pady=(14, 0))
        ttk.Button(row, text="‹ Back", command=self._back_to_connect).pack(
            side="left")
        self.transfer_btn = ttk.Button(
            row, text="Transfer →", style="Accent.TButton",
            command=self._start_send)
        self.transfer_btn.pack(side="right")

    def _back_to_connect(self):
        self._show_view("connect")
        self.app.set_status("")

    def _start_send(self):
        if not self.panel.any_selected():
            messagebox.showerror("FreeMove", "Nothing is selected — "
                                 "use Edit… on a category first.")
            return
        host, pin, port = self.send_host, self.send_pin, self.peer_port
        self._show_view("progress")
        self.progress.reset()
        self.progress.set_summary(
            f"Sending to {host} — building the file list…")
        self.back_btn.configure(state="disabled")
        self.busy = True

        def work():
            try:
                with tempfile.TemporaryDirectory(
                        prefix="freemove-stage-") as stage:
                    items = self.panel.collect_items(Path(stage))
                    entries = collector.expand_selection(items)
                    if not entries:
                        raise ValueError("the selection is empty on disk")
                    report = Sender(
                        on_event=self.app._on_event).send(
                            host, port, pin, entries)
                self.app.post("done", report)
            except Exception as exc:
                self.app.post("error", {"error": str(exc)})
        threading.Thread(target=work, daemon=True).start()

    # -- receive ------------------------------------------------------------

    def _start_receive(self):
        dest = self.dest_var.get().strip()
        if not dest:
            messagebox.showerror("FreeMove", "Choose the folder to "
                                 "save incoming files in first.")
            return
        try:
            self.receiver = Receiver(dest, announce=True,
                                     on_event=self.app._on_event)
            self.receiver.prepare()
        except Exception as exc:
            messagebox.showerror("FreeMove", str(exc))
            self.receiver = None
            return
        self._closing_receiver = False
        self.pin_label.configure(text=f"PIN: {self.receiver.pin}")
        self.fp_label.configure(
            text="Certificate fingerprint: "
                 + self.receiver.identity.short_fingerprint()
                 + " — the sender's screen must show the same one.")
        self.start_btn.configure(state="disabled")
        self._show_view("progress")
        self.progress.reset()
        self.progress.set_summary(
            f"Waiting for the sender…  PIN {self.receiver.pin}  ·  "
            f"fingerprint "
            f"{self.receiver.identity.short_fingerprint()}")
        self.back_btn.configure(state="disabled")
        self.busy = True
        threading.Thread(target=self._receive_work, daemon=True).start()
        self.app.set_status("Receiving — waiting for the sender…")

    def _receive_work(self):
        receiver = self.receiver
        try:
            report = receiver.serve_once()
            if report and not report.get("failed"):
                self.app.post("recv_done", report)
        except Exception:
            pass  # serve_once already reports through on_event
        finally:
            self.app.post("recv_finished", None)

    # -- progress view ------------------------------------------------------

    def _build_progress(self):
        view = self.progress_view
        ttk.Label(view, text="Transfer", style="Title.TLabel").pack(
            anchor="w", pady=(0, 8))
        self.progress = ProgressPanel(view)
        self.progress.pack(fill="both", expand=True)
        row = ttk.Frame(view)
        row.pack(fill="x", pady=(10, 0))
        self.back_btn = ttk.Button(row, text="‹ Back",
                                   command=self._back_to_connect)
        self.back_btn.pack(side="left")

    def _show_view(self, name):
        for view_name, frame in (("connect", self.connect_view),
                                 ("select", self.select_view),
                                 ("progress", self.progress_view)):
            if view_name == name:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()

    # -- lifecycle / events ---------------------------------------------------

    def on_show(self):
        self.panel.refresh()

    def on_hide(self):
        if self.receiver is not None:
            self._closing_receiver = True
            try:
                self.receiver.close()
            except Exception:
                pass
            self.receiver = None
            self.busy = False
            self.start_btn.configure(state="normal")
            self.pin_label.configure(text="PIN: — — —")
            self.fp_label.configure(text="")

    def handle_event(self, kind, data) -> bool:
        if kind == "peers":
            self.peer_list = data
            self.peer_box.delete(0, "end")
            for peer in data:
                self.peer_box.insert("end", peer.label())
            self.hint.configure(
                text=f"Found {len(data)} receiver(s)." if data else
                "No receivers found — check both PCs are on the same "
                "network and receiving is started there, or type the "
                "address manually.")
            return True
        if kind == "peers_error":
            self.hint.configure(text=f"Search failed: {data}")
            return True
        if kind == "connected":
            self.send_host = data["host"]
            self.send_pin = data["pin"]
            self.peer_port = data["port"]
            self.connect_btn.configure(state="normal")
            self.connected_label.configure(
                text=f"Connected to {data['host']} — what should move?")
            self.connected_fp.configure(
                text="Certificate fingerprint: "
                     + short_fingerprint(data["fingerprint"])
                     + " — check it matches the other PC's screen before "
                       "transferring.")
            self._show_view("select")
            self.panel.refresh()
            self.app.set_status(f"Paired with {data['host']} ✓")
            return True
        if kind == "pair_failed":
            self.connect_btn.configure(state="normal")
            messagebox.showerror(
                "FreeMove", "Pairing failed — check the PIN and that "
                            f"the other PC is receiving.\n\n{data}")
            return True
        if kind in ("file_start", "progress", "file_done", "paired"):
            return self.progress.handle(kind, data)
        if kind == "listening":
            return True  # PIN/fingerprint are already on screen
        if kind == "done":  # sender finished; data is the receiver report
            self.busy = False
            self.back_btn.configure(state="normal")
            count = len(data.get("received", []))
            self.progress.set_summary(
                f"Done ✓ — {count} file(s) sent; the other PC verified "
                "every file's hash before placing it.")
            self.app.set_status("Transfer complete ✓")
            return True
        if kind == "recv_done":
            self.busy = False
            self.back_btn.configure(state="normal")
            self.progress.set_summary(
                f"Done ✓ — received {len(data.get('received', []))} "
                f"file(s), {fmt_size(data.get('bytes', 0))}, all "
                f"hash-verified. A transfer report was saved in "
                f"{data.get('destination', '')}.")
            self.app.set_status("Transfer complete ✓")
            return True
        if kind == "recv_finished":
            if self.receiver is not None:
                self.receiver.close()
                self.receiver = None
            self.start_btn.configure(state="normal")
            return True
        if kind == "error":
            if self._closing_receiver:
                return True
            self.busy = False
            self.back_btn.configure(state="normal")
            message = str(data.get("error", data)) \
                if isinstance(data, dict) else str(data)
            self.progress.say(f"ERROR: {message}")
            self.progress.set_summary(f"Stopped with an error: {message}")
            messagebox.showerror("FreeMove", message)
            return True
        return False


class ImageScreen(Screen):
    """Image File: create a .fmimg from a category selection, or
    restore one into a folder."""

    title = "Image File"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.busy = False

        create = ttk.Frame(self, style="Card.TFrame", padding=14,
                           borderwidth=1, relief="solid")
        create.pack(fill="x")
        ttk.Label(create, text="Create an image",
                  style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(create, text="Pack the selection into one .fmimg "
                  "file — for a USB drive, a dead-PC rescue, or a "
                  "backup.", style="CardMuted.TLabel",
                  wraplength=900).pack(anchor="w", pady=(2, 8))
        self.panel = SelectionPanel(create, self.app, "image-select")
        self.panel.pack(fill="x")
        row = ttk.Frame(create, style="Card.TFrame")
        row.pack(fill="x", pady=(10, 0))
        ttk.Label(row, text="Image file:", style="Card.TLabel").grid(
            row=0, column=0, sticky="e", pady=2)
        self.out_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.out_var).grid(
            row=0, column=1, sticky="ew", padx=4, pady=2)
        ttk.Button(row, text="Browse…", command=self._browse_out).grid(
            row=0, column=2, pady=2)
        ttk.Label(row, text="Passphrase (optional):",
                  style="Card.TLabel").grid(row=1, column=0,
                                            sticky="e", pady=2)
        self.create_pass = tk.StringVar()
        ttk.Entry(row, textvariable=self.create_pass, show="•").grid(
            row=1, column=1, sticky="ew", padx=4, pady=2)
        if archive.crypto_available():
            note = "AES-256-GCM when a passphrase is set."
        else:
            note = "Encryption unavailable: the 'cryptography' package " \
                   "is missing, so a passphrase would be refused."
        ttk.Label(row, text=note, style="CardMuted.TLabel").grid(
            row=1, column=2, sticky="w", pady=2)
        row.columnconfigure(1, weight=1)
        self.create_btn = ttk.Button(
            create, text="Create image", style="Accent.TButton",
            command=self._create)
        self.create_btn.pack(anchor="w", pady=(10, 0))

        restore = ttk.Frame(self, style="Card.TFrame", padding=14,
                            borderwidth=1, relief="solid")
        restore.pack(fill="x", pady=(12, 0))
        ttk.Label(restore, text="Restore an image",
                  style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(restore, text="Every file is hash-verified before "
                  "it is placed — a tampered image restores nothing.",
                  style="CardMuted.TLabel", wraplength=900).pack(
                      anchor="w", pady=(2, 8))
        rrow = ttk.Frame(restore, style="Card.TFrame")
        rrow.pack(fill="x")
        ttk.Label(rrow, text="Image file:", style="Card.TLabel").grid(
            row=0, column=0, sticky="e", pady=2)
        self.image_var = tk.StringVar()
        ttk.Entry(rrow, textvariable=self.image_var).grid(
            row=0, column=1, sticky="ew", padx=4, pady=2)
        ttk.Button(rrow, text="Browse…", command=self._browse_image).grid(
            row=0, column=2, pady=2)
        ttk.Label(rrow, text="Restore into:", style="Card.TLabel").grid(
            row=1, column=0, sticky="e", pady=2)
        self.dest_var = tk.StringVar()
        ttk.Entry(rrow, textvariable=self.dest_var).grid(
            row=1, column=1, sticky="ew", padx=4, pady=2)
        ttk.Button(rrow, text="Browse…", command=self._browse_dest).grid(
            row=1, column=2, pady=2)
        ttk.Label(rrow, text="Passphrase:", style="Card.TLabel").grid(
            row=2, column=0, sticky="e", pady=2)
        self.restore_pass = tk.StringVar()
        ttk.Entry(rrow, textvariable=self.restore_pass, show="•").grid(
            row=2, column=1, sticky="ew", padx=4, pady=2)
        rrow.columnconfigure(1, weight=1)
        self.restore_btn = ttk.Button(
            restore, text="Restore image", style="Accent.TButton",
            command=self._restore)
        self.restore_btn.pack(anchor="w", pady=(10, 0))

        self.busy_bar = ttk.Progressbar(self, mode="indeterminate")
        self.result = ttk.Label(self, text="", style="Summary.TLabel",
                                wraplength=920, justify="left")

    # -- helpers ---------------------------------------------------------

    def _browse_out(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".fmimg",
            filetypes=[("FreeMove image", "*.fmimg")])
        if path:
            self.out_var.set(path)

    def _browse_image(self):
        path = filedialog.askopenfilename(
            filetypes=[("FreeMove image", "*.fmimg")])
        if path:
            self.image_var.set(path)

    def _browse_dest(self):
        folder = filedialog.askdirectory(title="Restore into which folder?")
        if folder:
            self.dest_var.set(folder)

    def _set_busy(self, busy: bool, text: str = ""):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.create_btn.configure(state=state)
        self.restore_btn.configure(state=state)
        if busy:
            self.busy_bar.pack(fill="x", pady=(12, 0))
            self.busy_bar.start(12)
            self.result.configure(text=text)
            self.result.pack(anchor="w", pady=(6, 0))
        else:
            self.busy_bar.stop()
            self.busy_bar.pack_forget()

    # -- actions -----------------------------------------------------------

    def _create(self):
        out = self.out_var.get().strip()
        if not out:
            messagebox.showerror("FreeMove", "Choose where to write "
                                 "the .fmimg file.")
            return
        if not self.panel.any_selected():
            messagebox.showerror("FreeMove", "Nothing is selected — "
                                 "use Edit… on a category first.")
            return
        passphrase = self.create_pass.get() or None
        self._set_busy(True, "Creating the image…")

        def work():
            try:
                with tempfile.TemporaryDirectory(
                        prefix="freemove-stage-") as stage:
                    items = self.panel.collect_items(Path(stage))
                    entries = collector.expand_selection(items)
                    if not entries:
                        raise ValueError("the selection is empty on disk")
                    report = archive.export_image(
                        entries, out, passphrase=passphrase,
                        on_missing_crypto="error")
                state = "AES-256-GCM encrypted" if report.encrypted \
                    else "unencrypted"
                self.app.post("img_done",
                              f"Wrote {report.image}: {report.files} "
                              f"file(s), {fmt_size(report.total_bytes)} "
                              f"— {state}.")
            except Exception as exc:
                self.app.post("img_error", str(exc))
        threading.Thread(target=work, daemon=True).start()

    def _restore(self):
        image = self.image_var.get().strip()
        dest = self.dest_var.get().strip()
        if not image or not dest:
            messagebox.showerror("FreeMove", "Pick the .fmimg file and "
                                 "the folder to restore into.")
            return
        passphrase = self.restore_pass.get() or None
        self._set_busy(True, "Restoring — verifying every file's hash…")

        def work():
            try:
                report = archive.import_image(image, dest,
                                              passphrase=passphrase)
                text = f"Imported {len(report.placed)} file(s) into " \
                       f"{dest} — all hashes verified ✓."
                if report.failed:
                    text += f"  ({len(report.failed)} file(s) failed)"
                self.app.post("img_done", text)
            except Exception as exc:
                self.app.post("img_error", str(exc))
        threading.Thread(target=work, daemon=True).start()

    # -- events --------------------------------------------------------------

    def on_show(self):
        self.panel.refresh()

    def handle_event(self, kind, data) -> bool:
        if kind == "img_done":
            self._set_busy(False)
            self.result.configure(text=data)
            self.result.pack(anchor="w", pady=(6, 0))
            self.app.set_status(data)
            return True
        if kind == "img_error":
            self._set_busy(False)
            self.result.configure(text=f"Error: {data}")
            self.result.pack(anchor="w", pady=(6, 0))
            messagebox.showerror("FreeMove", str(data))
            return True
        return False


class MoveScreen(Screen):
    """App Migration: move one app to another drive on this PC."""

    title = "App Migration"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.apps: list[apps_mod.InstalledApp] = []
        self._loaded = False
        card = ttk.Frame(self, style="Card.TFrame", padding=14,
                         borderwidth=1, relief="solid")
        card.pack(fill="x")
        ttk.Label(card, text="Move an app to another drive",
                  style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(card, text="The app is copied, every file is "
                  "hash-verified, and only then is the original path "
                  "turned into a junction pointing at the new home — "
                  "so the app keeps working from the same path while "
                  "the space is freed on the old drive.",
                  style="CardMuted.TLabel", wraplength=900).pack(
                      anchor="w", pady=(2, 10))
        ttk.Label(card, text="Installed apps (select one, or type a "
                  "folder below):", style="Card.TLabel").pack(anchor="w")
        list_row = ttk.Frame(card, style="Card.TFrame")
        list_row.pack(fill="x", pady=(2, 8))
        self.app_box = tk.Listbox(list_row, height=8, activestyle="none")
        self.app_box.pack(side="left", fill="x", expand=True)
        scroll = ttk.Scrollbar(list_row, orient="vertical",
                               command=self.app_box.yview)
        scroll.pack(side="right", fill="y")
        self.app_box.configure(yscrollcommand=scroll.set)
        self.app_box.bind("<<ListboxSelect>>", self._app_selected)
        ttk.Button(list_row, text="Refresh",
                   command=self._refresh).pack(side="left", padx=4,
                                               anchor="n")
        form = ttk.Frame(card, style="Card.TFrame")
        form.pack(fill="x")
        ttk.Label(form, text="App folder:", style="Card.TLabel").grid(
            row=0, column=0, sticky="e", pady=2)
        self.source_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.source_var).grid(
            row=0, column=1, sticky="ew", padx=4, pady=2)
        ttk.Button(form, text="Browse…", command=self._browse_source).grid(
            row=0, column=2, pady=2)
        ttk.Label(form, text="Move to (drive/folder root):",
                  style="Card.TLabel").grid(row=1, column=0, sticky="e",
                                            pady=2)
        self.target_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.target_var).grid(
            row=1, column=1, sticky="ew", padx=4, pady=2)
        ttk.Button(form, text="Browse…", command=self._browse_target).grid(
            row=1, column=2, pady=2)
        form.columnconfigure(1, weight=1)
        self.move_btn = ttk.Button(card, text="Move app",
                                   style="Accent.TButton",
                                   command=self._move)
        self.move_btn.pack(anchor="w", pady=(12, 0))
        self.result = ttk.Label(self, text="", style="Summary.TLabel",
                                wraplength=920, justify="left")
        self.result.pack(anchor="w", pady=(10, 0))

    def _refresh(self):
        self._loaded = False
        self.on_show()

    def on_show(self):
        if self._loaded:
            return

        def work():
            try:
                apps = apps_mod.list_installed_apps()
                self.app.post("move_apps", apps)
            except Exception as exc:
                self.app.post("move_error", str(exc))
        threading.Thread(target=work, daemon=True).start()

    def _app_selected(self, _event=None):
        selection = self.app_box.curselection()
        if selection and selection[0] < len(self.apps):
            app = self.apps[selection[0]]
            if app.install_location:
                self.source_var.set(app.install_location)
            else:
                self.app.set_status(
                    f"{app.name}: no install folder is recorded — type "
                    "its folder instead.")

    def _browse_source(self):
        folder = filedialog.askdirectory(title="The app's folder")
        if folder:
            self.source_var.set(folder)

    def _browse_target(self):
        folder = filedialog.askdirectory(
            title="Move to — the other drive's root folder")
        if folder:
            self.target_var.set(folder)

    def _move(self):
        source = self.source_var.get().strip()
        target = self.target_var.get().strip()
        if not source or not target:
            messagebox.showerror("FreeMove", "Set the app folder and "
                                 "the target drive root.")
            return
        self.move_btn.configure(state="disabled")
        self.result.configure(text=f"Moving {source} → {target} …")

        def work():
            try:
                result = apps_mod.local_move_app(source, target)
                self.app.post(
                    "move_done",
                    f"Moved {result.files} file(s) "
                    f"({fmt_size(result.bytes_moved)}) from "
                    f"{result.source} to {result.target}; the original "
                    "path now points there, so the app keeps working. "
                    "Verified ✓")
            except Exception as exc:
                self.app.post("move_error", str(exc))
        threading.Thread(target=work, daemon=True).start()

    def handle_event(self, kind, data) -> bool:
        if kind == "move_apps":
            self.apps = data
            self._loaded = True
            self.app_box.delete(0, "end")
            for app in data:
                loc = f"   [{app.install_location}]" \
                    if app.install_location else ""
                self.app_box.insert("end", f"{app.label()}{loc}")
            if not data:
                self.app.set_status("No installed apps found on this "
                                    "PC — type the app folder instead.")
            return True
        if kind == "move_done":
            self.move_btn.configure(state="normal")
            self.result.configure(text=data)
            self.app.set_status("App moved ✓")
            return True
        if kind == "move_error":
            self.move_btn.configure(state="normal")
            self.result.configure(text=f"Error: {data}")
            messagebox.showerror("FreeMove", str(data))
            return True
        return False


class KeysScreen(Screen):
    """Program Keys: scan for recoverable license keys and export."""

    title = "Program Keys"

    def __init__(self, master, app):
        super().__init__(master, app)
        self.keys: list[apps_mod.ProgramKey] = []
        card = ttk.Frame(self, style="Card.TFrame", padding=14,
                         borderwidth=1, relief="solid")
        card.pack(fill="both", expand=True)
        ttk.Label(card, text="Program keys stored on this PC",
                  style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(card, text="Only keys stored in plain registry "
                  "values can be recovered — many modern apps keep "
                  "theirs encrypted or account-based, and no tool can "
                  "extract those. Export what is found before wiping "
                  "the old PC.", style="CardMuted.TLabel",
                  wraplength=900).pack(anchor="w", pady=(2, 10))
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(0, 8))
        self.scan_btn = ttk.Button(row, text="Scan for keys",
                                   style="Accent.TButton",
                                   command=self._scan)
        self.scan_btn.pack(side="left")
        self.count_label = ttk.Label(row, text="Not scanned yet.",
                                     style="Card.TLabel")
        self.count_label.pack(side="left", padx=10)
        self.export_btn = ttk.Button(row, text="Export…",
                                     command=self._export,
                                     state="disabled")
        self.export_btn.pack(side="right")
        columns = ("app", "value", "key")
        self.tree = ttk.Treeview(card, columns=columns,
                                 show="headings", height=14)
        self.tree.heading("app", text="Program")
        self.tree.heading("value", text="Registry value")
        self.tree.heading("key", text="Key")
        self.tree.column("app", width=300)
        self.tree.column("value", width=180)
        self.tree.column("key", width=380)
        self.tree.pack(fill="both", expand=True)

    def _scan(self):
        self.scan_btn.configure(state="disabled")
        self.count_label.configure(text="Scanning…")

        def work():
            try:
                found = apps_mod.scan_program_keys(
                    apps_mod.list_installed_apps())
                self.app.post("keys_done", found)
            except Exception as exc:
                self.app.post("keys_error", str(exc))
        threading.Thread(target=work, daemon=True).start()

    def _export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt")],
            initialfile="freemove-program-keys.txt")
        if not path:
            return
        try:
            apps_mod.export_keys_report(self.keys, path)
            self.app.set_status(f"Exported {len(self.keys)} key(s) "
                                f"to {path}")
        except Exception as exc:
            messagebox.showerror("FreeMove", str(exc))

    def handle_event(self, kind, data) -> bool:
        if kind == "keys_done":
            self.keys = data
            self.scan_btn.configure(state="normal")
            self.export_btn.configure(state="normal")
            for row in self.tree.get_children():
                self.tree.delete(row)
            for key in data:
                self.tree.insert("", "end",
                                 values=(key.app, key.value_name, key.key))
            self.count_label.configure(
                text=f"Found {len(data)} recoverable key(s).")
            return True
        if kind == "keys_error":
            self.scan_btn.configure(state="normal")
            self.count_label.configure(text="Scan failed.")
            messagebox.showerror("FreeMove", str(data))
            return True
        return False


# ---------------------------------------------------------------------------
# Application shell
# ---------------------------------------------------------------------------

class FreeMoveApp:
    def __init__(self, root):
        self.root = root
        self.events: queue.Queue = queue.Queue()
        self._panels: dict[str, SelectionPanel] = {}
        root.title(f"FreeMove {__version__} — free, secure PC migration")
        root.geometry("1000x640")
        root.minsize(900, 580)
        root.configure(background=BG)
        self._styles()
        self._build()
        self.root.after(100, self._drain_events)

    # -- setup -----------------------------------------------------------

    def _styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        base = tkfont.nametofont("TkDefaultFont")
        family = base.cget("family")
        self.fonts = {
            "title": tkfont.Font(root=self.root, family=family, size=15,
                                 weight="bold"),
            "card_title": tkfont.Font(root=self.root, family=family,
                                      size=11, weight="bold"),
            "pin": tkfont.Font(root=self.root, family=family, size=20,
                               weight="bold"),
            "summary": tkfont.Font(root=self.root, family=family,
                                   size=10, weight="bold"),
        }
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Title.TLabel", background=BG, foreground=TEXT,
                        font=self.fonts["title"])
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Summary.TLabel", background=BG,
                        foreground=TEXT, font=self.fonts["summary"])
        style.configure("Card.TFrame", background=CARD)
        style.configure("Card.TLabel", background=CARD, foreground=TEXT)
        style.configure("CardTitle.TLabel", background=CARD,
                        foreground=TEXT, font=self.fonts["card_title"])
        style.configure("CardMuted.TLabel", background=CARD,
                        foreground=MUTED)
        style.configure("Pin.TLabel", background=CARD, foreground=ACCENT,
                        font=self.fonts["pin"])
        style.configure("Accent.TButton", background=ACCENT,
                        foreground="white", padding=(14, 6),
                        borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", ACCENT_DARK),
                              ("disabled", "#9db8cc")])
        style.configure("TRadiobutton", background=CARD)
        style.configure("TCheckbutton", background=CARD)
        style.configure("TProgressbar", troughcolor="#dde5eb",
                        background=ACCENT, borderwidth=0)

    def _build(self):
        header = tk.Frame(self.root, background=ACCENT, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)
        self.home_btn = tk.Button(
            header, text="‹ Home", command=lambda: self.show("home"),
            background=ACCENT, foreground="white", relief="flat",
            activebackground=ACCENT_DARK, activeforeground="white",
            borderwidth=0, padx=10)
        title_box = tk.Frame(header, background=ACCENT)
        title_box.pack(side="left", padx=14, pady=8)
        tk.Label(title_box, text="FreeMove", background=ACCENT,
                 foreground="white",
                 font=self.fonts["card_title"]).pack(anchor="w")
        tk.Label(title_box, text="Free, secure PC migration — no "
                 "accounts, no cloud, no limits", background=ACCENT,
                 foreground="#d7e7f3").pack(anchor="w")
        tk.Label(header, text=f"v{__version__}", background=ACCENT,
                 foreground="#d7e7f3").pack(side="right", padx=14)

        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True)
        self.screens: dict[str, Screen] = {}
        for name, cls in (("home", HomeScreen), ("pcp", PcScreen),
                          ("image", ImageScreen), ("move", MoveScreen),
                          ("keys", KeysScreen)):
            screen = cls(body, self)
            self.screens[name] = screen
        self.active: str | None = None

        status = ttk.Frame(self.root, padding=(10, 4))
        status.pack(fill="x")
        self.status_var = tk.StringVar(
            value="Ready. Pick a job on the home screen.")
        ttk.Label(status, textvariable=self.status_var,
                  style="Muted.TLabel").pack(side="left")
        self.show("home")

    # -- navigation ---------------------------------------------------------

    def show(self, name: str):
        if self.active == name:
            return
        if self.active is not None:
            self.screens[self.active].on_hide()
            self.screens[self.active].pack_forget()
        self.active = name
        screen = self.screens[name]
        screen.pack(fill="both", expand=True)
        screen.on_show()
        if name == "home":
            self.home_btn.pack_forget()
            self.set_status("Ready. Pick a job on the home screen.")
        else:
            self.home_btn.pack(side="left", padx=(6, 0))
            self.set_status(f"{screen.title} — "
                            f"{'‹ Home to go back.'}")

    def set_status(self, text: str):
        self.status_var.set(text)

    # -- event plumbing --------------------------------------------------------

    def register_panel(self, token: str, panel: SelectionPanel):
        self._panels[token] = panel

    def post(self, kind, data):
        self.events.put((kind, data))

    def _on_event(self, kind, data):
        """Backend on_event callback (any thread) -> the UI queue."""
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
        if kind in ("sel_sizes", "sel_apps"):
            for panel in self._panels.values():
                if panel.handle_app_event(kind, data):
                    break
            return
        screen = self.screens.get(self.active or "")
        if screen is not None and screen.handle_event(kind, data):
            return
        if kind == "error":
            message = str(data.get("error", data)) \
                if isinstance(data, dict) else str(data)
            messagebox.showerror("FreeMove", message)


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
