# FreeMove

**A free, secure, open PC-to-PC migration tool for Windows.**

FreeMove moves your files, application bundles, user profile, browser
data, mail stores and settings from an old PC to a new one — over your
own LAN, through an offline image file, or between disks on the same
machine. It exists because the commercial tools (it is modelled on
the feature set of EaseUS Todo PCTrans) charge for what is, at its
core, a careful copy with good bookkeeping.

- **No limits.** No 500 MB cap, no 2-app cap, no paid tiers.
- **No account, no cloud, no telemetry.** Nothing leaves your network.
- **Secure by design.** PIN-paired, TLS-encrypted, hash-verified.
- **Open source** (MIT). One Python codebase you can audit end to end.

## Download

**Get `FreeMove.exe` from the
[Releases page](https://github.com/jtfresh90/FreeMove/releases)** —
a single self-contained executable for Windows. No Python, no
installer, nothing else to download. Run it on both PCs.

Every tagged release (`v*`) is built automatically from this repo by
the GitHub Actions workflow in `.github/workflows/build-windows.yml`,
so the published `.exe` always corresponds to a commit you can read.

## What it does

| Capability | PCTrans Free | PCTrans Pro | **FreeMove** |
|---|---|---|---|
| PC-to-PC transfer over LAN/Wi-Fi | ✅ (500 MB cap) | ✅ | ✅ **unlimited** |
| Image-file transfer (offline / dead-PC data rescue) | ❌ | ✅ | ✅ |
| Local transfer between disks (C: → D:) | ✅ (limited) | ✅ | ✅ |
| Files & folders | ✅ | ✅ | ✅ |
| Installed apps (files + settings) | 2 apps | ✅ | ✅ **unlimited** |
| User accounts / profile migration | ❌ | ✅ | ✅ profile + personalisation bundle |
| Browser favorites & profile data | ✅ | ✅ | ✅ |
| Mail data | ✅ | ✅ | ✅ PST/OST + Thunderbird stores |
| Scan & export program keys | ❌ | ✅ | ✅ |
| 32-bit → 64-bit transfers | ✅ | ✅ | ✅ |
| Windows XP → 11 + Server | ✅ | ✅ | ✅ (Python 3.11 runtime permitting; see notes) |
| Command-line operation | ❌ (Technician) | 💲 | ✅ **free, built in** |
| Account / sign-up required | ✅ | ✅ | ❌ **never** |
| Telemetry / cloud relay | vendor cloud features | | ❌ **none — LAN only** |
| Price | $0 (capped) | paid | **$0, MIT-licensed** |

### The three modes

1. **PC to PC** — both PCs run FreeMove on the same network. The new
   PC chooses *Receive* and shows a pairing PIN; the old PC chooses
   *Send*, picks the receiver, enters the PIN, and transfers.
   Interrupted transfers **resume** where they left off.
2. **Image file** — export a selection to a single `.fmimg` file
   (optionally passphrase-encrypted), carry it on external media, and
   import it on the new PC. This is also the data-rescue path for a
   dead PC: slave its drive in another machine (or boot from rescue
   media) and export from the mounted drive.
3. **Local move** — free up C: by moving an app's folder to another
   drive. FreeMove copies it, verifies the copy hash-for-hash, and
   replaces the original folder with an NTFS junction, so the app
   keeps working from its old path. Verification failure = automatic
   rollback; the original is never deleted until the new location is
   proven good.

## Security design

Migration tools move *everything you own*; they should be paranoid.

- **Pairing.** The receiver displays a 6-digit PIN. The sender enters
  it; both sides derive a session key with PBKDF2-HMAC-SHA256
  (200,000 iterations, fresh random salts from both peers).
- **TLS with fingerprint pinning — not blind trust.** The receiver
  generates a fresh self-signed certificate per session. Its SHA-256
  fingerprint is announced in the pairing handshake, and the sender's
  proof (`HMAC(session_key, fingerprint)`) authenticates it: a
  man-in-the-middle who substitutes his own certificate cannot forge
  the proof without the PIN. The data connection then runs TLS 1.2+
  and the client refuses any certificate whose fingerprint differs
  from the pinned one. There is **no plaintext mode**.
- **Integrity.** Every file travels under a manifest SHA-256. The
  receiver verifies each file *before* placing it; a corrupt or
  tampered file is rejected and reported, never silently written.
- **Path safety.** Manifest paths are sanitised — a sender cannot
  write outside the chosen destination folder.
- **Image encryption** (optional) uses AES-256-GCM from the vetted
  `cryptography` package, key derived with PBKDF2. If that package
  isn't installed, FreeMove says so loudly and writes an unencrypted
  image rather than pretending. It never hand-rolls crypto.
- **Local only.** Discovery is LAN broadcast; transfers are direct
  PC-to-PC. No servers, no relays, no analytics, no update checks.

## Run from source

```powershell
# Windows, Python 3.11+
python run_freemove.py            # GUI
python cli.py receive --dest D:\Incoming
python cli.py send --host 192.168.1.50 --pin 123456 --profile --browsers --mail --path C:\Data
python cli.py discover
python cli.py export-image --out move.fmimg --profile --passphrase
python cli.py import-image move.fmimg --dest C:\Users\me --passphrase
python cli.py apps list
python cli.py apps move "C:\Program Files\SomeApp" --to D:\Apps
python cli.py keys export --out keys.txt
```

Build the standalone executable yourself, if you prefer:

```powershell
build_windows.bat        # tests + PyInstaller -> dist\FreeMove.exe
```

Run the test suite (loopback end-to-end, resume, tamper detection,
image round-trip, app inventory/local-move):

```powershell
python -m pytest tests\ -q
```

## Honest limits

FreeMove will not oversell itself — and neither should the commercial
tools, whose fine print says much of the same:

- **App relocation is best-effort.** Self-contained apps move well.
  Apps with Windows services, drivers, shell extensions, or
  machine-bound licensing/DRM may still need a reinstall on the new
  PC. (PCTrans has the same ceiling — and like it, FreeMove cannot
  move 64-bit apps onto a 32-bit Windows.)
- **Account passwords are NOT migrated.** Windows logon passwords and
  other LSA/DPAPI secrets are cryptographically tied to the original
  machine/account and cannot be transferred by any tool. You set a
  password on the new account yourself.
- **Browser saved passwords usually won't survive.** Cookies,
  bookmarks, history and the rest of the profile move fine, but saved
  passwords inside the profile are DPAPI-encrypted to the *old*
  account and generally won't decrypt on the new PC. Export passwords
  from the browser itself (or use its sync) if you rely on them.
- **Program-key recovery finds what's findable.** Keys stored in
  plain registry values are exported; keys held in encrypted blobs or
  vendor accounts (Microsoft, Adobe, Steam…) are not recoverable from
  the PC by anyone.
- **Domain accounts and mass deployment** are out of scope for v1.
  Some operations (moving apps out of `Program Files`, reading other
  users' profiles) need an administrator account.
- **Windows XP note:** FreeMove's code avoids post-XP assumptions
  where practical, but it runs on Python 3.11, which itself needs
  Windows 8.1+; on a genuinely old source PC, use image mode from a
  newer machine with the old drive attached.

## Layout

```
freemove/            the package
  discovery.py       LAN peer discovery (UDP broadcast)
  security.py        PIN pairing, PBKDF2, TLS + fingerprint pinning
  protocol.py        framing, manifest, SHA-256 verification
  collector.py       profile / browser / mail / settings selection
  apps.py            app inventory, bundles, program keys, local move
  archive.py         .fmimg image export/import (+ AES-GCM option)
  server.py          receiver        client.py   sender
  gui.py             Tkinter GUI     cli.py      command line
tests/               pytest suite (runs on any OS)
freemove.spec        PyInstaller one-file windowed build -> FreeMove.exe
build_windows.bat    local Windows build
.github/workflows/   CI: test + build + release asset on v* tags
```

## License

MIT — see [LICENSE](LICENSE). FreeMove is an original implementation
written from the published feature descriptions of commercial
migration tools; it contains no EaseUS code, assets, or branding.
