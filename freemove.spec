# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for FreeMove — one-file, windowed, named FreeMove.

Build (Windows):  pyinstaller freemove.spec   ->   dist/FreeMove.exe
The GitHub Actions workflow (.github/workflows/build-windows.yml)
does exactly this on every version tag.
"""

block_cipher = None

a = Analysis(
    ["run_freemove.py"],
    pathex=[],
    binaries=[],
    datas=[],
    # `cryptography` is optional at runtime (image encryption); bundle
    # it when present so the shipped .exe always supports it.
    hiddenimports=["cryptography"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="FreeMove",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # windowed: double-click opens the GUI
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
