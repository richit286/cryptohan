# -*- mode: python ; coding: utf-8 -*-
"""Spec PyInstaller untuk membangun CryptoHan sebagai satu .exe Windows.

Build (dari root repo, setelah `pip install -e ".[transport,build]"`):

    pyinstaller packaging/cryptohan.spec --noconfirm --clean

Output: dist/cryptohan/cryptohan.exe (mode onedir).
"""

import os
from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

SPEC_DIR = os.path.dirname(os.path.abspath(SPEC))
ROOT_DIR = os.path.dirname(SPEC_DIR)
SRC_DIR = os.path.join(ROOT_DIR, "src")

hiddenimports = collect_submodules("noise") + collect_submodules("cryptography")

a = Analysis(
    [os.path.join(SRC_DIR, "cryptohan", "__main__.py")],
    pathex=[SRC_DIR],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="cryptohan",
    debug=False,
    strip=False,
    upx=True,
    console=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name="cryptohan",
)
