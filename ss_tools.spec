# -*- mode: python ; coding: utf-8 -*-
"""
SS-Tools Ultimate v3.0 - PyInstaller Spec File
Build command: pyinstaller ss_tools.spec
"""

import sys
import os

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('data/cheat_keywords.json', 'data'),
    ],
    hiddenimports=[
        'PyQt6',
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'psutil',
        'json',
        'sqlite3',
        'hashlib',
        'zipfile',
        'struct',
        'difflib',
        'subprocess',
        'threading',
        'multiprocessing',
        'concurrent.futures',
        'urllib.request',
        'tempfile',
        'shutil',
        'socket',
        're',
        'glob',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'scipy',
        'pandas',
        'IPython',
        'jupyter',
        'notebook',
        'test',
        'unittest',
    ],
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
    name='SS-Tools-Ultimate',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window (GUI app)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,              # Add icon path here: icon='assets/icon.ico'
)
