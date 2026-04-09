# -*- mode: python ; coding: utf-8 -*-
"""
SS-Tools Ultimate v3.5.0 - PyInstaller Spec File (Hidden Web Monitor)
Build command: pyinstaller ss_tools_hidden_web.spec
Creates single .exe with web monitor running hidden in background
"""

import sys
import os

block_cipher = None

a = Analysis(
    ['main_with_hidden_web.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('data/cheat_keywords.json', 'data'),
        ('web_monitor/templates/', 'web_monitor/templates'),
        ('web_monitor/static/', 'web_monitor/static'),
    ],
    hiddenimports=[
        'PyQt6',
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'psutil',
        'flask',
        'flask_cors',
        'flask_socketio',
        'python_socketio',
        'python_engineio',
        'PIL',
        'threading',
        'json',
        'sqlite3',
        'hashlib',
        'zipfile',
        'struct',
        'subprocess',
        'multiprocessing',
        'concurrent.futures',
        'urllib.request',
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
    console=False,  # NO CONSOLE - HIDDEN
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

# Create bundle for macOS (if needed)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SS-Tools-Ultimate'
)
