# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'gui',
        'core',
        'core.scan_engine',
        'core.process_scanner',
        'core.file_scanner',
        'core.registry_scanner',
        'core.kernel_check',
        'core.mods_scanner',
        'core.vpn_proxy_scanner',
        'core.service_scanner',
        'core.clipboard_scanner',
        'core.gpu_driver_scanner',
        'core.browser_scanner',
        'core.screenshot_scanner',
        'core.behavior_analyzer',
        'core.keybind_detector',
        'core.screen_live_streamer',
        'core.hwid_spoofer',
        'core.injector_detector',
        'core.launcher_check',
        'gui.main_window',
        'gui.styles',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=[],
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
    name='SS-TOOLS-Ultimate',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
