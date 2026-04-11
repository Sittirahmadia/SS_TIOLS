"""
SS-Tools Ultimate - Minecraft SS AntiCheat Scanner
Central configuration for all modules and settings.

Version 1.0 - Enhanced with:
  - Admin privilege detection and UAC elevation
  - Gaming peripheral whitelist (Logitech, Razer, Corsair, SteelSeries, etc.)
  - Multi-layer detection config (hash + signature + behavior + memory + bytecode)
  - Decompiler integration paths
"""
import os
import json
import sys
import ctypes
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List

APP_NAME = "Minecraft SS AntiCheat Scanner"
APP_VERSION = "1.0.0"
APP_AUTHOR = "SS-Tools Team"
APP_YEAR = 2026

# Paths
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys._MEIPASS)
    APP_DIR = Path(os.path.dirname(sys.executable))
else:
    BASE_DIR = Path(__file__).parent.parent
    APP_DIR = BASE_DIR

DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = APP_DIR / "Evidence"
CACHE_DIR = APP_DIR / ".cache"
LOGS_DIR = APP_DIR / "logs"
REPORTS_DIR = APP_DIR / "Reports"

for d in [EVIDENCE_DIR, CACHE_DIR, LOGS_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

DATABASE_FILE = DATA_DIR / "cheat_keywords.json"
SETTINGS_FILE = APP_DIR / "settings.json"

# Database auto-update URL
DATABASE_UPDATE_URL = (
    "https://raw.githubusercontent.com/Sittirahmadia/SS_TIOLS/main/data/cheat_keywords.json"
)

# Decompiler options
DECOMPILER_OPTIONS = ["CFR", "FernFlower", "Procyon", "Vineflower"]

# Minecraft launcher paths (relative to user home or appdata)
MINECRAFT_LAUNCHER_PATHS = {
    "Official Launcher": [
        "{APPDATA}/.minecraft",
        "{HOME}/.minecraft",
    ],
    "TLauncher": [
        "{APPDATA}/.tlauncher",
        "{APPDATA}/tlauncher",
        "{HOME}/.tlauncher",
    ],
    "CurseForge": [
        "{APPDATA}/curseforge/minecraft",
        "{HOME}/curseforge/minecraft",
    ],
    "MultiMC": [
        "{APPDATA}/MultiMC",
        "{LOCALAPPDATA}/MultiMC",
        "{HOME}/.local/share/multimc",
    ],
    "Prism Launcher": [
        "{APPDATA}/PrismLauncher",
        "{LOCALAPPDATA}/PrismLauncher",
        "{HOME}/.local/share/PrismLauncher",
    ],
    "GDLauncher": [
        "{APPDATA}/gdlauncher_next",
        "{HOME}/.config/gdlauncher_next",
    ],
    "ATLauncher": [
        "{APPDATA}/ATLauncher",
        "{HOME}/.atlauncher",
    ],
    "HMCL": [
        "{APPDATA}/.hmcl",
        "{HOME}/.hmcl",
    ],
    "SKLauncher": [
        "{APPDATA}/SKLauncher",
        "{HOME}/.sklauncher",
    ],
    "Badlion Client": [
        "{APPDATA}/.minecraft_badlion",
        "{APPDATA}/Badlion Client",
    ],
    "Lunar Client": [
        "{USERPROFILE}/.lunarclient",
        "{HOME}/.lunarclient",
    ],
    "Feather Client": [
        "{APPDATA}/Feather Client",
        "{APPDATA}/.feather",
    ],
    "LabyMod": [
        "{APPDATA}/.labymod",
    ],
    "Technic Launcher": [
        "{APPDATA}/.technic",
        "{HOME}/.technic",
    ],
    "Void Launcher": [
        "{APPDATA}/.voidlauncher",
    ],
}

MINECRAFT_SCAN_DIRS = [
    "mods", "logs", "config", "saves", "resourcepacks",
    "shaderpacks", "versions", "libraries", "crash-reports",
    "screenshots", "replay_recordings",
]

# ── Gaming peripheral software whitelist ───────────────────────────────
# These are legitimate gaming software - detecting them is a false positive.
# Only their MACRO CONTENTS should be inspected, not the software itself.
GAMING_SOFTWARE_WHITELIST = {
    # Process names that are always safe (lowercase)
    "processes": [
        # Logitech
        "lghub.exe", "lghub_agent.exe", "lghub_updater.exe",
        "lcore.exe", "logitechg_backlight.exe", "logi_lamparray_service.exe",
        # Razer
        "razercentral.exe", "razercentralservice.exe", "razersynapse.exe",
        "razersynapse3.exe", "rzsdkservice.exe", "rzsdkserver.exe",
        "gamermanager.exe", "gamermanagerservice.exe",
        # Corsair iCUE
        "icue.exe", "corsair.service.cpuidremote64.exe",
        "corsair.service.displayadapter.exe", "corsairllaccess64.exe",
        # SteelSeries GG / Engine
        "steelseriesgg.exe", "steelseriesengine.exe",
        "steelseriesengine3.exe", "sseclient.exe",
        # HyperX NGENUITY
        "hyperxngenuity.exe",
        # Roccat Swarm
        "roccatswarm.exe", "roccatswarmmonitor.exe",
        # ASUS ROG / Armoury Crate
        "armourycrate.exe", "armourycrate.service.exe", "aaborc.exe",
        "asusoptimization.exe",
        # MSI Dragon Center
        "dragoncenter.exe", "msiservice.exe",
        # BenQ Zowie
        "zowiedirect.exe",
        # Glorious Model O/D
        "gloriouscore.exe",
        # Bloody / A4Tech (software only, macros inspected separately)
        "bloody7.exe", "bloody8.exe", "bloodycore.exe",
        # Redragon
        "redragonsetup.exe",
        # Generic gaming peripherals
        "synapse.exe", "synapse3.exe",
    ],
    # Signers that are always trusted for drivers
    "trusted_signers": [
        "microsoft windows",
        "microsoft corporation",
        "logitech",
        "razer inc",
        "razer usa",
        "corsair memory",
        "corsair components",
        "steelseries",
        "hyperx",
        "roccat",
        "asus",
        "msi",
        "nvidia",
        "amd",
        "intel",
        "realtek",
        "creative technology",
    ],
}

# ── Detection layers configuration ─────────────────────────────────────
DETECTION_LAYERS = [
    "hash",        # SHA-256 hash matching against known cheat hashes
    "signature",   # String/pattern signature matching
    "behavior",    # Behavioral analysis (timing, injection patterns)
    "memory",      # In-memory string scanning
    "bytecode",    # Java bytecode constant pool analysis
]


def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    if platform.system() != "Windows":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_admin_elevation():
    """Request UAC elevation on Windows. Re-launches the process as admin."""
    if platform.system() != "Windows":
        return
    if is_admin():
        return
    try:
        # Re-run the current script with admin privileges
        script = sys.argv[0]
        params = " ".join(sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        sys.exit(0)
    except Exception:
        # If elevation fails, continue without admin (some scans will be limited)
        pass


@dataclass
class AppSettings:
    """Application settings with defaults."""
    language: str = "id"  # 'id' or 'en'
    theme: str = "dark"
    decompiler: str = "CFR"
    auto_update_db: bool = True
    deep_scan_mode: bool = False
    max_threads: int = 8
    scan_timeout: int = 300
    cache_enabled: bool = True
    evidence_auto_collect: bool = True
    kernel_check_enabled: bool = True
    memory_scan_enabled: bool = True
    network_scan_enabled: bool = True
    browser_scan_enabled: bool = True
    mouse_scan_enabled: bool = True
    deleted_scan_enabled: bool = True
    cfr_path: str = ""
    fernflower_path: str = ""
    procyon_path: str = ""
    vineflower_path: str = ""

    def save(self):
        """Save settings to JSON file."""
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.__dict__, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls) -> 'AppSettings':
        """Load settings from JSON file."""
        settings = cls()
        if SETTINGS_FILE.exists():
            try:
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for k, v in data.items():
                    if hasattr(settings, k):
                        setattr(settings, k, v)
            except Exception:
                pass
        return settings
