"""
SS-Tools Ultimate - Application Configuration
Central configuration for all modules and settings.
"""
import os
import json
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

APP_NAME = "SS-Tools Ultimate"
APP_VERSION = "3.0.0"
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
