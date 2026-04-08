"""
SS-Tools Ultimate - Cheat Database Manager
Loads, caches, and auto-updates the cheat signature database.
"""
import json
import os
import time
import threading
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.config import DATABASE_FILE, DATABASE_UPDATE_URL, CACHE_DIR
from core.utils import logger


class CheatDatabase:
    """Manages the cheat signature database with auto-update support."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.data: Dict[str, Any] = {}
        self._cache_file = CACHE_DIR / "db_cache.json"
        self._load()

    def _load(self):
        """Load database from JSON file."""
        try:
            if DATABASE_FILE.exists():
                with open(DATABASE_FILE, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
                logger.info(
                    f"Database loaded: v{self.data.get('meta', {}).get('version', '?')} "
                    f"({self.data.get('meta', {}).get('total_entries', '?')} entries)"
                )
            else:
                logger.warning(f"Database file not found: {DATABASE_FILE}")
                self.data = {"meta": {"version": "0.0.0"}, "cheat_clients": [],
                             "cheat_modules": [], "suspicious_methods": [],
                             "suspicious_imports": [], "suspicious_strings": [],
                             "cheat_files": [], "cheat_urls": [],
                             "cheat_developers": [], "obfuscation_patterns": [],
                             "bytecode_signatures": [], "kernel_driver_signatures": [],
                             "suspicious_processes": [], "whitelist_mods": [],
                             "whitelist_processes": []}
        except Exception as e:
            logger.error(f"Failed to load database: {e}")
            self.data = {}

    def reload(self):
        """Force reload from disk."""
        self._initialized = False
        self.__init__()

    @property
    def version(self) -> str:
        return self.data.get("meta", {}).get("version", "0.0.0")

    @property
    def cheat_clients(self) -> List[Dict]:
        return self.data.get("cheat_clients", [])

    @property
    def cheat_modules(self) -> List[Dict]:
        return self.data.get("cheat_modules", [])

    @property
    def suspicious_methods(self) -> List[Dict]:
        return self.data.get("suspicious_methods", [])

    @property
    def suspicious_imports(self) -> List[Dict]:
        return self.data.get("suspicious_imports", [])

    @property
    def suspicious_strings(self) -> List[Dict]:
        return self.data.get("suspicious_strings", [])

    @property
    def cheat_files(self) -> List[Dict]:
        return self.data.get("cheat_files", [])

    @property
    def cheat_urls(self) -> List[Dict]:
        return self.data.get("cheat_urls", [])

    @property
    def cheat_developers(self) -> List[Dict]:
        return self.data.get("cheat_developers", [])

    @property
    def obfuscation_patterns(self) -> List[Dict]:
        return self.data.get("obfuscation_patterns", [])

    @property
    def bytecode_signatures(self) -> List[Dict]:
        return self.data.get("bytecode_signatures", [])

    @property
    def kernel_driver_signatures(self) -> List[Dict]:
        return self.data.get("kernel_driver_signatures", [])

    @property
    def suspicious_processes(self) -> List[Dict]:
        return self.data.get("suspicious_processes", [])

    @property
    def whitelist_mods(self) -> List[str]:
        return self.data.get("whitelist_mods", [])

    @property
    def whitelist_processes(self) -> List[str]:
        return self.data.get("whitelist_processes", [])

    def get_all_keywords(self) -> List[str]:
        """Get flattened list of all cheat keywords for matching."""
        keywords = []
        for client in self.cheat_clients:
            keywords.append(client["name"].lower())
            keywords.extend([a.lower() for a in client.get("aliases", [])])
        for module in self.cheat_modules:
            keywords.append(module["name"].lower())
            keywords.extend([a.lower() for a in module.get("aliases", [])])
        for dev in self.cheat_developers:
            keywords.append(dev["name"].lower())
        for f in self.cheat_files:
            keywords.append(f["name"].lower())
        return list(set(keywords))

    def get_all_url_patterns(self) -> List[Dict]:
        """Get all URL patterns for browser scanning."""
        return self.cheat_urls

    def is_mod_whitelisted(self, mod_name: str) -> bool:
        """Check if a mod name is in the whitelist."""
        mod_lower = mod_name.lower().replace(" ", "-").replace("_", "-")
        for wl in self.whitelist_mods:
            if wl.lower() in mod_lower or mod_lower in wl.lower():
                return True
        return False

    def is_process_whitelisted(self, proc_name: str) -> bool:
        """Check if a process name is in the whitelist."""
        proc_lower = proc_name.lower()
        return proc_lower in [w.lower() for w in self.whitelist_processes]

    def auto_update(self, callback=None) -> bool:
        """Check and download database updates from remote URL."""
        try:
            logger.info("Checking for database updates...")
            req = urllib.request.Request(
                DATABASE_UPDATE_URL,
                headers={"User-Agent": "SS-Tools/3.0", "Cache-Control": "no-cache"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                remote_data = json.loads(resp.read().decode('utf-8'))

            remote_version = remote_data.get("meta", {}).get("version", "0.0.0")
            local_version = self.version

            if self._compare_versions(remote_version, local_version) > 0:
                logger.info(f"Updating database: {local_version} -> {remote_version}")
                # Backup current
                backup = DATABASE_FILE.with_suffix('.json.bak')
                if DATABASE_FILE.exists():
                    import shutil
                    shutil.copy2(DATABASE_FILE, backup)
                # Write new
                with open(DATABASE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(remote_data, f, indent=2, ensure_ascii=False)
                self.data = remote_data
                logger.info(f"Database updated to v{remote_version}")
                if callback:
                    callback(True, f"Updated to v{remote_version}")
                return True
            else:
                logger.info("Database is up to date")
                if callback:
                    callback(False, "Already up to date")
                return False

        except Exception as e:
            logger.warning(f"Auto-update failed: {e}")
            if callback:
                callback(False, f"Update failed: {e}")
            return False

    def auto_update_async(self, callback=None):
        """Run auto-update in background thread."""
        thread = threading.Thread(target=self.auto_update, args=(callback,), daemon=True)
        thread.start()
        return thread

    @staticmethod
    def _compare_versions(v1: str, v2: str) -> int:
        """Compare two version strings. Returns >0 if v1 > v2."""
        parts1 = [int(x) for x in v1.split(".")]
        parts2 = [int(x) for x in v2.split(".")]
        for a, b in zip(parts1, parts2):
            if a > b:
                return 1
            if a < b:
                return -1
        return len(parts1) - len(parts2)
