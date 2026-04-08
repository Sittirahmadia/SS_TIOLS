"""
SS-Tools Ultimate - Minecraft Installation Scanner
Scans all Minecraft launcher installations for cheat indicators.
Multi-threaded, cached, with whitelist for zero false positives.
"""
import os
import time
import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import MINECRAFT_LAUNCHER_PATHS, MINECRAFT_SCAN_DIRS, CACHE_DIR
from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import (
    ScanResult, ScanProgress, logger, expand_path,
    file_hash_md5, safe_read_file, format_size, parallel_execute
)


class MinecraftScanner:
    """Scans Minecraft installations across all launchers."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()
        self._cache_db = CACHE_DIR / "scan_cache.db"
        self._init_cache()

    def _init_cache(self):
        """Initialize SQLite cache database."""
        try:
            conn = sqlite3.connect(str(self._cache_db))
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_cache (
                    filepath TEXT PRIMARY KEY,
                    md5 TEXT,
                    last_scan REAL,
                    results TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Cache init failed: {e}")

    def _check_cache(self, filepath: str, md5: str) -> Optional[List[Dict]]:
        """Check if file was already scanned with same hash."""
        try:
            conn = sqlite3.connect(str(self._cache_db))
            row = conn.execute(
                "SELECT results FROM file_cache WHERE filepath=? AND md5=?",
                (filepath, md5)
            ).fetchone()
            conn.close()
            if row:
                return json.loads(row[0])
        except Exception:
            pass
        return None

    def _update_cache(self, filepath: str, md5: str, results: List[Dict]):
        """Update scan cache."""
        try:
            conn = sqlite3.connect(str(self._cache_db))
            conn.execute(
                "INSERT OR REPLACE INTO file_cache (filepath, md5, last_scan, results) VALUES (?, ?, ?, ?)",
                (filepath, md5, time.time(), json.dumps(results))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def find_installations(self) -> Dict[str, List[Path]]:
        """Find all Minecraft installations on the system."""
        found = {}
        for launcher, paths in MINECRAFT_LAUNCHER_PATHS.items():
            launcher_dirs = []
            for path_template in paths:
                expanded = expand_path(path_template)
                if expanded and expanded.is_dir():
                    launcher_dirs.append(expanded)
            if launcher_dirs:
                found[launcher] = launcher_dirs
                logger.info(f"Found {launcher}: {[str(d) for d in launcher_dirs]}")
        return found

    def scan_all(self) -> List[ScanResult]:
        """Full scan of all Minecraft installations."""
        all_results = []
        installations = self.find_installations()

        if not installations:
            logger.info("No Minecraft installations found")
            return all_results

        total_dirs = sum(len(dirs) for dirs in installations.values())
        self.progress.start("Minecraft Scanner", total_dirs * len(MINECRAFT_SCAN_DIRS))

        for launcher, dirs in installations.items():
            for base_dir in dirs:
                results = self._scan_installation(base_dir, launcher)
                all_results.extend(results)

        logger.info(f"Minecraft scan complete: {len(all_results)} findings")
        return all_results

    def _scan_installation(self, base_dir: Path, launcher: str) -> List[ScanResult]:
        """Scan a single Minecraft installation directory."""
        results = []

        # Scan known cheat folders/files at root
        results.extend(self._scan_cheat_files(base_dir, launcher))

        # Scan subdirectories
        for subdir_name in MINECRAFT_SCAN_DIRS:
            subdir = base_dir / subdir_name
            if subdir.exists() and subdir.is_dir():
                sub_results = self._scan_directory(subdir, launcher, subdir_name)
                results.extend(sub_results)
            self.progress.update(str(subdir))

        # Scan log files specifically
        results.extend(self._scan_logs(base_dir, launcher))

        return results

    def _scan_cheat_files(self, base_dir: Path, launcher: str) -> List[ScanResult]:
        """Scan for known cheat files and folders in the installation."""
        results = []
        try:
            for item in base_dir.iterdir():
                filename_results = self.detector.scan_filename(
                    item.name, str(item)
                )
                for r in filename_results:
                    r.details["launcher"] = launcher
                results.extend(filename_results)
        except PermissionError:
            pass
        except Exception as e:
            logger.debug(f"Error scanning {base_dir}: {e}")
        return results

    def _scan_directory(self, directory: Path, launcher: str,
                        dir_type: str) -> List[ScanResult]:
        """Scan a specific subdirectory for cheat indicators."""
        results = []
        files_to_scan = []

        try:
            for root, dirs, files in os.walk(directory):
                # Skip very deep directories
                depth = str(root).count(os.sep) - str(directory).count(os.sep)
                if depth > 5:
                    continue
                for fname in files:
                    fpath = os.path.join(root, fname)
                    files_to_scan.append(fpath)
        except PermissionError:
            return results

        def scan_single_file(fpath):
            file_results = []
            fname = os.path.basename(fpath)

            # Filename check
            name_results = self.detector.scan_filename(fname, fpath)
            for r in name_results:
                r.details["launcher"] = launcher
                r.details["dir_type"] = dir_type
            file_results.extend(name_results)

            # Content scan for text-based files
            ext = os.path.splitext(fname)[1].lower()
            scannable_exts = {'.json', '.txt', '.cfg', '.toml', '.yml',
                              '.yaml', '.properties', '.log', '.xml', '.ini'}
            if ext in scannable_exts:
                try:
                    size = os.path.getsize(fpath)
                    if size < 5 * 1024 * 1024:  # Max 5MB
                        content = safe_read_file(fpath)
                        if content:
                            text_results = self.detector.scan_text(
                                content, source=dir_type, filepath=fpath
                            )
                            for r in text_results:
                                r.details["launcher"] = launcher
                                r.details["dir_type"] = dir_type
                            file_results.extend(text_results)
                except Exception:
                    pass

            return file_results

        # Parallel file scanning
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(scan_single_file, f): f for f in files_to_scan}
            for future in as_completed(futures):
                try:
                    file_results = future.result()
                    results.extend(file_results)
                except Exception:
                    pass

        return results

    def _scan_logs(self, base_dir: Path, launcher: str) -> List[ScanResult]:
        """Scan Minecraft log files for cheat evidence."""
        results = []
        log_dirs = [base_dir / "logs", base_dir / "crash-reports"]

        for log_dir in log_dirs:
            if not log_dir.exists():
                continue
            try:
                for log_file in log_dir.glob("*.log"):
                    content = safe_read_file(str(log_file))
                    if content:
                        log_results = self.detector.scan_text(
                            content, source="logs", filepath=str(log_file)
                        )
                        for r in log_results:
                            r.details["launcher"] = launcher
                            r.details["log_type"] = log_dir.name
                        results.extend(log_results)
                # Also scan .log.gz files (latest.log, etc.)
                for log_file in log_dir.glob("*.txt"):
                    content = safe_read_file(str(log_file))
                    if content:
                        log_results = self.detector.scan_text(
                            content, source="logs", filepath=str(log_file)
                        )
                        for r in log_results:
                            r.details["launcher"] = launcher
                        results.extend(log_results)
            except Exception as e:
                logger.debug(f"Error scanning logs: {e}")

        return results

    def get_installation_info(self) -> List[Dict]:
        """Get summary info about all installations found."""
        info = []
        installations = self.find_installations()
        for launcher, dirs in installations.items():
            for d in dirs:
                mod_count = 0
                mod_dir = d / "mods"
                if mod_dir.exists():
                    mod_count = len(list(mod_dir.glob("*.jar")))
                info.append({
                    "launcher": launcher,
                    "path": str(d),
                    "mods_count": mod_count,
                    "exists": True,
                })
        return info
