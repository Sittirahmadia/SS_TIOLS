"""
SS-Tools Ultimate - String Deleted Scanner (Forensic Level)
Scans Recycle Bin, temp folders, prefetch, registry, event logs,
and other forensic artifacts for evidence of deleted cheats.
"""
import os
import re
import glob
import struct
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import ScanResult, ScanProgress, logger, safe_read_file, safe_read_binary

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False


class StringDeletedScanner:
    """Forensic-level scanner for deleted cheat evidence."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Run full forensic scan."""
        results = []
        self.progress.start("Deleted String Scanner", 7)

        # 1. Recycle Bin
        self.progress.update("Scanning Recycle Bin...")
        results.extend(self._scan_recycle_bin())

        # 2. Temp folders
        self.progress.update("Scanning Temp folders...")
        results.extend(self._scan_temp_folders())

        # 3. Prefetch files
        self.progress.update("Scanning Prefetch...")
        results.extend(self._scan_prefetch())

        # 4. Registry (Recent Docs, RunMRU, UserAssist)
        self.progress.update("Scanning Registry...")
        results.extend(self._scan_registry())

        # 5. Windows Event Logs
        self.progress.update("Scanning Event Logs...")
        results.extend(self._scan_event_logs())

        # 6. Recent files and Jump Lists
        self.progress.update("Scanning Recent files...")
        results.extend(self._scan_recent_files())

        # 7. USN Journal / NTFS artifacts
        self.progress.update("Scanning NTFS artifacts...")
        results.extend(self._scan_ntfs_artifacts())

        return results

    def _scan_recycle_bin(self) -> List[ScanResult]:
        """Scan Recycle Bin for deleted cheat files."""
        results = []
        recycle_paths = []

        # Find all Recycle Bin paths
        for drive in "CDEFGHIJ":
            rb_path = Path(f"{drive}:\\$Recycle.Bin")
            if rb_path.exists():
                recycle_paths.append(rb_path)

        for rb_path in recycle_paths:
            try:
                for root, dirs, files in os.walk(rb_path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        # Check filename
                        name_results = self.detector.scan_filename(fname, fpath)
                        for r in name_results:
                            r.scanner = "DeletedScanner"
                            r.category = "recycle_bin"
                            r.description = f"[Recycle Bin] {r.description}"
                            r.severity = min(r.severity + 10, 100)
                        results.extend(name_results)

                        # Check $I info files for original path
                        if fname.startswith("$I"):
                            try:
                                data = safe_read_binary(fpath)
                                if data and len(data) > 28:
                                    # Parse $I file: offset 24+ is original path (UTF-16LE)
                                    original_path = data[28:].decode('utf-16-le', errors='replace').strip('\x00')
                                    if original_path:
                                        path_results = self.detector.scan_text(
                                            original_path, source="recycle_bin", filepath=fpath
                                        )
                                        for r in path_results:
                                            r.scanner = "DeletedScanner"
                                            r.category = "recycle_bin_path"
                                            r.description = f"[Recycle Bin Path] {original_path}"
                                            r.severity = min(r.severity + 15, 100)
                                        results.extend(path_results)
                            except Exception:
                                pass
            except PermissionError:
                pass
            except Exception as e:
                logger.debug(f"Recycle bin scan error: {e}")

        return results

    def _scan_temp_folders(self) -> List[ScanResult]:
        """Scan temporary folders for cheat evidence."""
        results = []
        temp_dirs = [
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
            os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Temp"),
            "C:\\Windows\\Temp",
        ]

        for temp_dir in temp_dirs:
            if not temp_dir or not os.path.exists(temp_dir):
                continue
            try:
                for item in os.listdir(temp_dir):
                    item_lower = item.lower()
                    fpath = os.path.join(temp_dir, item)

                    name_results = self.detector.scan_filename(item, fpath)
                    for r in name_results:
                        r.scanner = "DeletedScanner"
                        r.category = "temp_folder"
                        r.description = f"[Temp] {r.description}"
                    results.extend(name_results)

                    # Scan content of small text files in temp
                    if os.path.isfile(fpath):
                        ext = os.path.splitext(item)[1].lower()
                        if ext in ('.txt', '.log', '.json', '.cfg', '.ini', '.bat', '.cmd', '.ps1'):
                            try:
                                if os.path.getsize(fpath) < 1024 * 1024:
                                    content = safe_read_file(fpath)
                                    if content:
                                        text_results = self.detector.scan_text(
                                            content, source="temp", filepath=fpath
                                        )
                                        for r in text_results:
                                            r.scanner = "DeletedScanner"
                                            r.category = "temp_content"
                                        results.extend(text_results)
                            except Exception:
                                pass
            except PermissionError:
                pass
            except Exception as e:
                logger.debug(f"Temp scan error: {e}")

        return results

    def _scan_prefetch(self) -> List[ScanResult]:
        """Scan Windows Prefetch files for executed cheat programs."""
        results = []
        prefetch_dir = Path("C:\\Windows\\Prefetch")
        if not prefetch_dir.exists():
            return results

        keywords = self.db.get_all_keywords()
        try:
            for pf_file in prefetch_dir.glob("*.pf"):
                pf_name = pf_file.stem.lower()
                # Remove the hash suffix from prefetch name
                pf_app = re.sub(r'-[A-F0-9]{8}$', '', pf_name, flags=re.IGNORECASE)

                for entry in self.db.suspicious_processes:
                    if entry["name"].lower() in pf_app:
                        results.append(ScanResult(
                            scanner="DeletedScanner",
                            category="prefetch",
                            name=pf_file.name,
                            description=f"[Prefetch] Previously executed: {entry.get('description', pf_app)}",
                            severity=entry.get("severity", 80),
                            filepath=str(pf_file),
                            evidence=f"Prefetch file indicates {pf_app} was executed",
                        ))
                        break

                # Also check cheat client names
                for client in self.db.cheat_clients:
                    if client["name"].lower() in pf_app:
                        results.append(ScanResult(
                            scanner="DeletedScanner",
                            category="prefetch_cheat",
                            name=client["name"],
                            description=f"[Prefetch] Cheat client was executed: {client['name']}",
                            severity=100,
                            filepath=str(pf_file),
                            evidence=f"Prefetch proves {client['name']} was run on this PC",
                        ))
                        break
        except PermissionError:
            pass
        except Exception as e:
            logger.debug(f"Prefetch scan error: {e}")

        return results

    def _scan_registry(self) -> List[ScanResult]:
        """Scan Windows registry for cheat evidence."""
        results = []
        if not WINREG_AVAILABLE:
            return results

        registry_locations = [
            # Recent documents
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"),
            # Run MRU (Run dialog history)
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"),
            # App Compat Flags
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"),
            # BAM (Background Activity Moderator)
            (winreg.HKEY_LOCAL_MACHINE,
             r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"),
        ]

        for hive, subkey in registry_locations:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(key, i)
                        # Convert value to searchable string
                        search_str = ""
                        if isinstance(value, str):
                            search_str = value
                        elif isinstance(value, bytes):
                            search_str = value.decode('utf-16-le', errors='replace')

                        if search_str:
                            combined = f"{name} {search_str}"
                            reg_results = self.detector.scan_text(
                                combined, source="registry",
                                filepath=f"{subkey}\\{name}"
                            )
                            for r in reg_results:
                                r.scanner = "DeletedScanner"
                                r.category = "registry"
                                r.description = f"[Registry] {r.description}"
                                r.severity = min(r.severity + 5, 100)
                            results.extend(reg_results)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (PermissionError, FileNotFoundError, OSError):
                pass

        return results

    def _scan_event_logs(self) -> List[ScanResult]:
        """Scan Windows Event Logs for cheat-related events."""
        results = []
        try:
            # Check for recent program installations/executions
            proc = subprocess.run(
                ["powershell", "-Command",
                 "Get-WinEvent -LogName Application -MaxEvents 200 2>$null | "
                 "Select-Object -ExpandProperty Message 2>$null"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0 and proc.stdout:
                text_results = self.detector.scan_text(
                    proc.stdout, source="event_log", filepath="Application Log"
                )
                for r in text_results:
                    r.scanner = "DeletedScanner"
                    r.category = "event_log"
                    r.description = f"[Event Log] {r.description}"
                results.extend(text_results)
        except Exception as e:
            logger.debug(f"Event log scan error: {e}")

        return results

    def _scan_recent_files(self) -> List[ScanResult]:
        """Scan Recent files and Jump Lists."""
        results = []
        recent_dir = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
        if not recent_dir.exists():
            return results

        try:
            for item in recent_dir.iterdir():
                name_results = self.detector.scan_filename(item.name, str(item))
                for r in name_results:
                    r.scanner = "DeletedScanner"
                    r.category = "recent_files"
                    r.description = f"[Recent] {r.description}"
                    r.severity = min(r.severity + 10, 100)
                results.extend(name_results)
        except Exception as e:
            logger.debug(f"Recent files scan error: {e}")

        return results

    def _scan_ntfs_artifacts(self) -> List[ScanResult]:
        """Scan NTFS artifacts using fsutil/PowerShell."""
        results = []
        try:
            # Check USN journal for recently deleted files
            proc = subprocess.run(
                ["powershell", "-Command",
                 "fsutil usn readjournal C: csv 2>$null | Select-String -Pattern 'cheat|hack|inject|wurst|impact|meteor|killaura|aimbot' -SimpleMatch | Select-Object -First 20"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().split('\n'):
                    results.append(ScanResult(
                        scanner="DeletedScanner",
                        category="ntfs_usn",
                        name="USN Journal Match",
                        description=f"[NTFS USN] Cheat-related file activity detected",
                        severity=85,
                        evidence=line.strip()[:500],
                    ))
        except Exception as e:
            logger.debug(f"NTFS scan error: {e}")

        return results
