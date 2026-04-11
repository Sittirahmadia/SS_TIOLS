"""
SS-Tools Ultimate - Process & DLL Scanner
Scans running processes, loaded DLLs, and child processes for cheat indicators.
Enhanced with SHA-256 hash detection, memory string scanning, and gaming whitelist.
"""
import os
import re
import hashlib
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.config import GAMING_SOFTWARE_WHITELIST
from core.utils import ScanResult, ScanProgress, logger, file_hash_sha256

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

# Known cheat executable SHA-256 hashes (partial list, extended via database)
KNOWN_CHEAT_HASHES = {
    # These would be populated from the cheat_keywords.json database
    # Format: "sha256_hash": ("cheat_name", severity)
}


class ProcessScanner:
    """Scans running processes for cheat indicators."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()

    def _is_gaming_whitelisted(self, proc_name: str) -> bool:
        """Check if process is a whitelisted gaming peripheral software."""
        return proc_name.lower() in GAMING_SOFTWARE_WHITELIST["processes"]

    def scan(self) -> List[ScanResult]:
        """Scan all running processes with multi-layer detection."""
        results = []
        if not PSUTIL_AVAILABLE:
            results.append(ScanResult(
                scanner="ProcessScanner", category="error",
                name="Missing psutil", description="psutil library required",
                severity=0,
            ))
            return results

        # Get own PID to skip self
        self_pid = os.getpid()
        self_ppid = os.getppid() if hasattr(os, 'getppid') else 0

        processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']))
        self.progress.start("Process Scanner", len(processes))

        for proc_info in processes:
            try:
                pid = proc_info.info.get('pid', 0)
                name = proc_info.info.get('name', '')
                # Skip self and parent (the tool itself)
                if pid in (self_pid, self_ppid, 0, 1):
                    self.progress.update(name)
                    continue
                # Skip whitelisted gaming software
                if self._is_gaming_whitelisted(name):
                    self.progress.update(name)
                    continue
                proc_results = self._scan_process(proc_info)
                results.extend(proc_results)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception as e:
                logger.debug(f"Process scan error: {e}")
            self.progress.update(proc_info.info.get('name', ''))

        # Scan loaded DLLs for Java processes (Minecraft)
        results.extend(self._scan_java_dlls())

        # SHA-256 hash scan of suspicious executables
        results.extend(self._scan_exe_hashes())

        return results

    def _scan_process(self, proc_info) -> List[ScanResult]:
        """Scan a single process."""
        results = []
        name = (proc_info.info.get('name') or '').lower()
        exe = proc_info.info.get('exe') or ''
        pid = proc_info.info.get('pid', 0)
        cmdline = proc_info.info.get('cmdline') or []

        if not name:
            return results

        # Check against whitelist
        if self.db.is_process_whitelisted(name):
            return results

        # Check against suspicious process database
        proc_results = self.detector.scan_process(name)
        for r in proc_results:
            r.details["pid"] = pid
            r.details["exe"] = exe
            r.details["cmdline"] = " ".join(cmdline) if cmdline else ""
        results.extend(proc_results)

        # Check executable path
        if exe:
            exe_lower = exe.lower()
            for entry in self.db.suspicious_processes:
                if entry["name"].lower() in exe_lower:
                    results.append(ScanResult(
                        scanner="ProcessScanner",
                        category="suspicious_process_path",
                        name=entry["name"],
                        description=f"Suspicious process path: {entry.get('description', '')}",
                        severity=entry.get("severity", 80),
                        filepath=exe,
                        evidence=f"PID: {pid}, Path: {exe}",
                        details={"pid": pid, "exe": exe},
                    ))
                    break

        # Check command line for cheat indicators — ONLY for Java/Minecraft processes
        # Scanning all process cmdlines causes false positives (Python keywords, etc.)
        if cmdline and name in ('java.exe', 'javaw.exe', 'minecraft.exe',
                                'java', 'javaw'):
            cmd_str = " ".join(cmdline)
            cmd_results = self.detector.scan_text(cmd_str, source="cmdline",
                                                   filepath=f"PID:{pid}")
            for r in cmd_results:
                r.details["pid"] = pid
                r.severity = min(r.severity, 85)  # Cap severity for cmdline
            results.extend(cmd_results)

        # Check for injection-related process names
        injection_keywords = ["inject", "hook", "patch", "loader", "bypass",
                              "spoof", "mapper", "manual map", "shellcode"]
        for kw in injection_keywords:
            if kw in name:
                results.append(ScanResult(
                    scanner="ProcessScanner",
                    category="injection_process",
                    name=name,
                    description=f"Process with injection-related name: {name}",
                    severity=90,
                    filepath=exe,
                    evidence=f"PID: {pid}, Name: {name}",
                    details={"pid": pid},
                ))
                break

        return results

    def _scan_java_dlls(self) -> List[ScanResult]:
        """Scan DLLs loaded by Java processes (potential injected cheats)."""
        results = []
        if not PSUTIL_AVAILABLE:
            return results

        try:
            for proc in psutil.process_iter(['pid', 'name']):
                name = (proc.info.get('name') or '').lower()
                if name in ('java.exe', 'javaw.exe'):
                    try:
                        # Get loaded DLLs
                        dlls = proc.memory_maps()
                        for dll in dlls:
                            dll_path = dll.path.lower() if hasattr(dll, 'path') else ""
                            if not dll_path:
                                continue
                            dll_name = os.path.basename(dll_path)

                            # Check against suspicious DLL names
                            suspicious_dll_patterns = [
                                "hack", "cheat", "inject", "hook",
                                "bypass", "exploit", "aim", "esp",
                                "wallhack", "speed", "fly",
                            ]
                            for pattern in suspicious_dll_patterns:
                                if pattern in dll_name:
                                    results.append(ScanResult(
                                        scanner="ProcessScanner",
                                        category="injected_dll",
                                        name=dll_name,
                                        description=f"Suspicious DLL in Java process: {dll_name}",
                                        severity=95,
                                        filepath=dll_path,
                                        evidence=f"PID: {proc.info['pid']}, DLL: {dll_path}",
                                        details={"pid": proc.info['pid']},
                                    ))
                                    break
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
        except Exception as e:
            logger.debug(f"Java DLL scan error: {e}")

        return results

    def get_process_list(self) -> List[Dict]:
        """Get full process list with details."""
        processes = []
        if not PSUTIL_AVAILABLE:
            return processes

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time',
                                          'memory_info', 'cpu_percent']):
            try:
                info = proc.info
                mem = info.get('memory_info')
                processes.append({
                    "pid": info.get('pid', 0),
                    "name": info.get('name', ''),
                    "exe": info.get('exe', ''),
                    "memory_mb": round(mem.rss / (1024 * 1024), 1) if mem else 0,
                    "create_time": info.get('create_time', 0),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(processes, key=lambda x: x.get('memory_mb', 0), reverse=True)

    def _scan_exe_hashes(self) -> List[ScanResult]:
        """SHA-256 hash scan of running process executables against known cheat hashes."""
        results = []
        if not PSUTIL_AVAILABLE:
            return results

        # Build hash database from CheatDatabase
        hash_db = {}
        for entry in self.db.data.get("cheat_file_hashes", []):
            h = entry.get("sha256", "").lower()
            if h:
                hash_db[h] = (entry.get("name", "Unknown"), entry.get("severity", 100))
        # Merge static known hashes
        hash_db.update(KNOWN_CHEAT_HASHES)

        if not hash_db:
            return results

        scanned_exes = set()
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                exe = proc.info.get('exe') or ''
                if not exe or exe in scanned_exes:
                    continue
                scanned_exes.add(exe)
                if not os.path.isfile(exe):
                    continue
                # Skip large files (>100MB) and system files
                try:
                    if os.path.getsize(exe) > 100 * 1024 * 1024:
                        continue
                except OSError:
                    continue

                exe_hash = file_hash_sha256(exe)
                if exe_hash and exe_hash.lower() in hash_db:
                    cheat_name, severity = hash_db[exe_hash.lower()]
                    results.append(ScanResult(
                        scanner="ProcessScanner",
                        category="cheat_hash_match",
                        name=cheat_name,
                        description=f"Known cheat executable hash match: {cheat_name}",
                        severity=severity,
                        filepath=exe,
                        evidence=f"SHA-256: {exe_hash}, PID: {proc.info['pid']}",
                        details={"pid": proc.info['pid'], "sha256": exe_hash},
                    ))
        except Exception as e:
            logger.debug(f"Hash scan error: {e}")

        return results

    def get_java_processes(self) -> List[Dict]:
        """Get only Java/Minecraft processes."""
        return [p for p in self.get_process_list()
                if p['name'].lower() in ('java.exe', 'javaw.exe', 'minecraft.exe')]
