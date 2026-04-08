"""
SS-Tools Ultimate - Process Scanner
Scans running processes, loaded DLLs, and child processes for cheat indicators.
"""
import os
import re
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import ScanResult, ScanProgress, logger

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


class ProcessScanner:
    """Scans running processes for cheat indicators."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Scan all running processes."""
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
                # Skip self and parent (the tool itself)
                if pid in (self_pid, self_ppid, 0, 1):
                    self.progress.update(proc_info.info.get('name', ''))
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

    def get_java_processes(self) -> List[Dict]:
        """Get only Java/Minecraft processes."""
        return [p for p in self.get_process_list()
                if p['name'].lower() in ('java.exe', 'javaw.exe', 'minecraft.exe')]
