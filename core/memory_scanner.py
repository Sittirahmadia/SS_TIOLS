"""
SS-Tools Ultimate - Memory Scanner
Scans process memory for injected DLLs and cheat strings.
"""
import os
import re
import subprocess
from typing import List, Dict, Optional

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import ScanResult, ScanProgress, logger

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import ctypes
    import ctypes.wintypes
    CTYPES_AVAILABLE = True
except ImportError:
    CTYPES_AVAILABLE = False


class MemoryScanner:
    """Scans process memory for cheat indicators."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Scan memory of Java/Minecraft processes."""
        results = []
        if not PSUTIL_AVAILABLE:
            return results

        self.progress.start("Memory Scanner", 3)

        # 1. Find Java/Minecraft processes
        self.progress.update("Finding game processes...")
        java_procs = self._find_java_processes()

        # 2. Scan memory maps for suspicious DLLs
        self.progress.update("Scanning memory maps...")
        for proc in java_procs:
            results.extend(self._scan_memory_maps(proc))

        # 3. Scan process command lines and environment
        self.progress.update("Scanning process environment...")
        for proc in java_procs:
            results.extend(self._scan_process_env(proc))

        return results

    def _find_java_processes(self) -> list:
        """Find all Java/Minecraft processes."""
        procs = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                name = (proc.info.get('name') or '').lower()
                if name in ('java.exe', 'javaw.exe', 'minecraft.exe'):
                    procs.append(proc)
        except Exception:
            pass
        return procs

    def _scan_memory_maps(self, proc) -> List[ScanResult]:
        """Scan memory-mapped files for suspicious DLLs."""
        results = []
        try:
            maps = proc.memory_maps()
            for m in maps:
                path = getattr(m, 'path', '') or ''
                if not path:
                    continue
                path_lower = path.lower()
                basename = os.path.basename(path_lower)

                # Check against suspicious patterns
                suspicious_patterns = [
                    "hack", "cheat", "inject", "hook", "bypass",
                    "exploit", "aimbot", "killaura", "wurst",
                    "impact", "meteor", "vape", "autoclicker",
                    "speedhack", "noclip",
                ]
                for pattern in suspicious_patterns:
                    if pattern in basename:
                        results.append(ScanResult(
                            scanner="MemoryScanner",
                            category="suspicious_memory_module",
                            name=basename,
                            description=f"Suspicious module in Java memory: {basename}",
                            severity=95,
                            filepath=path,
                            evidence=f"PID: {proc.pid}, Module: {path}",
                            details={"pid": proc.pid, "module_path": path},
                        ))
                        break

                # Check for unsigned/unusual DLLs
                if path_lower.endswith('.dll'):
                    # DLLs not in standard system paths are suspicious in Java
                    standard_paths = [
                        "\\windows\\", "\\system32\\", "\\syswow64\\",
                        "\\jre\\", "\\jdk\\", "\\java\\", "\\jvm\\",
                        "\\program files\\", "\\nvidia\\", "\\amd\\",
                    ]
                    if not any(sp in path_lower for sp in standard_paths):
                        results.append(ScanResult(
                            scanner="MemoryScanner",
                            category="unusual_dll_in_java",
                            name=basename,
                            description=f"Non-standard DLL loaded in Java process: {basename}",
                            severity=60,
                            filepath=path,
                            evidence=f"PID: {proc.pid}, Path: {path}",
                            details={"pid": proc.pid},
                        ))
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        except Exception as e:
            logger.debug(f"Memory map scan error: {e}")
        return results

    def _scan_process_env(self, proc) -> List[ScanResult]:
        """Scan process command line and environment for cheat indicators."""
        results = []
        try:
            cmdline = proc.cmdline()
            if cmdline:
                cmd_str = " ".join(cmdline)

                # Check for suspicious Java agents
                if "-javaagent:" in cmd_str:
                    agent_match = re.search(r'-javaagent:([^\s]+)', cmd_str)
                    if agent_match:
                        agent_path = agent_match.group(1)
                        results.append(ScanResult(
                            scanner="MemoryScanner",
                            category="java_agent",
                            name="Java Agent",
                            description=f"Java agent loaded (potential injection): {agent_path}",
                            severity=80,
                            filepath=agent_path,
                            evidence=f"PID: {proc.pid}, Agent: {agent_path}",
                            details={"pid": proc.pid},
                        ))

                # Check for suspicious classpath entries
                text_results = self.detector.scan_text(
                    cmd_str, source="process_cmdline",
                    filepath=f"PID:{proc.pid}"
                )
                for r in text_results:
                    r.scanner = "MemoryScanner"
                    r.details["pid"] = proc.pid
                results.extend(text_results)

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        except Exception as e:
            logger.debug(f"Process env scan error: {e}")
        return results

    def scan_strings_in_memory(self, pid: int,
                                min_length: int = 6) -> List[ScanResult]:
        """Scan readable memory regions of a process for cheat strings.
        Uses Windows API via PowerShell for memory reading.
        """
        results = []
        try:
            # Use procdump or strings approach via PowerShell
            proc = subprocess.run(
                ["powershell", "-Command",
                 f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
                 f"if ($p) {{ "
                 f"  $p.Modules | ForEach-Object {{ $_.FileName }} "
                 f"}}"],
                capture_output=True, text=True, timeout=15
            )
            if proc.returncode == 0 and proc.stdout:
                module_text = proc.stdout
                text_results = self.detector.scan_text(
                    module_text, source="process_modules",
                    filepath=f"PID:{pid}"
                )
                for r in text_results:
                    r.scanner = "MemoryScanner"
                    r.details["pid"] = pid
                results.extend(text_results)
        except Exception as e:
            logger.debug(f"Memory strings scan error: {e}")
        return results
