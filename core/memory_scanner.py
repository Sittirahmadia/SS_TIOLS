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
        Uses Windows API via ctypes for direct memory reading.
        Falls back to PowerShell module enumeration.
        """
        results = []

        # Try direct memory scanning via ctypes on Windows
        if CTYPES_AVAILABLE and os.name == 'nt':
            results.extend(self._scan_memory_regions_ctypes(pid, min_length))
            if results:
                return results

        # Fallback: enumerate modules via PowerShell
        try:
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

    def _scan_memory_regions_ctypes(self, pid: int, min_length: int = 6) -> List[ScanResult]:
        """Scan process memory regions using Windows API (ctypes) for deleted/hidden strings."""
        results = []
        if not CTYPES_AVAILABLE:
            return results

        try:
            # Windows constants
            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400
            MEM_COMMIT = 0x1000
            PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40, 0x80}  # R, RW, RX, etc.

            kernel32 = ctypes.windll.kernel32

            # Open process
            handle = kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
            )
            if not handle:
                return results

            try:
                # Define MEMORY_BASIC_INFORMATION
                class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("BaseAddress", ctypes.c_void_p),
                        ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", ctypes.c_ulong),
                        ("RegionSize", ctypes.c_size_t),
                        ("State", ctypes.c_ulong),
                        ("Protect", ctypes.c_ulong),
                        ("Type", ctypes.c_ulong),
                    ]

                mbi = MEMORY_BASIC_INFORMATION()
                address = 0
                cheat_strings_found = []
                max_regions = 500  # Limit to prevent hanging
                regions_scanned = 0

                # Get cheat keywords for matching
                cheat_keywords = [kw.lower() for kw in self.db.get_all_keywords() if len(kw) >= 4]

                while regions_scanned < max_regions:
                    result_size = kernel32.VirtualQueryEx(
                        handle, ctypes.c_void_p(address),
                        ctypes.byref(mbi), ctypes.sizeof(mbi)
                    )
                    if result_size == 0:
                        break

                    # Only scan committed, readable regions up to 4MB
                    if (mbi.State == MEM_COMMIT and
                        mbi.Protect in PAGE_READABLE and
                        mbi.RegionSize <= 4 * 1024 * 1024):

                        buf = ctypes.create_string_buffer(mbi.RegionSize)
                        bytes_read = ctypes.c_size_t(0)
                        if kernel32.ReadProcessMemory(
                            handle, ctypes.c_void_p(mbi.BaseAddress),
                            buf, mbi.RegionSize, ctypes.byref(bytes_read)
                        ):
                            data = buf.raw[:bytes_read.value]
                            # Extract ASCII strings
                            ascii_strings = re.findall(
                                rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}', data
                            )
                            for s in ascii_strings:
                                try:
                                    decoded = s.decode('ascii', errors='ignore').lower()
                                    for kw in cheat_keywords:
                                        if kw in decoded:
                                            cheat_strings_found.append((kw, decoded[:200]))
                                            break
                                except Exception:
                                    pass

                    address = mbi.BaseAddress + mbi.RegionSize
                    if address <= mbi.BaseAddress:
                        break
                    regions_scanned += 1

                # Report findings
                seen = set()
                for kw, context in cheat_strings_found:
                    if kw not in seen:
                        seen.add(kw)
                        results.append(ScanResult(
                            scanner="MemoryScanner",
                            category="memory_string_forensic",
                            name=f"Memory string: {kw}",
                            description=f"Cheat-related string found in process memory (possibly deleted/hidden): {kw}",
                            severity=85,
                            filepath=f"PID:{pid}",
                            evidence=context[:300],
                            details={"pid": pid, "keyword": kw},
                        ))

            finally:
                kernel32.CloseHandle(handle)

        except Exception as e:
            logger.debug(f"Ctypes memory scan error for PID {pid}: {e}")

        return results

    def scan_all_game_processes(self) -> List[ScanResult]:
        """Forensic memory scan of all game-related processes (Minecraft + mouse software)."""
        results = []
        if not PSUTIL_AVAILABLE:
            return results

        target_processes = set()
        mouse_software = [
            "lghub", "razersynapse", "razercentral", "bloody",
            "icue", "steelseriesengine", "steelseriesgg",
        ]

        try:
            for proc in psutil.process_iter(['pid', 'name']):
                name = (proc.info.get('name') or '').lower()
                pid = proc.info.get('pid', 0)
                # Minecraft/Java processes
                if name in ('java.exe', 'javaw.exe', 'minecraft.exe'):
                    target_processes.add(pid)
                # Mouse software processes (scan for deleted macro strings)
                for ms in mouse_software:
                    if ms in name:
                        target_processes.add(pid)
                        break
        except Exception:
            pass

        for pid in target_processes:
            results.extend(self.scan_strings_in_memory(pid))

        return results
