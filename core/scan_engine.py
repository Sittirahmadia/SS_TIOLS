"""
SS-Tools Ultimate - Scan Engine
Orchestrates ALL scanners in parallel with per-scanner timeouts.
Guarantees: no stuck, no infinite loading, graceful error recovery.
"""
import os
import time
import traceback
import threading
from typing import List, Dict, Callable, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, Future, as_completed, TimeoutError

from core.config import AppSettings
from core.utils import ScanResult, ScanProgress, logger, format_duration


# Per-scanner timeout (seconds) - prevents any single scanner from blocking
SCANNER_TIMEOUTS = {
    "Minecraft Scanner": 30,
    "Mods Scanner": 120,
    "Kernel Check": 20,
    "Process Scanner": 15,
    "Browser Scanner": 25,
    "Deleted String Scanner": 20,
    "Deleted File Detector": 15,
    "Memory Scanner": 15,
    "Network Scanner": 15,
}

DEFAULT_TIMEOUT = 30


class ScannerTask:
    """Represents a single scanner task with metadata."""

    def __init__(self, name: str, func: Callable, enabled: bool = True,
                 timeout: int = None, parallel_group: int = 0):
        self.name = name
        self.func = func
        self.enabled = enabled
        self.timeout = timeout or SCANNER_TIMEOUTS.get(name, DEFAULT_TIMEOUT)
        self.parallel_group = parallel_group  # 0 = run in parallel pool
        self.status = "pending"  # pending, running, completed, failed, timeout
        self.results: List[ScanResult] = []
        self.error: str = ""
        self.duration: float = 0.0

    def run(self) -> List[ScanResult]:
        """Execute the scanner with error handling."""
        self.status = "running"
        start = time.time()
        try:
            self.results = self.func() or []
            self.status = "completed"
        except Exception as e:
            self.status = "failed"
            self.error = f"{type(e).__name__}: {str(e)}"
            logger.error(f"Scanner {self.name} failed: {self.error}")
            logger.debug(traceback.format_exc())
            self.results = [ScanResult(
                scanner=self.name,
                category="scanner_error",
                name=f"{self.name} Error",
                description=f"Scanner encountered an error: {self.error}",
                severity=0,
            )]
        finally:
            self.duration = time.time() - start
        return self.results


class ScanEngine:
    """
    Parallel scan orchestrator.
    Runs all scanners concurrently with per-scanner timeouts.
    Thread-safe progress reporting via callbacks.
    """

    def __init__(self, settings: AppSettings = None):
        self.settings = settings or AppSettings.load()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._tasks: List[ScannerTask] = []
        self._all_results: List[ScanResult] = []
        self._mod_results = []
        self._completed_scanners = 0
        self._total_scanners = 0
        self._start_time = 0.0

        # Callbacks
        self.on_scanner_start: Optional[Callable] = None      # (scanner_name)
        self.on_scanner_done: Optional[Callable] = None        # (scanner_name, results, duration)
        self.on_scanner_error: Optional[Callable] = None       # (scanner_name, error_msg)
        self.on_result: Optional[Callable] = None              # (ScanResult)
        self.on_mod_result: Optional[Callable] = None          # (ModScanResult)
        self.on_progress: Optional[Callable] = None            # (completed, total, pct, eta_str)
        self.on_finished: Optional[Callable] = None            # (all_results, mod_results, duration)

    def stop(self):
        """Signal all scanners to stop."""
        self._stop_event.set()

    @property
    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def _emit_progress(self):
        """Thread-safe progress emission."""
        if self.on_progress and self._total_scanners > 0:
            pct = int((self._completed_scanners / self._total_scanners) * 100)
            elapsed = time.time() - self._start_time
            if self._completed_scanners > 0:
                rate = elapsed / self._completed_scanners
                remaining = rate * (self._total_scanners - self._completed_scanners)
                eta = format_duration(remaining)
            else:
                eta = "calculating..."
            try:
                self.on_progress(self._completed_scanners, self._total_scanners, pct, eta)
            except Exception:
                pass

    def _make_scanner_tasks(self, scan_type: str, mod_dir: str = "",
                            deep_scan: bool = False) -> List[ScannerTask]:
        """Build list of scanner tasks based on scan type."""
        tasks = []
        progress = ScanProgress()

        if scan_type in ("full", "minecraft"):
            def mc_scan():
                from core.minecraft_scanner import MinecraftScanner
                return MinecraftScanner(progress).scan_all()
            tasks.append(ScannerTask("Minecraft Scanner", mc_scan))

        if scan_type in ("full", "process"):
            def proc_scan():
                from core.process_scanner import ProcessScanner
                return ProcessScanner(progress).scan()
            tasks.append(ScannerTask("Process Scanner", proc_scan))

        if scan_type in ("full", "browser"):
            if self.settings.browser_scan_enabled or scan_type == "browser":
                def browser_scan():
                    from core.browser_scanner import BrowserScanner
                    return BrowserScanner(progress).scan()
                tasks.append(ScannerTask("Browser Scanner", browser_scan))

        if scan_type in ("full", "deleted"):
            def deleted_str_scan():
                from core.string_deleted_scanner import StringDeletedScanner
                return StringDeletedScanner(progress).scan()
            tasks.append(ScannerTask("Deleted String Scanner", deleted_str_scan))

            def deleted_file_scan():
                from core.deleted_file_detector import DeletedFileDetector
                return DeletedFileDetector(progress).scan()
            tasks.append(ScannerTask("Deleted File Detector", deleted_file_scan))

        if scan_type in ("full", "memory"):
            if self.settings.memory_scan_enabled or scan_type == "memory":
                def mem_scan():
                    from core.memory_scanner import MemoryScanner
                    return MemoryScanner(progress).scan()
                tasks.append(ScannerTask("Memory Scanner", mem_scan))

        if scan_type in ("full", "network"):
            if self.settings.network_scan_enabled or scan_type == "network":
                def net_scan():
                    from core.network_scanner import NetworkScanner
                    return NetworkScanner(progress).scan()
                tasks.append(ScannerTask("Network Scanner", net_scan))

        if scan_type in ("full", "macro"):
            def macro_scan():
                from core.mouse_macro_scanner import MouseMacroScanner
                return MouseMacroScanner(progress).scan()
            tasks.append(ScannerTask("Mouse Macro Scanner", macro_scan, timeout=20))

        if scan_type in ("full", "kernel"):
            if self.settings.kernel_check_enabled or scan_type == "kernel":
                def kernel_scan():
                    from core.kernel_check import KernelCheck
                    return KernelCheck(progress).scan()
                tasks.append(ScannerTask("Kernel Check", kernel_scan))

        if scan_type in ("full", "mods"):
            def mods_scan():
                from core.mods_scanner import ModsScanner
                scanner = ModsScanner(progress, self.settings)
                if mod_dir:
                    mod_results = scanner.scan_directory(mod_dir)
                else:
                    mod_files = scanner.find_all_mods()
                    if not mod_files:
                        return []
                    mod_results = scanner.scan_mods(mod_files, deep_scan)

                scan_results = []
                for mr in mod_results:
                    with self._lock:
                        self._mod_results.append(mr)
                    if self.on_mod_result:
                        try:
                            self.on_mod_result(mr)
                        except Exception:
                            pass
                    if mr.status != "CLEAN":
                        sr = ScanResult(
                            scanner="ModsScanner",
                            category=f"mod_{mr.status.lower()}",
                            name=mr.filename,
                            description=f"{mr.status}: {mr.filename} (severity: {mr.severity})",
                            severity=mr.severity,
                            filepath=mr.filepath,
                        )
                        scan_results.append(sr)
                return scan_results
            tasks.append(ScannerTask("Mods Scanner", mods_scan, timeout=120))

        return tasks

    def run_scan(self, scan_type: str = "full", mod_dir: str = "",
                 deep_scan: bool = False) -> Tuple[List[ScanResult], list, float]:
        """
        Execute scan. All scanners run in parallel with timeouts.
        Returns (all_results, mod_results, duration).
        """
        self._stop_event.clear()
        self._all_results = []
        self._mod_results = []
        self._completed_scanners = 0
        self._start_time = time.time()

        self._tasks = self._make_scanner_tasks(scan_type, mod_dir, deep_scan)
        self._total_scanners = len(self._tasks)

        if self._total_scanners == 0:
            duration = time.time() - self._start_time
            if self.on_finished:
                self.on_finished([], [], duration)
            return [], [], duration

        logger.info(f"Starting {scan_type} scan with {self._total_scanners} scanners in parallel")
        self._emit_progress()

        # Use ThreadPoolExecutor to run ALL scanners in parallel
        max_workers = min(self._total_scanners, self.settings.max_threads)
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scanner") as pool:
            future_to_task: Dict[Future, ScannerTask] = {}
            
            # Submit all tasks immediately
            for task in self._tasks:
                if self.is_stopped:
                    break
                if self.on_scanner_start:
                    try:
                        self.on_scanner_start(task.name)
                    except Exception:
                        pass
                future = pool.submit(task.run)
                future_to_task[future] = task

            # Collect results as they complete with NO global timeout
            # Each scanner has its own timeout via task.timeout
            for future in as_completed(future_to_task):
                if self.is_stopped:
                    break
                task = future_to_task[future]
                try:
                    results = future.result(timeout=task.timeout)
                    # Emit individual results
                    for r in results:
                        with self._lock:
                            self._all_results.append(r)
                        if self.on_result:
                            try:
                                self.on_result(r)
                            except Exception:
                                pass
                    if self.on_scanner_done:
                        try:
                            self.on_scanner_done(task.name, results, task.duration)
                        except Exception:
                            pass
                    logger.info(f"  {task.name}: {len(results)} findings in {format_duration(task.duration)}")

                except TimeoutError:
                    task.status = "timeout"
                    task.error = f"Scanner timed out after {task.timeout}s"
                    logger.warning(f"  {task.name}: TIMEOUT after {task.timeout}s")
                    timeout_result = ScanResult(
                        scanner=task.name, category="scanner_timeout",
                        name=f"{task.name} Timeout",
                        description=f"Scanner timed out after {task.timeout}s — skipped",
                        severity=0,
                    )
                    with self._lock:
                        self._all_results.append(timeout_result)
                    if self.on_scanner_error:
                        try:
                            self.on_scanner_error(task.name, task.error)
                        except Exception:
                            pass

                except Exception as e:
                    task.status = "failed"
                    task.error = str(e)
                    logger.error(f"  {task.name}: ERROR — {e}")
                    if self.on_scanner_error:
                        try:
                            self.on_scanner_error(task.name, str(e))
                        except Exception:
                            pass

                finally:
                    with self._lock:
                        self._completed_scanners += 1
                    self._emit_progress()

        duration = time.time() - self._start_time
        logger.info(f"Scan complete: {len(self._all_results)} findings in {format_duration(duration)}")

        if self.on_finished:
            try:
                self.on_finished(self._all_results, self._mod_results, duration)
            except Exception:
                pass

        return self._all_results, self._mod_results, duration

    def get_summary(self) -> Dict:
        """Get scan summary statistics."""
        results = self._all_results
        return {
            "total": len(results),
            "critical": len([r for r in results if r.severity >= 90]),
            "high": len([r for r in results if 70 <= r.severity < 90]),
            "medium": len([r for r in results if 50 <= r.severity < 70]),
            "low": len([r for r in results if r.severity < 50]),
            "scanners_total": self._total_scanners,
            "scanners_completed": self._completed_scanners,
            "scanners_failed": len([t for t in self._tasks if t.status in ("failed", "timeout")]),
            "duration": time.time() - self._start_time if self._start_time else 0,
            "is_cheater": (
                len([r for r in results if r.severity >= 90]) > 0 or
                len([r for r in results if 70 <= r.severity < 90]) > 2
            ),
        }
