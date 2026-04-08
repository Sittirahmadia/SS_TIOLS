"""
SS-Tools Ultimate - Shared Utilities
Common utility functions used across all modules.
"""
import os
import sys
import time
import hashlib
import logging
import platform
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

from core.config import LOGS_DIR

# ── Logging Setup ──────────────────────────────────────────────
log_file = LOGS_DIR / f"ss_tools_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("SS-Tools")


def get_timestamp() -> str:
    """Get formatted timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_file_timestamp() -> str:
    """Get timestamp string safe for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


@lru_cache(maxsize=4096)
def file_hash_md5(filepath: str) -> Optional[str]:
    """Compute MD5 hash of a file with caching."""
    try:
        h = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


@lru_cache(maxsize=4096)
def file_hash_sha256(filepath: str) -> Optional[str]:
    """Compute SHA-256 hash of a file with caching."""
    try:
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def format_size(size_bytes: int) -> str:
    """Format file size to human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.1f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} GB"


def format_duration(seconds: float) -> str:
    """Format duration to human-readable string."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.0f}s"


def is_windows() -> bool:
    """Check if running on Windows."""
    return platform.system() == "Windows"


def expand_path(path_template: str) -> Optional[Path]:
    """Expand path template with environment variables."""
    replacements = {
        "{APPDATA}": os.environ.get("APPDATA", ""),
        "{LOCALAPPDATA}": os.environ.get("LOCALAPPDATA", ""),
        "{USERPROFILE}": os.environ.get("USERPROFILE", ""),
        "{HOME}": str(Path.home()),
        "{PROGRAMFILES}": os.environ.get("PROGRAMFILES", ""),
        "{PROGRAMFILESX86}": os.environ.get("PROGRAMFILES(X86)", ""),
    }
    result = path_template
    for key, value in replacements.items():
        result = result.replace(key, value)
    p = Path(result)
    if p.exists():
        return p
    return None


def parallel_execute(func, items: list, max_workers: int = 8,
                     progress_callback=None) -> List[Any]:
    """Execute function in parallel over items with optional progress."""
    results = []
    total = len(items)
    completed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(func, item): item for item in items}
        for future in as_completed(future_map):
            completed += 1
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as e:
                logger.warning(f"Parallel task error: {e}")
            if progress_callback:
                progress_callback(completed, total)
    return results


def safe_read_file(filepath: str, encoding: str = 'utf-8',
                   fallback_encoding: str = 'latin-1') -> Optional[str]:
    """Safely read file with encoding fallback."""
    try:
        with open(filepath, 'r', encoding=encoding) as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(filepath, 'r', encoding=fallback_encoding) as f:
                return f.read()
        except Exception:
            return None
    except Exception:
        return None


def safe_read_binary(filepath: str, max_size: int = 50 * 1024 * 1024) -> Optional[bytes]:
    """Safely read binary file up to max_size."""
    try:
        size = os.path.getsize(filepath)
        if size > max_size:
            with open(filepath, 'rb') as f:
                return f.read(max_size)
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception:
        return None


def severity_color(severity: int) -> str:
    """Get hex color based on severity level."""
    if severity >= 90:
        return "#FF1744"  # Red
    elif severity >= 70:
        return "#FF9100"  # Orange
    elif severity >= 50:
        return "#FFD600"  # Yellow
    elif severity >= 30:
        return "#64DD17"  # Light Green
    else:
        return "#00E676"  # Green


def severity_label(severity: int) -> str:
    """Get text label based on severity level."""
    if severity >= 90:
        return "CRITICAL"
    elif severity >= 70:
        return "HIGH"
    elif severity >= 50:
        return "MEDIUM"
    elif severity >= 30:
        return "LOW"
    else:
        return "INFO"


class ScanResult:
    """Represents a single scan finding."""

    def __init__(self, scanner: str, category: str, name: str,
                 description: str, severity: int, filepath: str = "",
                 line_number: int = 0, evidence: str = "",
                 details: Dict = None):
        self.scanner = scanner
        self.category = category
        self.name = name
        self.description = description
        self.severity = min(max(severity, 0), 100)
        self.filepath = filepath
        self.line_number = line_number
        self.evidence = evidence
        self.details = details or {}
        self.timestamp = get_timestamp()

    def to_dict(self) -> Dict:
        return {
            "scanner": self.scanner,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "severity_label": severity_label(self.severity),
            "filepath": self.filepath,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        return (f"ScanResult({self.scanner}: {self.name} "
                f"[{severity_label(self.severity)}:{self.severity}])")


class ScanProgress:
    """Thread-safe scan progress tracker."""

    def __init__(self):
        self.total = 0
        self.completed = 0
        self.current_file = ""
        self.current_module = ""
        self.start_time = 0.0
        self.results: List[ScanResult] = []
        self._callbacks = []

    def start(self, module: str, total: int):
        self.current_module = module
        self.total = total
        self.completed = 0
        self.start_time = time.time()
        self._notify()

    def update(self, current_file: str = ""):
        self.completed += 1
        self.current_file = current_file
        self._notify()

    def add_result(self, result: ScanResult):
        self.results.append(result)
        self._notify()

    def get_eta(self) -> str:
        if self.completed == 0:
            return "Calculating..."
        elapsed = time.time() - self.start_time
        rate = self.completed / elapsed
        remaining = (self.total - self.completed) / rate if rate > 0 else 0
        return format_duration(remaining)

    def get_progress_pct(self) -> float:
        if self.total == 0:
            return 0.0
        return min(100.0, (self.completed / self.total) * 100)

    def add_callback(self, callback):
        self._callbacks.append(callback)

    def _notify(self):
        for cb in self._callbacks:
            try:
                cb(self)
            except Exception:
                pass

    @property
    def cheat_count(self) -> int:
        return len([r for r in self.results if r.severity >= 80])

    @property
    def suspicious_count(self) -> int:
        return len([r for r in self.results if 40 <= r.severity < 80])

    @property
    def clean(self) -> bool:
        return self.cheat_count == 0
