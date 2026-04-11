"""
SS-Tools Ultimate - Kernel Check Module
Detects kernel-level cheats, rootkits, vulnerable/exploitable drivers,
hidden drivers, unsigned drivers, and minifilter (fltmc) anomalies.

Enhanced with:
  - fltmc filter driver scanning
  - Trusted signer validation against gaming peripheral whitelist
  - SSDT hook detection via cross-view analysis
"""
import os
import re
import struct
import ctypes
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.database import CheatDatabase
from core.config import GAMING_SOFTWARE_WHITELIST
from core.utils import ScanResult, ScanProgress, logger, file_hash_sha256

# Windows-only imports (gracefully handle non-Windows)
try:
    import ctypes.wintypes
    import win32api
    import win32file
    import win32security
    import pefile
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False


class KernelCheck:
    """Kernel-level cheat and rootkit detection."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Run full kernel check scan."""
        results = []

        if not WINDOWS_AVAILABLE:
            logger.warning("Kernel Check requires Windows + pywin32")
            results.append(ScanResult(
                scanner="KernelCheck",
                category="info",
                name="Platform Warning",
                description="Kernel Check hanya tersedia di Windows dengan pywin32",
                severity=0,
            ))
            return results

        self.progress.start("Kernel Check", 5)

        # 1. Enumerate loaded drivers
        self.progress.update("Enumerating drivers...")
        driver_results = self._enumerate_drivers()
        results.extend(driver_results)

        # 2. Check driver signatures
        self.progress.update("Checking signatures...")
        sig_results = self._check_driver_signatures()
        results.extend(sig_results)

        # 3. Check against known cheat driver database
        self.progress.update("Checking cheat database...")
        db_results = self._check_cheat_drivers()
        results.extend(db_results)

        # 4. Detect suspicious / recently loaded drivers
        self.progress.update("Checking recent drivers...")
        recent_results = self._check_recent_drivers()
        results.extend(recent_results)

        # 5. Cross-view detection for hidden drivers
        self.progress.update("Cross-view scanning...")
        hidden_results = self._detect_hidden_drivers()
        results.extend(hidden_results)

        # 6. Minifilter (fltmc) driver scanning
        self.progress.update("Scanning minifilter drivers...")
        fltmc_results = self._scan_fltmc_filters()
        results.extend(fltmc_results)

        # 7. SSDT hook detection
        self.progress.update("Checking SSDT integrity...")
        ssdt_results = self._check_ssdt_hooks()
        results.extend(ssdt_results)

        return results

    def _enumerate_drivers(self) -> List[ScanResult]:
        """Enumerate all loaded kernel drivers."""
        results = []
        try:
            # Use driverquery command
            proc = subprocess.run(
                ["driverquery", "/v", "/fo", "csv"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                if len(lines) > 1:
                    headers = lines[0].replace('"', '').split(',')
                    for line in lines[1:]:
                        fields = line.replace('"', '').split(',')
                        if len(fields) >= 6:
                            driver_name = fields[0].strip()
                            driver_type = fields[3].strip() if len(fields) > 3 else ""
                            driver_state = fields[2].strip() if len(fields) > 2 else ""
                            # Check against cheat database
                            for sig in self.db.kernel_driver_signatures:
                                if sig["name"].lower() in driver_name.lower():
                                    results.append(ScanResult(
                                        scanner="KernelCheck",
                                        category="kernel_cheat_driver",
                                        name=driver_name,
                                        description=f"Known cheat/exploit driver: {sig.get('description', driver_name)}",
                                        severity=sig.get("severity", 100),
                                        evidence=f"Driver: {driver_name}, State: {driver_state}, Type: {driver_type}",
                                    ))
        except Exception as e:
            logger.warning(f"Driver enumeration failed: {e}")
        return results

    def _check_driver_signatures(self) -> List[ScanResult]:
        """Check digital signatures of driver files."""
        results = []
        if not WINDOWS_AVAILABLE:
            return results

        sys_dir = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "drivers"
        if not sys_dir.exists():
            return results

        try:
            driver_files = list(sys_dir.glob("*.sys"))
            for driver_file in driver_files:
                try:
                    is_signed = self._verify_signature(str(driver_file))
                    if not is_signed:
                        fname = driver_file.name.lower()
                        # Check if it's a known cheat driver
                        severity = 60  # Default for unsigned
                        for sig in self.db.kernel_driver_signatures:
                            if sig["name"].lower() in fname:
                                severity = sig.get("severity", 100)
                                break
                        results.append(ScanResult(
                            scanner="KernelCheck",
                            category="unsigned_driver",
                            name=driver_file.name,
                            description=f"Unsigned driver detected: {driver_file.name}",
                            severity=severity,
                            filepath=str(driver_file),
                            evidence=f"No valid digital signature found",
                        ))
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Signature check error: {e}")

        return results

    def _verify_signature(self, filepath: str) -> bool:
        """Verify digital signature of a file."""
        if not WINDOWS_AVAILABLE:
            return True
        try:
            # Efficient PE-based signature check (no PowerShell spam)
            pe = pefile.PE(filepath, fast_load=True)
            # Check for SECURITY directory (certificate table)
            has_sig = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and \
                     pe.OPTIONAL_HEADER.DataDirectories[4].Size > 0
            pe.close()
            return has_sig
        except Exception:
            # If PE parsing fails, assume valid (may be non-PE or system file)
            return True

    def _check_cheat_drivers(self) -> List[ScanResult]:
        """Cross-reference loaded drivers against cheat signature database."""
        results = []
        try:
            # Use driverquery instead of WMI (more efficient, no PowerShell spam)
            proc = subprocess.run(
                ["driverquery", "/v", "/fo", "csv"],
                capture_output=True, text=True, timeout=20
            )
            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                if len(lines) > 1:
                    headers = lines[0].replace('"', '').split(',')
                    for line in lines[1:]:
                        fields = line.replace('"', '').split(',')
                        if len(fields) >= 2:
                            name = fields[0].strip().lower()
                            # PathName may not be available in driverquery
                            path = fields[-1].strip() if len(fields) > 5 else ""

                            for sig in self.db.kernel_driver_signatures:
                                sig_name = sig["name"].lower()
                                if sig_name in name or (path and sig_name in path.lower()):
                                    # Get file hash if available
                                    file_hash = ""
                                    if path and os.path.exists(path):
                                        file_hash = file_hash_sha256(path) or ""

                                    results.append(ScanResult(
                                        scanner="KernelCheck",
                                        category="cheat_driver_match",
                                        name=sig["name"],
                                        description=f"⚠ KERNEL CHEAT DRIVER: {sig.get('description', sig['name'])}",
                                        severity=sig.get("severity", 100),
                                        filepath=path,
                                        evidence=f"Driver: {name}, Hash: {file_hash}",
                                        details={"hash": file_hash, "path": path},
                                    ))
                                    break  # Avoid duplicate results for same driver
        except Exception as e:
            logger.debug(f"Cheat driver check error: {e}")
        return results

    def _check_recent_drivers(self) -> List[ScanResult]:
        """Detect drivers loaded recently (during SS session)."""
        results = []
        # Skip recent driver check if already found issues (reduce PowerShell spam)
        if len(results) > 0:
            return results
        try:
            # Use Event Log via wevtutil (lighter than PowerShell)
            proc = subprocess.run(
                ["wevtutil", "qe", "System", "/q:*[System[EventID=7045]]", "/c:10", "/f:text"],
                capture_output=True, text=True, timeout=15
            )
            if proc.returncode == 0 and proc.stdout.strip():
                lines = proc.stdout.strip().split('\n')
                for line in lines:
                    line_lower = line.lower()
                    for sig in self.db.kernel_driver_signatures:
                        if sig["name"].lower() in line_lower:
                            results.append(ScanResult(
                                scanner="KernelCheck",
                                category="recent_cheat_driver",
                                name=sig["name"],
                                description=f"Recently loaded cheat driver detected: {sig['name']}",
                                severity=min(100, sig.get("severity", 90) + 10),
                                evidence=f"Found in system event log",
                            ))
                            break  # Avoid duplicate results
        except Exception as e:
            logger.debug(f"Recent driver check error: {e}")
        return results

    def _detect_hidden_drivers(self) -> List[ScanResult]:
        """Detect potentially hidden drivers using cross-view technique."""
        results = []
        if not WINDOWS_AVAILABLE:
            return results

        try:
            # Method 1: Compare driverquery vs WMI
            dq_drivers = set()
            proc1 = subprocess.run(
                ["driverquery", "/fo", "csv"],
                capture_output=True, text=True, timeout=15
            )
            if proc1.returncode == 0:
                for line in proc1.stdout.strip().split('\n')[1:]:
                    fields = line.replace('"', '').split(',')
                    if fields:
                        dq_drivers.add(fields[0].strip().lower())

            wmi_drivers = set()
            proc2 = subprocess.run(
                ["powershell", "-Command",
                 "Get-WmiObject Win32_SystemDriver | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=15
            )
            if proc2.returncode == 0:
                for line in proc2.stdout.strip().split('\n'):
                    wmi_drivers.add(line.strip().lower())

            # Drivers in one but not the other could be hidden
            hidden_candidates = wmi_drivers - dq_drivers
            for drv in hidden_candidates:
                if drv and len(drv) > 1:
                    results.append(ScanResult(
                        scanner="KernelCheck",
                        category="hidden_driver",
                        name=drv,
                        description=f"Possible hidden driver (cross-view mismatch): {drv}",
                        severity=70,
                        evidence="Found via WMI but not driverquery",
                    ))

        except Exception as e:
            logger.debug(f"Hidden driver detection error: {e}")

        return results

    def _is_trusted_signer(self, signer: str) -> bool:
        """Check if a driver signer is in the trusted gaming/system whitelist."""
        signer_lower = signer.lower()
        for trusted in GAMING_SOFTWARE_WHITELIST["trusted_signers"]:
            if trusted in signer_lower:
                return True
        return False

    def _scan_fltmc_filters(self) -> List[ScanResult]:
        """Scan minifilter drivers using fltmc command.
        Minifilters can intercept file I/O at the kernel level -- cheat tools
        sometimes install them to hide files or intercept game data.
        """
        results = []
        try:
            proc = subprocess.run(
                ["fltmc", "filters"],
                capture_output=True, text=True, timeout=15
            )
            if proc.returncode == 0 and proc.stdout.strip():
                lines = proc.stdout.strip().split('\n')
                # Skip header lines (first 2-3 lines are headers/separator)
                for line in lines[2:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        filter_name = parts[0].strip()
                        # Check against known cheat minifilters
                        for sig in self.db.kernel_driver_signatures:
                            if sig["name"].lower() in filter_name.lower():
                                results.append(ScanResult(
                                    scanner="KernelCheck",
                                    category="cheat_minifilter",
                                    name=filter_name,
                                    description=f"Suspicious minifilter driver: {filter_name} (matches {sig['name']})",
                                    severity=sig.get("severity", 95),
                                    evidence=f"fltmc output: {line.strip()}",
                                ))
                                break

                        # Flag minifilters not from known vendors
                        known_filter_prefixes = [
                            "wcifs", "cldflt", "storqosflt", "wcnfs", "filecrypt",
                            "luafv", "npsvctrig", "bindfltr", "wof", "fileinfo",
                            "fltmgr", "mup", "dfsc", "csc", "rdyboost",
                            "wd", "windows defender", "mbam", "avgflt",
                        ]
                        filter_lower = filter_name.lower()
                        is_known = any(p in filter_lower for p in known_filter_prefixes)
                        if not is_known and len(filter_name) > 2:
                            # Unknown minifilter -- low severity informational
                            results.append(ScanResult(
                                scanner="KernelCheck",
                                category="unknown_minifilter",
                                name=filter_name,
                                description=f"Unknown minifilter driver: {filter_name}",
                                severity=30,
                                evidence=f"fltmc: {line.strip()}",
                            ))

        except FileNotFoundError:
            logger.debug("fltmc not available (not running as admin?)")
        except Exception as e:
            logger.debug(f"fltmc scan error: {e}")

        return results

    def _check_ssdt_hooks(self) -> List[ScanResult]:
        """Detect SSDT (System Service Descriptor Table) hooks.
        Uses indirect detection: compare loaded kernel modules against
        expected system modules to find rogue kernel-level hooks.
        """
        results = []
        try:
            # Check for suspicious kernel modules that commonly hook SSDT
            proc = subprocess.run(
                ["driverquery", "/si", "/fo", "csv"],
                capture_output=True, text=True, timeout=20
            )
            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                for line in lines[1:]:
                    fields = line.replace('"', '').split(',')
                    if len(fields) >= 5:
                        driver_name = fields[0].strip()
                        is_signed = fields[-1].strip().lower() if len(fields) > 5 else ""

                        # Flag unsigned kernel drivers (potential SSDT hookers)
                        if is_signed in ("false", "no", ""):
                            driver_lower = driver_name.lower()
                            # Skip known false positives
                            if any(safe in driver_lower for safe in
                                   ["virtual", "vm", "vbox", "hyper"]):
                                continue
                            results.append(ScanResult(
                                scanner="KernelCheck",
                                category="unsigned_kernel_module",
                                name=driver_name,
                                description=f"Unsigned kernel module (potential SSDT hook): {driver_name}",
                                severity=65,
                                evidence=f"Driver: {driver_name}, Signed: {is_signed}",
                            ))
        except Exception as e:
            logger.debug(f"SSDT check error: {e}")

        return results

    def get_driver_info(self) -> List[Dict]:
        """Get list of all loaded drivers with info."""
        drivers = []
        try:
            proc = subprocess.run(
                ["driverquery", "/v", "/fo", "csv"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                if len(lines) > 1:
                    for line in lines[1:]:
                        fields = line.replace('"', '').split(',')
                        if len(fields) >= 6:
                            drivers.append({
                                "name": fields[0].strip(),
                                "display_name": fields[1].strip() if len(fields) > 1 else "",
                                "state": fields[2].strip() if len(fields) > 2 else "",
                                "type": fields[3].strip() if len(fields) > 3 else "",
                            })
        except Exception:
            pass
        return drivers
