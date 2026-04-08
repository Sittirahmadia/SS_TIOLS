"""
SS-Tools Ultimate - Kernel Check Module
Detects kernel-level cheats, rootkits, vulnerable/exploitable drivers,
hidden drivers, and unsigned drivers.
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
            # Use WinVerifyTrust via ctypes
            WINTRUST_ACTION_GENERIC_VERIFY_V2 = \
                '{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}'

            # Simple check using sigcheck-like approach
            proc = subprocess.run(
                ["powershell", "-Command",
                 f"(Get-AuthenticodeSignature '{filepath}').Status"],
                capture_output=True, text=True, timeout=10
            )
            status = proc.stdout.strip()
            return status == "Valid"
        except Exception:
            # Fallback: check PE signature
            try:
                pe = pefile.PE(filepath, fast_load=True)
                # Check for SECURITY directory
                has_sig = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')
                pe.close()
                return has_sig
            except Exception:
                return True  # Assume signed if can't check

    def _check_cheat_drivers(self) -> List[ScanResult]:
        """Cross-reference loaded drivers against cheat signature database."""
        results = []
        try:
            # Get loaded drivers via WMI
            proc = subprocess.run(
                ["powershell", "-Command",
                 "Get-WmiObject Win32_SystemDriver | Select-Object Name,PathName,State | ConvertTo-Csv -NoTypeInformation"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                for line in lines[1:]:
                    fields = line.replace('"', '').split(',')
                    if len(fields) >= 2:
                        name = fields[0].strip().lower()
                        path = fields[1].strip() if len(fields) > 1 else ""

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
        except Exception as e:
            logger.debug(f"Cheat driver check error: {e}")
        return results

    def _check_recent_drivers(self) -> List[ScanResult]:
        """Detect drivers loaded recently (during SS session)."""
        results = []
        try:
            proc = subprocess.run(
                ["powershell", "-Command",
                 "Get-WinEvent -LogName System -FilterXPath '*[System[EventID=7045]]' -MaxEvents 20 2>$null | "
                 "Select-Object TimeCreated,@{N='Service';E={$_.Properties[0].Value}},@{N='Path';E={$_.Properties[1].Value}} | "
                 "ConvertTo-Csv -NoTypeInformation"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0 and proc.stdout.strip():
                lines = proc.stdout.strip().split('\n')
                for line in lines[1:]:
                    fields = line.replace('"', '').split(',')
                    if len(fields) >= 3:
                        time_created = fields[0].strip()
                        service_name = fields[1].strip().lower()
                        service_path = fields[2].strip()

                        for sig in self.db.kernel_driver_signatures:
                            if sig["name"].lower() in service_name or \
                               sig["name"].lower() in service_path.lower():
                                results.append(ScanResult(
                                    scanner="KernelCheck",
                                    category="recent_cheat_driver",
                                    name=sig["name"],
                                    description=f"Recently loaded cheat driver: {sig['name']} at {time_created}",
                                    severity=min(100, sig.get("severity", 90) + 10),
                                    filepath=service_path,
                                    evidence=f"Installed: {time_created}",
                                ))
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
