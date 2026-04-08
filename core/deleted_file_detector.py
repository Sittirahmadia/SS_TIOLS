"""
SS-Tools Ultimate - Deleted File Detector
Detects files deleted during the screenshare session by comparing timestamps.
"""
import os
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import ScanResult, ScanProgress, logger


class DeletedFileDetector:
    """Detects recently deleted cheat files during SS session."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()
        self.session_start = time.time()

    def scan(self, lookback_minutes: int = 30) -> List[ScanResult]:
        """Detect files deleted within the lookback period."""
        results = []
        self.progress.start("Deleted File Detector", 4)

        # 1. Check Windows Security Event Log for file deletions
        self.progress.update("Checking Security Events...")
        results.extend(self._check_security_events(lookback_minutes))

        # 2. Check Recycle Bin for recently deleted items
        self.progress.update("Checking Recycle Bin timestamps...")
        results.extend(self._check_recent_recycle_bin(lookback_minutes))

        # 3. Check NTFS MFT for recent deletions
        self.progress.update("Checking MFT records...")
        results.extend(self._check_mft_deletions(lookback_minutes))

        # 4. Check Sysmon logs if available
        self.progress.update("Checking Sysmon logs...")
        results.extend(self._check_sysmon_logs(lookback_minutes))

        return results

    def _check_security_events(self, lookback_minutes: int) -> List[ScanResult]:
        """Check Windows Security events for file deletion."""
        results = []
        try:
            cutoff = datetime.now() - timedelta(minutes=lookback_minutes)
            cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S")
            proc = subprocess.run(
                ["powershell", "-Command",
                 f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4663;StartTime='{cutoff_str}'}} -MaxEvents 100 2>$null | "
                 "ForEach-Object {{ $_.Message }} 2>$null"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0 and proc.stdout.strip():
                text_results = self.detector.scan_text(
                    proc.stdout, source="security_events",
                    filepath="Windows Security Log"
                )
                for r in text_results:
                    r.scanner = "DeletedFileDetector"
                    r.category = "security_event_deletion"
                    r.description = f"[Security Log] {r.description}"
                    r.severity = min(r.severity + 15, 100)
                results.extend(text_results)
        except Exception as e:
            logger.debug(f"Security event check error: {e}")
        return results

    def _check_recent_recycle_bin(self, lookback_minutes: int) -> List[ScanResult]:
        """Check Recycle Bin for items deleted during the session."""
        results = []
        cutoff = time.time() - (lookback_minutes * 60)

        for drive in "CDEFGHIJ":
            rb_path = Path(f"{drive}:\\$Recycle.Bin")
            if not rb_path.exists():
                continue
            try:
                for root, dirs, files in os.walk(rb_path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            mtime = os.path.getmtime(fpath)
                            if mtime >= cutoff:
                                # Recently deleted file
                                name_results = self.detector.scan_filename(fname, fpath)
                                for r in name_results:
                                    r.scanner = "DeletedFileDetector"
                                    r.category = "recent_deletion"
                                    deleted_time = datetime.fromtimestamp(mtime).strftime("%H:%M:%S")
                                    r.description = f"[RECENT DELETE @ {deleted_time}] {r.description}"
                                    r.severity = min(r.severity + 20, 100)
                                results.extend(name_results)

                                # Even without keyword match, flag recently deleted JARs/EXEs
                                ext = os.path.splitext(fname)[1].lower()
                                if ext in ('.jar', '.exe', '.dll', '.sys', '.ahk'):
                                    deleted_time = datetime.fromtimestamp(mtime).strftime("%H:%M:%S")
                                    results.append(ScanResult(
                                        scanner="DeletedFileDetector",
                                        category="recent_suspicious_deletion",
                                        name=fname,
                                        description=f"Suspicious file deleted during session ({ext}) at {deleted_time}",
                                        severity=75,
                                        filepath=fpath,
                                        evidence=f"Deleted at {deleted_time}, Extension: {ext}",
                                    ))
                        except OSError:
                            pass
            except PermissionError:
                pass

        return results

    def _check_mft_deletions(self, lookback_minutes: int) -> List[ScanResult]:
        """Check USN Journal for recent file deletions."""
        results = []
        try:
            proc = subprocess.run(
                ["powershell", "-Command",
                 f"$cutoff = (Get-Date).AddMinutes(-{lookback_minutes}); "
                 "fsutil usn readjournal C: csv 2>$null | "
                 "Select-String -Pattern '\\.jar|\\.exe|\\.dll|\\.sys|\\.ahk' | "
                 "Select-String -Pattern 'DELETE|RENAME' | "
                 "Select-Object -First 50"],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.strip().split('\n'):
                    text_results = self.detector.scan_text(
                        line, source="usn_journal", filepath="USN Journal"
                    )
                    for r in text_results:
                        r.scanner = "DeletedFileDetector"
                        r.category = "mft_deletion"
                        r.description = f"[MFT] {r.description}"
                        r.severity = min(r.severity + 10, 100)
                    results.extend(text_results)

                    # Flag any jar/exe deletions
                    if any(ext in line.lower() for ext in ['.jar', '.exe', '.dll']):
                        results.append(ScanResult(
                            scanner="DeletedFileDetector",
                            category="mft_file_deletion",
                            name="USN File Deletion",
                            description=f"[MFT] File operation detected in USN Journal",
                            severity=60,
                            evidence=line.strip()[:300],
                        ))
        except Exception as e:
            logger.debug(f"MFT deletion check error: {e}")
        return results

    def _check_sysmon_logs(self, lookback_minutes: int) -> List[ScanResult]:
        """Check Sysmon logs for file deletions (if Sysmon installed)."""
        results = []
        try:
            cutoff = datetime.now() - timedelta(minutes=lookback_minutes)
            cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S")
            proc = subprocess.run(
                ["powershell", "-Command",
                 f"Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational';Id=23,26;StartTime='{cutoff_str}'}} -MaxEvents 50 2>$null | "
                 "ForEach-Object {{ $_.Message }} 2>$null"],
                capture_output=True, text=True, timeout=15
            )
            if proc.returncode == 0 and proc.stdout.strip():
                text_results = self.detector.scan_text(
                    proc.stdout, source="sysmon", filepath="Sysmon Log"
                )
                for r in text_results:
                    r.scanner = "DeletedFileDetector"
                    r.category = "sysmon_deletion"
                    r.description = f"[Sysmon] {r.description}"
                    r.severity = min(r.severity + 10, 100)
                results.extend(text_results)
        except Exception as e:
            logger.debug(f"Sysmon log check error: {e}")
        return results
