"""
SS-Tools Ultimate - Evidence Collector & Report Generator
Automatically collects evidence and generates professional reports.
"""
import os
import json
import shutil
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from core.config import EVIDENCE_DIR, REPORTS_DIR, APP_NAME, APP_VERSION
from core.utils import (
    ScanResult, ScanProgress, logger, get_file_timestamp,
    severity_label, severity_color, format_size, format_duration
)


class EvidenceCollector:
    """Automatically collects and organizes evidence."""

    def __init__(self):
        self.session_id = get_file_timestamp()
        self.evidence_path = EVIDENCE_DIR / self.session_id
        self.evidence_path.mkdir(parents=True, exist_ok=True)
        self.collected_items: List[Dict] = []

    def collect_screenshot(self, label: str = "evidence") -> Optional[str]:
        """Take screenshot and save to evidence folder."""
        try:
            screenshot_path = self.evidence_path / f"screenshot_{label}_{get_file_timestamp()}.png"
            # Use PowerShell for screenshot on Windows
            ps_script = f"""
            Add-Type -AssemblyName System.Windows.Forms
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
            $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
            $bitmap.Save('{str(screenshot_path)}')
            $graphics.Dispose()
            $bitmap.Dispose()
            """
            subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True, timeout=10
            )
            if screenshot_path.exists():
                self.collected_items.append({
                    "type": "screenshot",
                    "path": str(screenshot_path),
                    "label": label,
                    "timestamp": get_file_timestamp(),
                })
                logger.info(f"Screenshot saved: {screenshot_path}")
                return str(screenshot_path)
        except Exception as e:
            logger.debug(f"Screenshot error: {e}")
        return None

    def collect_file(self, source_path: str, label: str = "") -> Optional[str]:
        """Copy a suspicious file to evidence folder."""
        try:
            src = Path(source_path)
            if src.exists() and src.stat().st_size < 100 * 1024 * 1024:  # Max 100MB
                dest = self.evidence_path / "files" / (label or src.name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, dest)
                self.collected_items.append({
                    "type": "file",
                    "path": str(dest),
                    "original": source_path,
                    "label": label or src.name,
                    "timestamp": get_file_timestamp(),
                })
                return str(dest)
        except Exception as e:
            logger.debug(f"File collection error: {e}")
        return None

    def collect_process_list(self) -> Optional[str]:
        """Save current process list to evidence."""
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    processes.append(proc.info)
                except Exception:
                    pass
            output_path = self.evidence_path / f"processes_{get_file_timestamp()}.json"
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(processes, f, indent=2, default=str, ensure_ascii=False)
            self.collected_items.append({
                "type": "process_list",
                "path": str(output_path),
                "timestamp": get_file_timestamp(),
            })
            return str(output_path)
        except Exception as e:
            logger.debug(f"Process list collection error: {e}")
        return None

    def save_scan_results(self, results: List[ScanResult]) -> str:
        """Save scan results to JSON in evidence folder."""
        output_path = self.evidence_path / f"scan_results_{get_file_timestamp()}.json"
        data = [r.to_dict() for r in results]
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.collected_items.append({
            "type": "scan_results",
            "path": str(output_path),
            "count": len(data),
            "timestamp": get_file_timestamp(),
        })
        return str(output_path)


class ReportGenerator:
    """Generates professional HTML/PDF reports."""

    def __init__(self):
        self.report_dir = REPORTS_DIR

    def generate_html_report(self, results: List[ScanResult],
                              scan_duration: float = 0,
                              player_name: str = "Unknown",
                              staff_name: str = "Staff",
                              server_name: str = "Server",
                              mod_results: list = None) -> str:
        """Generate a detailed HTML report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_timestamp = get_file_timestamp()

        # Categorize results
        critical = [r for r in results if r.severity >= 90]
        high = [r for r in results if 70 <= r.severity < 90]
        medium = [r for r in results if 50 <= r.severity < 70]
        low = [r for r in results if r.severity < 50]

        is_cheater = len(critical) > 0 or len(high) > 2
        verdict = "CHEATER DETECTED" if is_cheater else "PLAYER CLEAN"
        verdict_color = "#FF1744" if is_cheater else "#00E676"
        verdict_bg = "#2d0a0a" if is_cheater else "#0a2d0a"

        # Build findings HTML
        findings_html = ""
        for i, r in enumerate(sorted(results, key=lambda x: -x.severity)):
            color = severity_color(r.severity)
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="badge" style="background:{color};">{severity_label(r.severity)} ({r.severity})</span>
                    <span class="scanner-badge">{r.scanner}</span>
                    <span class="category">{r.category}</span>
                </div>
                <div class="finding-name">{self._escape(r.name)}</div>
                <div class="finding-desc">{self._escape(r.description)}</div>
                {f'<div class="finding-path">Path: {self._escape(r.filepath)}</div>' if r.filepath else ''}
                {f'<div class="finding-evidence">Evidence: <code>{self._escape(r.evidence[:300])}</code></div>' if r.evidence else ''}
            </div>
            """

        # Mod results table
        mods_html = ""
        if mod_results:
            mods_html = '<h2>Mod Scanner Results</h2><table class="mod-table"><tr><th>Mod</th><th>Status</th><th>Severity</th><th>Classes</th><th>Findings</th></tr>'
            for m in mod_results:
                status = m.status if hasattr(m, 'status') else 'UNKNOWN'
                sev = m.severity if hasattr(m, 'severity') else 0
                color = severity_color(sev)
                fname = m.filename if hasattr(m, 'filename') else str(m)
                cls_count = m.classes_scanned if hasattr(m, 'classes_scanned') else 0
                finding_count = len(m.findings) if hasattr(m, 'findings') else 0
                mods_html += f'<tr><td>{self._escape(fname)}</td><td style="color:{color};font-weight:bold;">{status}</td><td>{sev}</td><td>{cls_count}</td><td>{finding_count}</td></tr>'
            mods_html += '</table>'

        html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>SS-Tools Report - {player_name}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', system-ui, sans-serif; padding: 30px; }}
.header {{ text-align: center; padding: 40px 0; border-bottom: 2px solid #30363d; margin-bottom: 30px; }}
.header h1 {{ font-size: 28px; color: #58a6ff; margin-bottom: 10px; }}
.verdict {{ font-size: 48px; font-weight: 900; color: {verdict_color}; background: {verdict_bg}; padding: 30px; border-radius: 16px; margin: 20px 0; text-align: center; border: 3px solid {verdict_color}; text-shadow: 0 0 20px {verdict_color}; }}
.info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
.info-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; }}
.info-card label {{ color: #8b949e; font-size: 12px; text-transform: uppercase; }}
.info-card .value {{ font-size: 20px; font-weight: 700; margin-top: 5px; }}
.stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 25px 0; }}
.stat {{ background: #161b22; border-radius: 8px; padding: 20px; text-align: center; border: 1px solid #30363d; }}
.stat .num {{ font-size: 36px; font-weight: 900; }}
.stat .label {{ color: #8b949e; margin-top: 5px; }}
h2 {{ color: #58a6ff; margin: 25px 0 15px; font-size: 22px; }}
.finding {{ background: #161b22; border-radius: 8px; padding: 15px; margin: 10px 0; }}
.finding-header {{ display: flex; gap: 10px; align-items: center; margin-bottom: 8px; }}
.badge {{ padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; color: #fff; }}
.scanner-badge {{ background: #1f6feb; padding: 3px 8px; border-radius: 8px; font-size: 11px; }}
.category {{ color: #8b949e; font-size: 12px; }}
.finding-name {{ font-weight: 700; font-size: 16px; margin-bottom: 4px; }}
.finding-desc {{ color: #c9d1d9; font-size: 14px; }}
.finding-path {{ color: #8b949e; font-size: 12px; margin-top: 4px; word-break: break-all; }}
.finding-evidence {{ margin-top: 6px; }}
.finding-evidence code {{ background: #0d1117; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #f0883e; }}
.mod-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
.mod-table th, .mod-table td {{ padding: 10px; text-align: left; border-bottom: 1px solid #30363d; }}
.mod-table th {{ background: #161b22; color: #58a6ff; }}
.footer {{ text-align: center; padding: 30px 0; color: #8b949e; border-top: 1px solid #30363d; margin-top: 30px; }}
@media print {{ body {{ background: #fff; color: #000; }} .finding {{ border: 1px solid #ddd; }} }}
</style>
</head>
<body>
<div class="header">
    <h1>{APP_NAME} v{APP_VERSION} - Screenshare Report</h1>
    <p>Generated: {timestamp}</p>
</div>

<div class="verdict">{verdict}</div>

<div class="info-grid">
    <div class="info-card"><label>Player</label><div class="value">{self._escape(player_name)}</div></div>
    <div class="info-card"><label>Staff</label><div class="value">{self._escape(staff_name)}</div></div>
    <div class="info-card"><label>Server</label><div class="value">{self._escape(server_name)}</div></div>
    <div class="info-card"><label>Scan Duration</label><div class="value">{format_duration(scan_duration)}</div></div>
</div>

<div class="stats">
    <div class="stat"><div class="num" style="color:#FF1744;">{len(critical)}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num" style="color:#FF9100;">{len(high)}</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#FFD600;">{len(medium)}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num" style="color:#00E676;">{len(low)}</div><div class="label">Low/Info</div></div>
</div>

<h2>All Findings ({len(results)} total)</h2>
{findings_html if results else '<p style="color:#8b949e;">No findings detected. Player appears clean.</p>'}

{mods_html}

<div class="footer">
    <p>{APP_NAME} v{APP_VERSION} &copy; 2026 | Anti-Cheat Screenshare Tool</p>
    <p>This report is auto-generated and should be reviewed by staff.</p>
</div>
</body>
</html>"""

        output_path = self.report_dir / f"SS_Report_{player_name}_{file_timestamp}.html"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        logger.info(f"Report generated: {output_path}")
        return str(output_path)

    @staticmethod
    def _escape(text: str) -> str:
        """HTML-escape text."""
        return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))
