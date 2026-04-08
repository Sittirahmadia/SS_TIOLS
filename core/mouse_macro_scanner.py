"""
SS-Tools Ultimate - Mouse Macro Scanner
Inspects Logitech G Hub, Razer Synapse, Bloody/A4Tech, Corsair iCUE,
and SteelSeries macro configurations for suspicious PvP macros.

PRINCIPLE: Tidak mendeteksi software-nya (false flag), tapi mendeteksi
ISI MACRO yang mencurigakan (autoclicker, anchor macro, crystal macro, dll).
"""
import os
import re
import json
import glob
import sqlite3
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from xml.etree import ElementTree as ET

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import ScanResult, ScanProgress, logger, safe_read_file


# ── Suspicious macro content patterns ──────────────────────────────────
# These detect the CONTENT of macros, not the software itself
SUSPICIOUS_MACRO_PATTERNS = {
    # Autoclicker patterns (very fast repeated clicks)
    # NOTE: rapid click patterns removed from simple indicator matching
    # to prevent false flags on normal button configs ("button1": "left_click").
    # Click speed is detected via _check_timing_patterns() instead.
    "very_short_delay": {
        "description": "Very short delay between actions (<50ms = inhuman speed)",
        "severity": 95,
        "patterns": [
            r'"delay"\s*:\s*[1-4]\d\b',       # JSON: delay < 50
            r'<Delay>\s*[1-4]\d\s*</Delay>',   # XML: delay < 50
            r'Sleep\s*\(\s*[1-4]\d\s*\)',       # Lua: Sleep(10-49)
            r'delay\s*=\s*[1-4]\d\b',           # Generic
        ],
    },
    "crystal_pvp_macro": {
        "description": "Crystal PvP macro (place + detonate crystal pattern)",
        "severity": 100,
        "indicators": ["crystal", "obsidian", "anchor", "totem", "hotbar",
                        "slot4", "slot5", "slot1", "endcrystal", "end_crystal"],
    },
    "anchor_macro": {
        "description": "Anchor macro (place + ignite respawn anchor)",
        "severity": 100,
        "indicators": ["anchor", "glowstone", "respawn_anchor", "respawnanchor"],
    },
    "hotbar_switch": {
        "description": "Rapid hotbar switching macro (totem/crystal swap)",
        "severity": 85,
        "indicators": ["hotbar", "hotkey", "slot_switch", "inventory_swap",
                        "offhand", "swap_hand"],
    },
    "w_tap_macro": {
        "description": "W-Tap combo macro (sprint reset for PvP)",
        "severity": 80,
        "indicators": ["wtap", "w_tap", "sprint_reset", "sprintreset",
                        "forward_tap", "combo_tap"],
    },
    "butterfly_click": {
        "description": "Butterfly click macro (double-click simulation)",
        "severity": 85,
        "indicators": ["butterfly", "double_click", "doubleclick", "jitter",
                        "drag_click", "dragclick"],
    },
    "pearl_macro": {
        "description": "Ender pearl macro (auto-throw pearl)",
        "severity": 80,
        "indicators": ["pearl", "enderpearl", "ender_pearl", "throw_pearl"],
    },
    "sword_macro": {
        "description": "Sword PvP macro (attack automation)",
        "severity": 90,
        "indicators": ["sword", "attack", "swing", "crit", "critical",
                        "knockback", "combo"],
    },
    "mace_macro": {
        "description": "Mace PvP macro (mace attack automation)",
        "severity": 90,
        "indicators": ["mace", "wind_charge", "windcharge", "mace_attack"],
    },
    "toggle_sneak": {
        "description": "Toggle sneak/sprint macro",
        "severity": 50,
        "indicators": ["toggle_sneak", "togglesneak", "toggle_sprint", "togglesprint"],
    },
    "lua_autoclicker": {
        "description": "Lua script autoclicker (Logitech G Hub)",
        "severity": 95,
        "indicators": ["PressMouseButton", "ReleaseMouseButton", "PressAndReleaseMouseButton",
                        "IsMouseButtonPressed", "Sleep", "EnablePrimaryMouseButtonEvents",
                        "OnEvent", "MOUSE_BUTTON_PRESSED"],
    },
}

# Minimum delay thresholds (ms) - below these = inhuman/macro
INHUMAN_DELAY_MS = 30       # < 30ms between clicks = definitely macro
SUSPICIOUS_DELAY_MS = 50    # < 50ms = very likely macro
FAST_DELAY_MS = 80          # < 80ms = suspicious for non-gaming mice


class MouseMacroScanner:
    """
    Scans mouse software macro configurations for suspicious PvP macros.
    Does NOT flag having the software — only flags suspicious macro CONTENT.
    """

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Scan all mouse software macro files."""
        results = []
        self.progress.start("Mouse Macro Scanner", 6)

        # 1. Logitech G Hub
        self.progress.update("Scanning Logitech G Hub macros...")
        results.extend(self._scan_logitech_ghub())

        # 2. Logitech Gaming Software (legacy)
        self.progress.update("Scanning Logitech Gaming Software...")
        results.extend(self._scan_logitech_lgs())

        # 3. Razer Synapse
        self.progress.update("Scanning Razer Synapse macros...")
        results.extend(self._scan_razer_synapse())

        # 4. Bloody / A4Tech
        self.progress.update("Scanning Bloody/A4Tech macros...")
        results.extend(self._scan_bloody())

        # 5. Corsair iCUE
        self.progress.update("Scanning Corsair iCUE macros...")
        results.extend(self._scan_corsair_icue())

        # 6. SteelSeries GG
        self.progress.update("Scanning SteelSeries macros...")
        results.extend(self._scan_steelseries())

        return results

    # ── Logitech G Hub ────────────────────────────────────────────────
    def _scan_logitech_ghub(self) -> List[ScanResult]:
        """Scan Logitech G Hub settings.db (SQLite with JSON macro data)."""
        results = []
        ghub_paths = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "LGHUB", "settings.db"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "LGHUB", "settings.json"),
            os.path.join(os.environ.get("APPDATA", ""), "LGHUB", "settings.db"),
        ]

        for db_path in ghub_paths:
            if not os.path.exists(db_path):
                continue

            try:
                if db_path.endswith('.db'):
                    results.extend(self._scan_ghub_sqlite(db_path))
                elif db_path.endswith('.json'):
                    results.extend(self._scan_ghub_json(db_path))
            except Exception as e:
                logger.debug(f"G Hub scan error: {e}")

        # Also scan Lua script files (G Hub supports Lua macros)
        lua_dirs = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "LGHUB"),
            os.path.join(os.environ.get("APPDATA", ""), "LGHUB"),
        ]
        for lua_dir in lua_dirs:
            if os.path.exists(lua_dir):
                results.extend(self._scan_lua_scripts(lua_dir))

        return results

    def _scan_ghub_sqlite(self, db_path: str) -> List[ScanResult]:
        """Extract and scan JSON macro data from G Hub SQLite database."""
        results = []
        try:
            # Copy to temp to avoid locking
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name
            shutil.copy2(db_path, tmp_path)

            conn = sqlite3.connect(tmp_path)
            # G Hub stores settings as JSON in a data table
            for table in ['data', 'settings', 'DATA']:
                try:
                    cursor = conn.execute(f"SELECT * FROM {table}")
                    for row in cursor:
                        for col in row:
                            if isinstance(col, (str, bytes)):
                                text = col if isinstance(col, str) else col.decode('utf-8', errors='replace')
                                if len(text) > 20:
                                    macro_results = self._analyze_macro_content(
                                        text, "Logitech G Hub", db_path
                                    )
                                    results.extend(macro_results)
                except sqlite3.OperationalError:
                    continue
            conn.close()
            os.unlink(tmp_path)
        except Exception as e:
            logger.debug(f"G Hub SQLite error: {e}")
        return results

    def _scan_ghub_json(self, json_path: str) -> List[ScanResult]:
        """Scan G Hub JSON settings file."""
        results = []
        content = safe_read_file(json_path)
        if content:
            results.extend(self._analyze_macro_content(content, "Logitech G Hub", json_path))
        return results

    def _scan_lua_scripts(self, directory: str) -> List[ScanResult]:
        """Scan Lua macro scripts in G Hub directory."""
        results = []
        try:
            for root, dirs, files in os.walk(directory):
                for fname in files:
                    if fname.endswith('.lua'):
                        fpath = os.path.join(root, fname)
                        content = safe_read_file(fpath)
                        if content:
                            lua_results = self._analyze_lua_macro(content, fpath)
                            results.extend(lua_results)
        except Exception as e:
            logger.debug(f"Lua script scan error: {e}")
        return results

    def _analyze_lua_macro(self, content: str, filepath: str) -> List[ScanResult]:
        """Analyze a Lua macro script for suspicious patterns."""
        results = []
        content_lower = content.lower()

        # Check for Logitech-specific Lua API calls that indicate autoclicker
        lua_indicators = {
            "PressMouseButton": ("Mouse button press via Lua API", 70),
            "ReleaseMouseButton": ("Mouse button release via Lua API", 70),
            "PressAndReleaseMouseButton": ("Click simulation via Lua API", 80),
            "EnablePrimaryMouseButtonEvents": ("Primary mouse button event hook", 85),
            "IsMouseButtonPressed": ("Mouse button state check", 60),
        }

        found_indicators = []
        for indicator, (desc, sev) in lua_indicators.items():
            if indicator in content:
                found_indicators.append(indicator)

        # If script has click simulation + loop/sleep = autoclicker
        has_click = any(i in content for i in ["PressMouseButton", "PressAndReleaseMouseButton"])
        has_loop = "while" in content_lower or "repeat" in content_lower or "for " in content_lower
        has_sleep = "Sleep" in content or "sleep" in content_lower

        if has_click and has_loop and has_sleep:
            # Extract delay value
            delay_match = re.search(r'Sleep\s*\(\s*(\d+)\s*\)', content)
            delay = int(delay_match.group(1)) if delay_match else 0

            sev = 95 if delay < SUSPICIOUS_DELAY_MS else 80
            results.append(ScanResult(
                scanner="MouseMacroScanner",
                category="lua_autoclicker",
                name="Logitech Lua Autoclicker",
                description=f"[Logitech G Hub] Lua autoclicker detected (delay: {delay}ms)",
                severity=sev,
                filepath=filepath,
                evidence=f"Click + Loop + Sleep({delay}ms) pattern in Lua script",
                details={"software": "Logitech G Hub", "delay_ms": delay,
                         "indicators": found_indicators},
            ))

        # Check for PvP-specific content
        pvp_results = self._analyze_macro_content(content, "Logitech G Hub Lua", filepath)
        results.extend(pvp_results)

        return results

    # ── Logitech Gaming Software (Legacy) ─────────────────────────────
    def _scan_logitech_lgs(self) -> List[ScanResult]:
        """Scan legacy Logitech Gaming Software profiles."""
        results = []
        lgs_paths = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Logitech",
                         "Logitech Gaming Software", "profiles"),
            os.path.join(os.environ.get("APPDATA", ""), "Logitech",
                         "Logitech Gaming Software", "profiles"),
        ]

        for lgs_dir in lgs_paths:
            if not os.path.exists(lgs_dir):
                continue
            try:
                for xml_file in glob.glob(os.path.join(lgs_dir, "*.xml")):
                    content = safe_read_file(xml_file)
                    if content:
                        results.extend(self._analyze_macro_content(
                            content, "Logitech Gaming Software", xml_file
                        ))
                        results.extend(self._analyze_xml_macros(
                            content, "Logitech Gaming Software", xml_file
                        ))
            except Exception as e:
                logger.debug(f"LGS scan error: {e}")
        return results

    # ── Razer Synapse ─────────────────────────────────────────────────
    def _scan_razer_synapse(self) -> List[ScanResult]:
        """Scan Razer Synapse macro files (XML format)."""
        results = []

        # Synapse 3 paths
        synapse_paths = [
            os.path.join("C:\\ProgramData", "Razer", "Synapse3", "Accounts"),
            os.path.join("C:\\ProgramData", "Razer", "Synapse", "Accounts"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Razer", "Synapse3"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Razer", "Synapse"),
        ]

        for base_path in synapse_paths:
            if not os.path.exists(base_path):
                continue
            try:
                # Walk through all account folders looking for Macros/ directories
                for root, dirs, files in os.walk(base_path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        if fname.endswith('.xml') or fname.endswith('.json'):
                            content = safe_read_file(fpath)
                            if content:
                                results.extend(self._analyze_macro_content(
                                    content, "Razer Synapse", fpath
                                ))
                                if fname.endswith('.xml'):
                                    results.extend(self._analyze_xml_macros(
                                        content, "Razer Synapse", fpath
                                    ))
            except Exception as e:
                logger.debug(f"Razer scan error: {e}")

        # Synapse 4 path
        synapse4 = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Razer", "RazerAppEngine")
        if os.path.exists(synapse4):
            try:
                for root, dirs, files in os.walk(synapse4):
                    for fname in files:
                        if fname.endswith(('.json', '.xml')):
                            fpath = os.path.join(root, fname)
                            content = safe_read_file(fpath)
                            if content:
                                results.extend(self._analyze_macro_content(
                                    content, "Razer Synapse 4", fpath
                                ))
            except Exception:
                pass

        return results

    # ── Bloody / A4Tech ───────────────────────────────────────────────
    def _scan_bloody(self) -> List[ScanResult]:
        """Scan Bloody/A4Tech Oscar Editor macro files (.amc, .mgn)."""
        results = []

        bloody_paths = [
            os.path.join(os.environ.get("PROGRAMFILES", ""), "Bloody7"),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Bloody7"),
            os.path.join(os.environ.get("PROGRAMFILES", ""), "A4Tech"),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "A4Tech"),
            os.path.join(os.environ.get("APPDATA", ""), "Bloody"),
            os.path.join(os.environ.get("APPDATA", ""), "Bloody7"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Bloody"),
            os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "Bloody"),
            os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "A4Tech"),
        ]

        macro_extensions = {'.amc', '.mgn', '.bmc', '.xml', '.json'}

        for base_path in bloody_paths:
            if not os.path.exists(base_path):
                continue
            try:
                for root, dirs, files in os.walk(base_path):
                    for fname in files:
                        ext = os.path.splitext(fname)[1].lower()
                        if ext in macro_extensions:
                            fpath = os.path.join(root, fname)
                            # .amc and .mgn files are binary but contain readable strings
                            try:
                                with open(fpath, 'rb') as f:
                                    data = f.read(1024 * 1024)  # Max 1MB
                                # Extract printable strings
                                strings = re.findall(rb'[\x20-\x7e]{4,}', data)
                                text = " ".join(s.decode('ascii', errors='replace') for s in strings)
                                if text:
                                    macro_results = self._analyze_macro_content(
                                        text, "Bloody/A4Tech", fpath
                                    )
                                    results.extend(macro_results)

                                # Check for rapid click patterns in binary data
                                results.extend(self._analyze_bloody_binary(data, fpath))
                            except Exception:
                                pass
            except Exception as e:
                logger.debug(f"Bloody scan error: {e}")

        return results

    def _analyze_bloody_binary(self, data: bytes, filepath: str) -> List[ScanResult]:
        """Analyze Bloody macro binary data for rapid-click patterns."""
        results = []
        # Bloody macros store delay values as 16-bit LE integers
        # Look for repeated very short delays
        short_delays = 0
        for i in range(0, len(data) - 2, 2):
            val = int.from_bytes(data[i:i+2], 'little')
            if 1 <= val <= SUSPICIOUS_DELAY_MS:
                short_delays += 1

        if short_delays >= 10:
            results.append(ScanResult(
                scanner="MouseMacroScanner",
                category="bloody_rapid_macro",
                name="Bloody Rapid Click Macro",
                description=f"[Bloody/A4Tech] Rapid-click macro detected ({short_delays} short delays found)",
                severity=90,
                filepath=filepath,
                evidence=f"{short_delays} delay values under {SUSPICIOUS_DELAY_MS}ms",
                details={"software": "Bloody/A4Tech", "short_delays": short_delays},
            ))

        return results

    # ── Corsair iCUE ──────────────────────────────────────────────────
    def _scan_corsair_icue(self) -> List[ScanResult]:
        """Scan Corsair iCUE macro profiles."""
        results = []
        icue_paths = [
            os.path.join(os.environ.get("APPDATA", ""), "Corsair", "CUE"),
            os.path.join(os.environ.get("APPDATA", ""), "Corsair", "CUE4"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Corsair", "CUE"),
        ]

        for base_path in icue_paths:
            if not os.path.exists(base_path):
                continue
            try:
                for root, dirs, files in os.walk(base_path):
                    for fname in files:
                        if fname.endswith(('.cueprofile', '.json', '.xml')):
                            fpath = os.path.join(root, fname)
                            content = safe_read_file(fpath)
                            if content:
                                results.extend(self._analyze_macro_content(
                                    content, "Corsair iCUE", fpath
                                ))
            except Exception as e:
                logger.debug(f"Corsair scan error: {e}")
        return results

    # ── SteelSeries GG ────────────────────────────────────────────────
    def _scan_steelseries(self) -> List[ScanResult]:
        """Scan SteelSeries GG/Engine macro profiles."""
        results = []
        ss_paths = [
            os.path.join(os.environ.get("PROGRAMDATA", ""), "SteelSeries", "GG"),
            os.path.join(os.environ.get("APPDATA", ""), "SteelSeries Engine 3"),
            os.path.join(os.environ.get("PROGRAMDATA", ""), "SteelSeries",
                         "SteelSeries Engine 3"),
        ]

        for base_path in ss_paths:
            if not os.path.exists(base_path):
                continue
            try:
                for root, dirs, files in os.walk(base_path):
                    for fname in files:
                        if fname.endswith(('.json', '.xml', '.config')):
                            fpath = os.path.join(root, fname)
                            content = safe_read_file(fpath)
                            if content:
                                results.extend(self._analyze_macro_content(
                                    content, "SteelSeries", fpath
                                ))
            except Exception as e:
                logger.debug(f"SteelSeries scan error: {e}")
        return results

    # ── Content Analysis (shared) ─────────────────────────────────────
    def _analyze_macro_content(self, content: str, software: str,
                                filepath: str) -> List[ScanResult]:
        """
        Analyze macro file content for suspicious PvP patterns.
        This is the CORE detection logic — checks WHAT the macro DOES,
        not just that the software exists.
        """
        results = []
        content_lower = content.lower()

        for pattern_name, pattern_info in SUSPICIOUS_MACRO_PATTERNS.items():
            matched = False
            match_evidence = ""

            # Check keyword indicators
            if "indicators" in pattern_info:
                for indicator in pattern_info["indicators"]:
                    if indicator.lower() in content_lower:
                        matched = True
                        # Extract context
                        idx = content_lower.find(indicator.lower())
                        start = max(0, idx - 50)
                        end = min(len(content), idx + len(indicator) + 50)
                        match_evidence = content[start:end].strip()
                        break

            # Check regex patterns
            if not matched and "patterns" in pattern_info:
                for regex in pattern_info["patterns"]:
                    match = re.search(regex, content, re.IGNORECASE)
                    if match:
                        matched = True
                        match_evidence = match.group(0)
                        break

            if matched:
                results.append(ScanResult(
                    scanner="MouseMacroScanner",
                    category=f"macro_{pattern_name}",
                    name=pattern_info["description"].split("(")[0].strip(),
                    description=f"[{software}] {pattern_info['description']}",
                    severity=pattern_info["severity"],
                    filepath=filepath,
                    evidence=match_evidence[:300],
                    details={"software": software, "pattern": pattern_name},
                ))

        # Check for very fast repeated actions (timing analysis)
        results.extend(self._check_timing_patterns(content, software, filepath))

        return results

    def _check_timing_patterns(self, content: str, software: str,
                                filepath: str) -> List[ScanResult]:
        """Check for inhuman timing patterns in macro data."""
        results = []

        # Find all delay/sleep values
        delay_patterns = [
            r'"delay"\s*:\s*(\d+)',           # JSON
            r'<[Dd]elay>\s*(\d+)\s*</[Dd]elay>',  # XML
            r'Sleep\s*\(\s*(\d+)\s*\)',       # Lua
            r'"interval"\s*:\s*(\d+)',         # JSON interval
            r'"wait"\s*:\s*(\d+)',             # JSON wait
            r'<[Ww]ait>\s*(\d+)\s*</[Ww]ait>',  # XML wait
        ]

        delays = []
        for pattern in delay_patterns:
            for match in re.finditer(pattern, content):
                try:
                    val = int(match.group(1))
                    if 0 < val < 5000:  # Reasonable range
                        delays.append(val)
                except ValueError:
                    pass

        if delays:
            avg_delay = sum(delays) / len(delays)
            min_delay = min(delays)
            inhuman_count = len([d for d in delays if d < SUSPICIOUS_DELAY_MS])

            if min_delay < INHUMAN_DELAY_MS and inhuman_count >= 3:
                results.append(ScanResult(
                    scanner="MouseMacroScanner",
                    category="inhuman_timing",
                    name="Inhuman Click Speed",
                    description=f"[{software}] Inhuman click timing detected: min {min_delay}ms, avg {avg_delay:.0f}ms ({inhuman_count} actions < {SUSPICIOUS_DELAY_MS}ms)",
                    severity=95,
                    filepath=filepath,
                    evidence=f"Delays: min={min_delay}ms, avg={avg_delay:.0f}ms, count={len(delays)}, inhuman={inhuman_count}",
                    details={"software": software, "min_delay": min_delay,
                             "avg_delay": round(avg_delay), "inhuman_count": inhuman_count},
                ))
            elif min_delay < SUSPICIOUS_DELAY_MS and inhuman_count >= 2:
                results.append(ScanResult(
                    scanner="MouseMacroScanner",
                    category="suspicious_timing",
                    name="Suspicious Click Speed",
                    description=f"[{software}] Suspicious click timing: min {min_delay}ms, avg {avg_delay:.0f}ms",
                    severity=75,
                    filepath=filepath,
                    evidence=f"Delays: min={min_delay}ms, avg={avg_delay:.0f}ms",
                    details={"software": software, "min_delay": min_delay,
                             "avg_delay": round(avg_delay)},
                ))

        return results

    def _analyze_xml_macros(self, content: str, software: str,
                            filepath: str) -> List[ScanResult]:
        """Parse XML macro files and analyze action sequences."""
        results = []
        try:
            root = ET.fromstring(content)

            # Count rapid click actions
            click_count = 0
            total_delay = 0
            action_count = 0

            for elem in root.iter():
                tag = elem.tag.lower() if elem.tag else ""
                text = (elem.text or "").lower()

                if "click" in tag or "mousebutton" in tag or "mouse" in tag:
                    click_count += 1
                    action_count += 1
                elif "delay" in tag or "wait" in tag or "sleep" in tag:
                    try:
                        val = int(elem.text or "0")
                        if 0 < val < 5000:
                            total_delay += val
                            action_count += 1
                    except ValueError:
                        pass

            if click_count >= 5 and action_count > 0:
                avg = total_delay / max(click_count, 1)
                if avg < SUSPICIOUS_DELAY_MS:
                    results.append(ScanResult(
                        scanner="MouseMacroScanner",
                        category="xml_rapid_macro",
                        name=f"{software} Rapid Click Macro",
                        description=f"[{software}] XML macro with {click_count} clicks, avg delay {avg:.0f}ms",
                        severity=90 if avg < INHUMAN_DELAY_MS else 75,
                        filepath=filepath,
                        evidence=f"{click_count} click actions, avg delay: {avg:.0f}ms",
                        details={"software": software, "click_count": click_count,
                                 "avg_delay": round(avg)},
                    ))

        except ET.ParseError:
            pass
        except Exception as e:
            logger.debug(f"XML macro parse error: {e}")

        return results

    def get_installed_mouse_software(self) -> List[Dict]:
        """Detect which mouse software is installed (informational only)."""
        software = []
        checks = {
            "Logitech G Hub": [
                os.path.join(os.environ.get("PROGRAMFILES", ""), "LGHUB"),
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "LGHUB"),
            ],
            "Razer Synapse": [
                os.path.join(os.environ.get("PROGRAMFILES", ""), "Razer", "Synapse3"),
                os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Razer", "Synapse3"),
                os.path.join("C:\\ProgramData", "Razer", "Synapse3"),
            ],
            "Razer Synapse 4": [
                os.path.join(os.environ.get("LOCALAPPDATA", ""), "Razer", "RazerAppEngine"),
            ],
            "Bloody 7": [
                os.path.join(os.environ.get("PROGRAMFILES", ""), "Bloody7"),
                os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Bloody7"),
            ],
            "A4Tech Oscar": [
                os.path.join(os.environ.get("PROGRAMFILES", ""), "A4Tech"),
                os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "A4Tech"),
            ],
            "Corsair iCUE": [
                os.path.join(os.environ.get("PROGRAMFILES", ""), "Corsair", "CORSAIR iCUE Software"),
                os.path.join(os.environ.get("APPDATA", ""), "Corsair", "CUE"),
            ],
            "SteelSeries GG": [
                os.path.join(os.environ.get("PROGRAMDATA", ""), "SteelSeries", "GG"),
                os.path.join(os.environ.get("PROGRAMFILES", ""), "SteelSeries", "GG"),
            ],
        }

        for name, paths in checks.items():
            for p in paths:
                if os.path.exists(p):
                    software.append({"name": name, "path": p, "installed": True})
                    break

        return software
