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
# Minecraft PvP macro typical delays: 20ms, 25ms, 30ms, 35ms
# Human click speed: ~70-170ms between clicks (6-14 CPS)
# Butterfly click: ~50-70ms (15-20 CPS)
# Anything below 50ms = macro territory
INHUMAN_DELAY_MS = 40       # < 40ms = definitely macro (covers 20, 25, 30, 35ms range)
SUSPICIOUS_DELAY_MS = 55    # < 55ms = very likely macro
FAST_DELAY_MS = 80          # < 80ms = suspicious for non-gaming mice


# ── Known standalone macro tools (.exe / .jar / .ahk) ─────────────────
# These are dedicated macro programs — the FILE ITSELF is the cheat.
# Different from mouse software macros (where only the content matters).
KNOWN_MACRO_TOOLS = {
    # === Premium/Paid macro clients ===
    "zenithmacros": {
        "display": "ZenithMacros",
        "desc_id": "Tool macro PvP premium (Crystal/Sword/Mace). 23+ modul + 7 individual macro CLI ($5 each). Fitur: Single Anchor, Safe Anchor, Shield Break, Triggerbot, Stun Slam, Pearl Catch, Breach Swap. Crystal Bundle ($8), Mace Bundle ($12). Jalan di background via CLI app — opsi terbaik untuk closet cheating.",
        "desc_en": "Premium PvP macro tool (Crystal/Sword/Mace). 23+ modules + 7 individual CLI macros ($5 each). Features: Single Anchor, Safe Anchor, Shield Break, Triggerbot, Stun Slam, Pearl Catch, Breach Swap. Crystal Bundle ($8), Mace Bundle ($12). Runs in background via CLI application — best option for closet cheating.",
        "severity": 100, "type": "macro_client", "source": "zenithmacros.store",
        "filenames": ["zenithmacros.exe", "zenith-macros.exe", "zenithmacro.exe", "zenith_macros.exe"],
    },
    "zenith_single_anchor": {
        "display": "ZenithMacro - Single Anchor",
        "desc_id": "Individual macro CLI dari ZenithMacros ($5). Otomasi single anchor placement + detonation. Jalan di background, closet cheating.",
        "desc_en": "Individual CLI macro from ZenithMacros ($5). Automates single anchor placement + detonation. Runs in background, closet cheating.",
        "severity": 100, "type": "individual_macro", "source": "zenithmacros.store",
        "filenames": ["single-anchor.exe", "singleanchor.exe", "single_anchor.exe"],
    },
    "zenith_safe_anchor": {
        "display": "ZenithMacro - Safe Anchor",
        "desc_id": "Individual macro CLI dari ZenithMacros ($5). Safe anchor placement dengan timing aman untuk avoid detection.",
        "desc_en": "Individual CLI macro from ZenithMacros ($5). Safe anchor placement with safe timing to avoid detection.",
        "severity": 100, "type": "individual_macro", "source": "zenithmacros.store",
        "filenames": ["safe-anchor.exe", "safeanchor.exe", "safe_anchor.exe"],
    },
    "zenith_shield_break": {
        "display": "ZenithMacro - Shield Break",
        "desc_id": "Individual macro CLI dari ZenithMacros ($5). Otomasi shield break lawan secara instan.",
        "desc_en": "Individual CLI macro from ZenithMacros ($5). Automates instant enemy shield breaking.",
        "severity": 100, "type": "individual_macro", "source": "zenithmacros.store",
        "filenames": ["shield-break.exe", "shieldbreak.exe", "shield_break.exe"],
    },
    "zenith_triggerbot": {
        "display": "ZenithMacro - Triggerbot",
        "desc_id": "Individual macro CLI dari ZenithMacros ($5). Triggerbot dengan pixel detection — auto-attack saat crosshair mengenai musuh.",
        "desc_en": "Individual CLI macro from ZenithMacros ($5). Triggerbot with pixel detection — auto-attacks when crosshair hits enemy.",
        "severity": 100, "type": "individual_macro", "source": "zenithmacros.store",
        "filenames": ["triggerbot.exe", "trigger-bot.exe", "trigger_bot.exe"],
    },
    "zenith_stun_slam": {
        "display": "ZenithMacro - Stun Slam",
        "desc_id": "Individual macro CLI dari ZenithMacros ($5). Otomasi Mace stun slam combo untuk PvP.",
        "desc_en": "Individual CLI macro from ZenithMacros ($5). Automates Mace stun slam combo for PvP.",
        "severity": 100, "type": "individual_macro", "source": "zenithmacros.store",
        "filenames": ["stun-slam.exe", "stunslam.exe", "stun_slam.exe"],
    },
    "zenith_pearl_catch": {
        "display": "ZenithMacro - Pearl Catch",
        "desc_id": "Individual macro CLI dari ZenithMacros ($5). Otomasi pearl catch untuk counter ender pearl lawan.",
        "desc_en": "Individual CLI macro from ZenithMacros ($5). Automates pearl catch to counter enemy ender pearls.",
        "severity": 100, "type": "individual_macro", "source": "zenithmacros.store",
        "filenames": ["pearl-catch.exe", "pearlcatch.exe", "pearl_catch.exe"],
    },
    "zenith_breach_swap": {
        "display": "ZenithMacro - Breach Swap",
        "desc_id": "Individual macro CLI dari ZenithMacros ($5). Otomasi breach swap — instant weapon/item swap saat breach.",
        "desc_en": "Individual CLI macro from ZenithMacros ($5). Automates breach swap — instant weapon/item swap during breach.",
        "severity": 100, "type": "individual_macro", "source": "zenithmacros.store",
        "filenames": ["breach-swap.exe", "breachswap.exe", "breach_swap.exe"],
    },
    "198macros": {
        "display": "198 Macros",
        "desc_id": "Tool macro Crystal/Sword/Mace PvP. Fitur: Hit Crystal, Single/Double Anchor, Anchor Pearl, Mace Attack, W-Tap, Sprint Reset.",
        "desc_en": "Crystal/Sword/Mace PvP macro tool. Features: Hit Crystal, Single/Double Anchor, Anchor Pearl, Mace Attack, W-Tap, Sprint Reset.",
        "severity": 100, "type": "macro_client", "source": "198macros.com",
        "filenames": ["198-macros.exe", "198macros.exe", "198m.exe", "198macros.jar", "198-macros.jar"],
    },
    "xenith": {
        "display": "Xenith Macro",
        "desc_id": "Tool macro PvP external (dulunya veyzyn.lol). Digunakan untuk Crystal PvP automation.",
        "desc_en": "External PvP macro tool (formerly veyzyn.lol). Used for Crystal PvP automation.",
        "severity": 100, "type": "macro_client", "source": "veyzyn.lol",
        "filenames": ["xenith.exe", "xenith-macro.exe", "xenithmacro.exe", "veyzyn.exe"],
    },
    "twiezmacro": {
        "display": "Twiez Macro",
        "desc_id": "Tool macro PvP open-source dari GitHub. Digunakan untuk Minecraft PvP automation.",
        "desc_en": "Open-source PvP macro tool from GitHub. Used for Minecraft PvP automation.",
        "severity": 100, "type": "macro_client", "source": "github.com/twiez",
        "filenames": ["twiez-macro.exe", "twiezmacro.exe", "twiez.exe"],
    },
    # === Auto-clickers ===
    "toadclicker": {
        "display": "ToadClicker",
        "desc_id": "Auto-clicker khusus Minecraft (C++). Fitur: left/right autoclicker, jitter, double-click, inventory click, click recording.",
        "desc_en": "Minecraft-specific auto-clicker (C++). Features: left/right autoclicker, jitter, double-click, inventory click, click recording.",
        "severity": 95, "type": "autoclicker", "source": "github.com/Steve987321",
        "filenames": ["toadclicker.exe", "toad-clicker.exe", "toad.exe"],
    },
    "chione": {
        "display": "Chione",
        "desc_id": "Auto-clicker + macro Python untuk Minecraft. Fitur: left/right click, auto-sprint, sprint reset, strafe, anti-AFK, self-destruct.",
        "desc_en": "Python auto-clicker + macro for Minecraft. Features: left/right click, auto-sprint, sprint reset, strafe, anti-AFK, self-destruct.",
        "severity": 95, "type": "autoclicker", "source": "github.com/LennardFe",
        "filenames": ["chione.exe", "chione-macro.exe"],
    },
    "opautoclicker": {
        "display": "OP Auto Clicker",
        "desc_id": "Auto-clicker populer yang sering dipakai untuk Minecraft PvP. Bisa set CPS sangat tinggi.",
        "desc_en": "Popular auto-clicker often used for Minecraft PvP. Can set very high CPS.",
        "severity": 90, "type": "autoclicker", "source": "opautoclicker.com",
        "filenames": ["op auto clicker.exe", "opautoclicker.exe", "op-auto-clicker.exe", "opautoclick.exe"],
    },
    "gsautoclicker": {
        "display": "GS Auto Clicker",
        "desc_id": "Auto-clicker dari Golden Software. Sering dipakai untuk Minecraft PvP dan farming.",
        "desc_en": "Auto-clicker by Golden Software. Often used for Minecraft PvP and farming.",
        "severity": 90, "type": "autoclicker", "source": "gs-auto-clicker.com",
        "filenames": ["gs auto clicker.exe", "gsautoclicker.exe", "gs-auto-clicker.exe"],
    },
    "fastautoclicker": {
        "display": "Fast Auto Clicker",
        "desc_id": "Auto-clicker kecepatan tinggi. Bisa mencapai 9999+ CPS.",
        "desc_en": "High-speed auto-clicker. Can reach 9999+ CPS.",
        "severity": 90, "type": "autoclicker", "source": "various",
        "filenames": ["fast auto clicker.exe", "fastautoclicker.exe", "fast-auto-clicker.exe",
                      "speed auto clicker.exe", "speedautoclicker.exe"],
    },
    "murgee": {
        "display": "Murgee Auto Clicker",
        "desc_id": "Auto-clicker profesional dari MurGee Software. Fitur lengkap untuk click automation.",
        "desc_en": "Professional auto-clicker by MurGee Software. Full click automation features.",
        "severity": 85, "type": "autoclicker", "source": "murgee.net",
        "filenames": ["murgee.exe", "auto clicker by murgee.exe", "murgee auto clicker.exe"],
    },
    # === Macro platforms ===
    "keyran": {
        "display": "Keyran",
        "desc_id": "Platform macro gaming. Tersedia 16+ macro Minecraft termasuk AutoCrystal, Anchor, AutoPearl.",
        "desc_en": "Gaming macro platform. 16+ Minecraft macros including AutoCrystal, Anchor, AutoPearl.",
        "severity": 85, "type": "macro_platform", "source": "keyran.net",
        "filenames": ["keyran.exe", "keyran setup.exe"],
    },
    "botmek": {
        "display": "BotMek",
        "desc_id": "Emulator keyboard & mouse untuk gaming. Tersedia macro Minecraft PvP (anchor, auto-build, auto-mine).",
        "desc_en": "Keyboard & mouse emulator for gaming. Minecraft PvP macros available (anchor, auto-build, auto-mine).",
        "severity": 85, "type": "macro_platform", "source": "botmek.com",
        "filenames": ["botmek.exe", "botmek setup.exe"],
    },
    # === AHK/Script-based ===
    "autohotkey_mc": {
        "display": "AutoHotkey (Minecraft Script)",
        "desc_id": "Script AutoHotkey untuk Minecraft. Bisa berisi autoclicker, crystal macro, butterfly click, dll.",
        "desc_en": "AutoHotkey script for Minecraft. May contain autoclicker, crystal macro, butterfly click, etc.",
        "severity": 80, "type": "ahk_script", "source": "various",
        "filenames": [],  # Detected by .ahk content scanning, not filename
    },
    # === Other tools ===
    "tinytask": {
        "display": "TinyTask",
        "desc_id": "Perekam & pemutar macro sederhana. Bisa merekam klik untuk Minecraft PvP.",
        "desc_en": "Simple macro recorder & player. Can record clicks for Minecraft PvP.",
        "severity": 80, "type": "macro_recorder", "source": "tinytask.net",
        "filenames": ["tinytask.exe", "tiny task.exe"],
    },
    "jitbit": {
        "display": "Jitbit Macro Recorder",
        "desc_id": "Perekam macro profesional. Sering dipakai untuk record klik PvP.",
        "desc_en": "Professional macro recorder. Often used to record PvP clicks.",
        "severity": 80, "type": "macro_recorder", "source": "jitbit.com",
        "filenames": ["jitbit.exe", "macro recorder.exe", "jitbit macro recorder.exe"],
    },
    "minecraftmacrotool": {
        "display": "MinecraftMacroTool",
        "desc_id": "Tool macro khusus Minecraft (Java). Bisa automate gerakan & aksi yang tidak mungkin dilakukan manusia.",
        "desc_en": "Minecraft-specific macro tool (Java). Can automate impossible human movements & actions.",
        "severity": 90, "type": "macro_tool", "source": "github.com/Kideneb",
        "filenames": ["minecraftmacrotool.jar", "minecraftmacrotool.exe", "mmt.jar"],
    },
    "clickcrystals": {
        "display": "ClickCrystals",
        "desc_id": "Mod Crystal PvP dengan 80+ modul built-in. Termasuk killaura, crystal placement, auto-pearl, rendering tools. Punya scripting language sendiri (CCS).",
        "desc_en": "Crystal PvP mod with 80+ built-in modules. Includes killaura, crystal placement, auto-pearl, rendering tools. Has own scripting language (CCS).",
        "severity": 85, "type": "mod_macro", "source": "clickcrystals.xyz",
        "filenames": ["clickcrystals.jar", "click-crystals.jar"],
    },
}


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
        """Scan all mouse software macro files + standalone macro tools."""
        results = []
        self.progress.start("Mouse Macro Scanner", 10)

        # ── Phase 1: Standalone macro tools (.exe/.jar downloaded from web or installed) ──
        self.progress.update("Scanning for standalone macro tools...")
        results.extend(self._scan_standalone_macro_tools())

        # ── Phase 2: Running macro processes ──
        self.progress.update("Checking running macro processes...")
        results.extend(self._scan_running_macro_processes())

        # ── Phase 3: AHK scripts on disk ──
        self.progress.update("Scanning AutoHotkey scripts...")
        results.extend(self._scan_ahk_scripts())

        # ── Phase 4: Mouse software macro content inspection ──
        self.progress.update("Scanning Logitech G Hub macros...")
        results.extend(self._scan_logitech_ghub())

        self.progress.update("Scanning Logitech Gaming Software...")
        results.extend(self._scan_logitech_lgs())

        self.progress.update("Scanning Razer Synapse macros...")
        results.extend(self._scan_razer_synapse())

        self.progress.update("Scanning Bloody/A4Tech macros...")
        results.extend(self._scan_bloody())

        self.progress.update("Scanning Corsair iCUE macros...")
        results.extend(self._scan_corsair_icue())

        self.progress.update("Scanning SteelSeries macros...")
        results.extend(self._scan_steelseries())

        # ── Phase 5: Deep binary scan of mouse software install dirs ──
        self.progress.update("Deep binary scan of mouse software...")
        for sw in self.get_installed_software():
            if sw.get("installed") and sw.get("path"):
                results.extend(self._scan_binary_files(sw["path"], sw["name"]))

        return results

    # ── Standalone Macro Tool Detection ────────────────────────────────
    def _scan_standalone_macro_tools(self) -> List[ScanResult]:
        """
        Scan common download/install locations for known macro .exe/.jar files.
        These are standalone tools — the FILE ITSELF is the cheat.
        """
        results = []

        # Common locations where macro tools are downloaded/installed
        scan_dirs = []
        home = os.environ.get("USERPROFILE", str(Path.home()))
        for env_dir in [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents"),
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
            os.path.join(home, "AppData", "Local", "Temp"),
            os.environ.get("PROGRAMFILES", ""),
            os.environ.get("PROGRAMFILES(X86)", ""),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs"),
            os.path.join(home, ".minecraft"),  # Some tools placed here
        ]:
            if env_dir and os.path.exists(env_dir):
                scan_dirs.append(env_dir)

        # Build lookup: filename -> tool info
        filename_lookup = {}
        for tool_key, tool_info in KNOWN_MACRO_TOOLS.items():
            for fname in tool_info.get("filenames", []):
                filename_lookup[fname.lower()] = (tool_key, tool_info)

        for scan_dir in scan_dirs:
            try:
                # Scan top level + 1 level deep (not recursive to avoid slowness)
                items_to_check = []
                try:
                    for item in os.listdir(scan_dir):
                        items_to_check.append(os.path.join(scan_dir, item))
                        # 1 level deep
                        subpath = os.path.join(scan_dir, item)
                        if os.path.isdir(subpath):
                            try:
                                for subitem in os.listdir(subpath):
                                    items_to_check.append(os.path.join(subpath, subitem))
                            except (PermissionError, OSError):
                                pass
                except (PermissionError, OSError):
                    continue

                for fpath in items_to_check:
                    if not os.path.isfile(fpath):
                        continue
                    fname = os.path.basename(fpath).lower()

                    # Check exact filename match
                    if fname in filename_lookup:
                        tool_key, tool_info = filename_lookup[fname]
                        results.append(self._make_tool_finding(tool_info, fpath))
                        continue

                    # Check partial match (tool name in filename)
                    for tool_key, tool_info in KNOWN_MACRO_TOOLS.items():
                        tool_name_lower = tool_info["display"].lower().replace(" ", "")
                        if (tool_name_lower in fname.replace(" ", "").replace("-", "").replace("_", "")
                                and fname.endswith(('.exe', '.jar'))):
                            results.append(self._make_tool_finding(tool_info, fpath))
                            break

            except Exception as e:
                logger.debug(f"Standalone scan error in {scan_dir}: {e}")

        return results

    def _make_tool_finding(self, tool_info: dict, filepath: str) -> ScanResult:
        """Create a detailed finding for a standalone macro tool."""
        display = tool_info["display"]
        desc_id = tool_info["desc_id"]
        desc_en = tool_info["desc_en"]
        source = tool_info.get("source", "unknown")
        tool_type = tool_info.get("type", "macro_tool")

        # Get file info
        try:
            fsize = os.path.getsize(filepath)
            from core.utils import format_size
            size_str = format_size(fsize)
        except Exception:
            size_str = "unknown"

        # Build detailed keterangan
        keterangan = (
            f"\n"
            f"═══ MACRO TOOL TERDETEKSI ═══\n"
            f"Nama: {display}\n"
            f"Tipe: {tool_type}\n"
            f"File: {os.path.basename(filepath)}\n"
            f"Ukuran: {size_str}\n"
            f"Lokasi: {filepath}\n"
            f"Sumber: {source}\n"
            f"\n"
            f"[ID] {desc_id}\n"
            f"[EN] {desc_en}\n"
            f"\n"
            f"⚠ File ini adalah tool macro yang berdiri sendiri (standalone).\n"
            f"  Keberadaan file ini di PC sudah cukup sebagai bukti.\n"
        )

        return ScanResult(
            scanner="MouseMacroScanner",
            category=f"standalone_{tool_type}",
            name=f"{display} ({os.path.basename(filepath)})",
            description=f"[Standalone Macro] {display} ditemukan di {filepath}",
            severity=tool_info.get("severity", 90),
            filepath=filepath,
            evidence=keterangan,
            details={
                "tool_name": display,
                "tool_type": tool_type,
                "source": source,
                "desc_id": desc_id,
                "desc_en": desc_en,
                "file_size": size_str,
            },
        )

    # ── Running Process Detection ─────────────────────────────────────
    def _scan_running_macro_processes(self) -> List[ScanResult]:
        """Check if any known macro tools are currently running."""
        results = []
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pname = (proc.info.get('name') or '').lower()
                    pexe = (proc.info.get('exe') or '').lower()
                    pid = proc.info.get('pid', 0)

                    for tool_key, tool_info in KNOWN_MACRO_TOOLS.items():
                        for fname in tool_info.get("filenames", []):
                            fname_stem = fname.lower().replace('.exe', '').replace('.jar', '')
                            if fname_stem in pname or (pexe and fname.lower() in pexe):
                                display = tool_info["display"]
                                desc_id = tool_info["desc_id"]

                                keterangan = (
                                    f"\n"
                                    f"═══ MACRO TOOL SEDANG BERJALAN ═══\n"
                                    f"Nama: {display}\n"
                                    f"Proses: {proc.info.get('name', '')}\n"
                                    f"PID: {pid}\n"
                                    f"Path: {proc.info.get('exe', '')}\n"
                                    f"\n"
                                    f"[ID] {desc_id}\n"
                                    f"\n"
                                    f"⚠ Tool macro ini AKTIF BERJALAN saat screenshare!\n"
                                    f"  Ini bukti kuat bahwa player menggunakan macro.\n"
                                )

                                results.append(ScanResult(
                                    scanner="MouseMacroScanner",
                                    category="running_macro_process",
                                    name=f"{display} (RUNNING - PID:{pid})",
                                    description=f"[RUNNING] {display} sedang berjalan (PID: {pid})",
                                    severity=min(tool_info.get("severity", 95) + 5, 100),
                                    filepath=proc.info.get('exe', ''),
                                    evidence=keterangan,
                                    details={
                                        "tool_name": display,
                                        "pid": pid,
                                        "process_name": proc.info.get('name', ''),
                                        "desc_id": desc_id,
                                    },
                                ))
                                break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Running process scan error: {e}")
        return results

    # ── AHK Script Detection ──────────────────────────────────────────
    def _scan_ahk_scripts(self) -> List[ScanResult]:
        """Scan for AutoHotkey .ahk scripts related to Minecraft."""
        results = []
        home = os.environ.get("USERPROFILE", str(Path.home()))
        search_dirs = [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Documents", "AutoHotkey"),
            os.path.join(home, "Documents", "AHK"),
            os.environ.get("TEMP", ""),
        ]

        # Keywords that indicate Minecraft PvP macro in AHK content
        mc_ahk_indicators = [
            "minecraft", "mc_macro", "pvp", "crystal", "anchor",
            "autoclicker", "auto_click", "butterfly", "jitter",
            "wtap", "w_tap", "sprint_reset", "combo",
            "Send {LButton", "Send {RButton", "Click",
            "DllCall.*mouse_event",  # Direct mouse input
            "SetKeyDelay", "SetMouseDelay",
        ]

        for search_dir in search_dirs:
            if not search_dir or not os.path.exists(search_dir):
                continue
            try:
                for item in os.listdir(search_dir):
                    if not item.lower().endswith('.ahk'):
                        continue
                    fpath = os.path.join(search_dir, item)
                    if not os.path.isfile(fpath):
                        continue

                    try:
                        content = safe_read_file(fpath)
                        if not content:
                            continue
                        content_lower = content.lower()

                        # Check if this AHK script is Minecraft-related
                        mc_related = any(ind.lower() in content_lower for ind in mc_ahk_indicators)
                        if not mc_related:
                            continue  # Skip non-Minecraft AHK scripts (NO false flag)

                        # Analyze the AHK script content
                        findings = []

                        # Detect autoclicker pattern
                        if re.search(r'(Send\s*\{[LR]Button|Click|mouse_event)', content, re.IGNORECASE):
                            if re.search(r'(Loop|While|Sleep\s*\d)', content, re.IGNORECASE):
                                delay_match = re.search(r'Sleep[,\s]+?(\d+)', content)
                                delay = int(delay_match.group(1)) if delay_match else 0
                                cps = round(1000 / max(delay, 1)) if delay > 0 else 0
                                findings.append(('autoclicker', delay, cps))

                        # Detect crystal/anchor macro
                        if any(k in content_lower for k in ['crystal', 'obsidian', 'anchor', 'glowstone', 'endcrystal']):
                            findings.append(('crystal_pvp', 0, 0))

                        # Detect butterfly/jitter
                        if any(k in content_lower for k in ['butterfly', 'jitter', 'drag_click', 'double_click']):
                            findings.append(('butterfly', 0, 0))

                        # Detect W-tap
                        if any(k in content_lower for k in ['wtap', 'w_tap', 'sprint_reset', 'combo_tap']):
                            findings.append(('wtap', 0, 0))

                        for finding_type, delay, cps in findings:
                            keterangan = self._build_ahk_keterangan(
                                item, fpath, finding_type, delay, cps, content[:500]
                            )
                            sev = 95 if finding_type == 'autoclicker' and delay < 50 else 85

                            results.append(ScanResult(
                                scanner="MouseMacroScanner",
                                category=f"ahk_{finding_type}",
                                name=f"AHK Script: {item} ({finding_type})",
                                description=f"[AutoHotkey] Minecraft {finding_type} script: {item}",
                                severity=sev,
                                filepath=fpath,
                                evidence=keterangan,
                                details={
                                    "script_name": item,
                                    "finding_type": finding_type,
                                    "delay_ms": delay,
                                    "estimated_cps": cps,
                                },
                            ))

                    except Exception:
                        pass
            except (PermissionError, OSError):
                pass

        return results

    def _build_ahk_keterangan(self, filename: str, filepath: str,
                               finding_type: str, delay: int, cps: int,
                               snippet: str) -> str:
        """Build detailed keterangan for AHK script finding."""
        type_names = {
            'autoclicker': 'Auto-Clicker',
            'crystal_pvp': 'Crystal PvP Macro',
            'butterfly': 'Butterfly Click',
            'wtap': 'W-Tap Combo Macro',
        }
        type_descs_id = {
            'autoclicker': 'Script yang mengklik otomatis dengan kecepatan tinggi.',
            'crystal_pvp': 'Script yang mengotomasi penempatan & peledakan crystal/anchor.',
            'butterfly': 'Script yang mensimulasi butterfly click untuk CPS tinggi.',
            'wtap': 'Script yang mengotomasi W-Tap untuk combo PvP.',
        }

        keterangan = (
            f"\n"
            f"═══ AHK SCRIPT TERDETEKSI ═══\n"
            f"File: {filename}\n"
            f"Lokasi: {filepath}\n"
            f"Tipe: {type_names.get(finding_type, finding_type)}\n"
        )
        if delay > 0:
            keterangan += f"Delay: {delay}ms\n"
        if cps > 0:
            keterangan += f"Estimasi CPS: ~{cps} clicks/second\n"
        if cps > 20:
            keterangan += f"⚠ CPS {cps} JAUH MELEBIHI kemampuan manusia (max ~20 CPS)\n"
        keterangan += (
            f"\n"
            f"Deskripsi: {type_descs_id.get(finding_type, '')}\n"
            f"\n"
            f"Cuplikan script:\n"
            f"{snippet[:300]}\n"
        )
        return keterangan

    # ── Logitech G Hub ────────────────────────────────────────────────
    def _scan_logitech_ghub(self) -> List[ScanResult]:
        """Scan Logitech G Hub settings.db, Lua scripts, and web-downloaded macros."""
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

        # Scan Lua scripts in G Hub directory
        lua_dirs = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "LGHUB"),
            os.path.join(os.environ.get("APPDATA", ""), "LGHUB"),
        ]
        for lua_dir in lua_dirs:
            if os.path.exists(lua_dir):
                results.extend(self._scan_lua_scripts(lua_dir))

        # Scan web-downloaded Lua macros from common download locations
        # People download .lua scripts from logitechmacro.com, GitHub, etc.
        # and either run them directly or import into G Hub
        results.extend(self._scan_web_downloaded_lua_macros())

        return results

    def _scan_web_downloaded_lua_macros(self) -> List[ScanResult]:
        """Scan Downloads/Desktop/Documents for Lua macro scripts from the web.
        Only flags Minecraft/gaming-related Lua scripts, not general Lua files."""
        results = []
        home = os.environ.get("USERPROFILE", str(Path.home()))
        search_dirs = [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Documents", "Logitech"),
            os.path.join(home, "Documents", "LGHUB"),
        ]

        # Indicators that a .lua file is a gaming/Minecraft macro
        gaming_lua_indicators = [
            # Logitech G Hub API functions
            "PressMouseButton", "ReleaseMouseButton", "PressAndReleaseMouseButton",
            "EnablePrimaryMouseButtonEvents", "IsMouseButtonPressed",
            "OnEvent", "MOUSE_BUTTON_PRESSED", "MOUSE_BUTTON_RELEASED",
            "PressKey", "ReleaseKey", "PressAndReleaseKey",
            # Gaming/Minecraft indicators
            "minecraft", "pvp", "crystal", "anchor", "autoclicker",
            "auto_click", "recoil", "no_recoil", "rapid_fire",
            "macro", "gaming",
        ]

        for search_dir in search_dirs:
            if not search_dir or not os.path.exists(search_dir):
                continue
            try:
                for item in os.listdir(search_dir):
                    if not item.lower().endswith('.lua'):
                        continue
                    fpath = os.path.join(search_dir, item)
                    if not os.path.isfile(fpath):
                        continue
                    try:
                        content = safe_read_file(fpath)
                        if not content or len(content) < 20:
                            continue
                        # Check if this Lua file is a gaming macro
                        is_gaming = any(ind in content for ind in gaming_lua_indicators)
                        if not is_gaming:
                            continue  # Skip non-gaming Lua files

                        # It's a gaming Lua macro — analyze it
                        lua_results = self._analyze_lua_macro(content, fpath)
                        if lua_results:
                            for r in lua_results:
                                r.description = f"[Web-Downloaded Lua Macro] {r.description}"
                                r.evidence = (
                                    f"\n═══ LUA MACRO DARI WEB TERDETEKSI ═══\n"
                                    f"File: {item}\n"
                                    f"Lokasi: {fpath}\n"
                                    f"\n"
                                    f"File .lua ini kemungkinan didownload dari web\n"
                                    f"(logitechmacro.com, GitHub, forum, dll) dan\n"
                                    f"digunakan di Logitech G Hub sebagai macro gaming.\n"
                                    f"\n" + r.evidence
                                )
                            results.extend(lua_results)
                        else:
                            # Even without specific pattern, a G Hub Lua macro
                            # in Downloads with gaming indicators is suspicious
                            has_ghub_api = any(api in content for api in [
                                "PressMouseButton", "PressAndReleaseMouseButton",
                                "EnablePrimaryMouseButtonEvents", "OnEvent",
                            ])
                            if has_ghub_api:
                                keterangan = (
                                    f"\n═══ LUA MACRO G HUB DARI WEB ═══\n"
                                    f"File: {item}\n"
                                    f"Lokasi: {fpath}\n"
                                    f"\n"
                                    f"File ini menggunakan Logitech G Hub Lua API\n"
                                    f"dan ditemukan di folder Downloads/Desktop.\n"
                                    f"Kemungkinan didownload dari web untuk cheat.\n"
                                    f"\n"
                                    f"Cuplikan:\n{content[:300]}\n"
                                )
                                results.append(ScanResult(
                                    scanner="MouseMacroScanner",
                                    category="web_lua_macro",
                                    name=f"Web Lua Macro: {item}",
                                    description=f"[Web Lua] Logitech G Hub macro script dari web: {item}",
                                    severity=75,
                                    filepath=fpath,
                                    evidence=keterangan,
                                    details={"software": "Logitech G Hub (web)", "filename": item},
                                ))
                    except Exception:
                        pass
            except (PermissionError, OSError):
                pass

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
                # Build detailed keterangan
                keterangan = (
                    f"\n"
                    f"═══ MACRO CONTENT TERDETEKSI ═══\n"
                    f"Software: {software}\n"
                    f"Pattern: {pattern_name}\n"
                    f"Deskripsi: {pattern_info['description']}\n"
                    f"File: {os.path.basename(filepath)}\n"
                    f"\n"
                    f"Bukti yang ditemukan:\n"
                    f"  {match_evidence[:300]}\n"
                    f"\n"
                    f"⚠ Ini menunjukkan macro yang secara spesifik dibuat untuk\n"
                    f"  keuntungan PvP di Minecraft (bukan konfigurasi normal).\n"
                )

                results.append(ScanResult(
                    scanner="MouseMacroScanner",
                    category=f"macro_{pattern_name}",
                    name=pattern_info["description"].split("(")[0].strip(),
                    description=f"[{software}] {pattern_info['description']}",
                    severity=pattern_info["severity"],
                    filepath=filepath,
                    evidence=keterangan,
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
                est_cps = round(1000 / max(avg_delay, 1))
                keterangan = (
                    f"\n"
                    f"═══ KECEPATAN KLIK TIDAK MANUSIAWI ═══\n"
                    f"Software: {software}\n"
                    f"File: {os.path.basename(filepath)}\n"
                    f"\n"
                    f"Analisis Delay:\n"
                    f"  Delay minimum: {min_delay}ms\n"
                    f"  Delay rata-rata: {avg_delay:.0f}ms\n"
                    f"  Total aksi: {len(delays)}\n"
                    f"  Aksi < {SUSPICIOUS_DELAY_MS}ms: {inhuman_count}\n"
                    f"\n"
                    f"Estimasi CPS: ~{est_cps} clicks/second\n"
                    f"\n"
                    f"⚠ Perbandingan kecepatan klik:\n"
                    f"  Manusia normal     : 70-170ms (6-14 CPS)\n"
                    f"  Butterfly click    : 50-70ms  (15-20 CPS)\n"
                    f"  Jitter click       : 50-65ms  (15-20 CPS)\n"
                    f"  ─────────────────────────────────────\n"
                    f"  Macro Logitech khas: 20-35ms  (28-50 CPS) ← BUKAN MANUSIA\n"
                    f"  Delay ditemukan    : {min_delay}ms = ~{round(1000/max(min_delay,1))} CPS\n"
                    f"\n"
                    f"  Delay 20-35ms adalah range KHAS macro Logitech/Razer\n"
                    f"  untuk Minecraft PvP (crystal swap, autoclicker, anchor).\n"
                    f"  Delay di bawah 40ms TIDAK MUNGKIN dilakukan tangan manusia.\n"
                    f"  Ini BUKTI KUAT penggunaan macro.\n"
                )
                results.append(ScanResult(
                    scanner="MouseMacroScanner",
                    category="inhuman_timing",
                    name="Inhuman Click Speed",
                    description=f"[{software}] Kecepatan klik tidak manusiawi: {min_delay}ms (~{est_cps} CPS)",
                    severity=95,
                    filepath=filepath,
                    evidence=keterangan,
                    details={"software": software, "min_delay": min_delay,
                             "avg_delay": round(avg_delay), "inhuman_count": inhuman_count,
                             "estimated_cps": est_cps},
                ))
            elif min_delay < SUSPICIOUS_DELAY_MS and inhuman_count >= 2:
                est_cps = round(1000 / max(avg_delay, 1))
                # Check if delay falls in typical Logitech macro range (20-35ms)
                in_logitech_range = 15 <= min_delay <= 40
                sev = 90 if in_logitech_range else 75
                keterangan = (
                    f"\n"
                    f"═══ KECEPATAN KLIK MENCURIGAKAN ═══\n"
                    f"Software: {software}\n"
                    f"File: {os.path.basename(filepath)}\n"
                    f"\n"
                    f"Analisis Delay:\n"
                    f"  Delay minimum: {min_delay}ms (~{round(1000/max(min_delay,1))} CPS)\n"
                    f"  Delay rata-rata: {avg_delay:.0f}ms (~{est_cps} CPS)\n"
                    f"  Aksi cepat (< {SUSPICIOUS_DELAY_MS}ms): {inhuman_count}\n"
                    f"\n"
                )
                if in_logitech_range:
                    keterangan += (
                        f"⚠ Delay {min_delay}ms MASUK RANGE KHAS macro Logitech/Razer:\n"
                        f"  20ms, 25ms, 30ms, 35ms → delay yang umum di-set\n"
                        f"  di macro Logitech G Hub / Razer Synapse untuk\n"
                        f"  Minecraft Crystal PvP, autoclicker, dan anchor macro.\n"
                        f"\n"
                        f"  Manusia normal: 70-170ms (6-14 CPS)\n"
                        f"  Delay {min_delay}ms = {round(1000/max(min_delay,1))} CPS → PASTI MACRO\n"
                    )
                else:
                    keterangan += (
                        f"  Delay ini lebih cepat dari kemampuan manusia normal.\n"
                        f"  Perlu investigasi lebih lanjut.\n"
                    )
                results.append(ScanResult(
                    scanner="MouseMacroScanner",
                    category="suspicious_timing",
                    name="Suspicious Click Speed",
                    description=f"[{software}] Kecepatan klik mencurigakan: {min_delay}ms (~{est_cps} CPS)",
                    severity=sev,
                    filepath=filepath,
                    evidence=keterangan,
                    details={"software": software, "min_delay": min_delay,
                             "avg_delay": round(avg_delay), "estimated_cps": est_cps},
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

    def _scan_binary_files(self, install_path: str, software_name: str) -> List[ScanResult]:
        """Deep binary scan of mouse software .exe and .dll files for embedded cheat strings.
        This scans the actual binaries of mouse software for hidden macro/autoclicker code
        that wouldn't appear in config files.
        """
        results = []
        if not os.path.isdir(install_path):
            return results

        cheat_binary_strings = [
            (b"autoclicker", 90, "AutoClicker code embedded in binary"),
            (b"auto_click", 90, "Auto-click function in binary"),
            (b"mouse_replay", 80, "Mouse replay/record function"),
            (b"rapid_fire", 95, "Rapid fire macro in binary"),
            (b"jitter_click", 85, "Jitter click simulation"),
            (b"butterfly_click", 85, "Butterfly click macro"),
            (b"drag_click", 80, "Drag click macro"),
            (b"minecraft", 40, "Minecraft-specific targeting"),
            (b"killaura", 100, "KillAura cheat reference"),
            (b"aimassist", 95, "Aim assist reference"),
            (b"triggerbot", 95, "Triggerbot reference"),
        ]

        try:
            for root, dirs, files in os.walk(install_path):
                # Limit depth to 3
                depth = root[len(install_path):].count(os.sep)
                if depth > 3:
                    continue
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in ('.exe', '.dll'):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        fsize = os.path.getsize(fpath)
                        if fsize > 50 * 1024 * 1024:  # Skip >50MB
                            continue
                        with open(fpath, 'rb') as f:
                            data = f.read()
                        data_lower = data.lower()
                        for pattern, severity, desc in cheat_binary_strings:
                            if pattern in data_lower:
                                # Skip low-severity matches for known safe software
                                if severity < 80 and software_name in (
                                    "Logitech G Hub", "Razer Synapse", "Corsair iCUE",
                                    "SteelSeries GG"
                                ):
                                    continue
                                results.append(ScanResult(
                                    scanner="MouseMacroScanner",
                                    category="binary_cheat_string",
                                    name=f"{software_name}: {fname}",
                                    description=f"Suspicious string in {software_name} binary: {desc}",
                                    severity=severity,
                                    filepath=fpath,
                                    evidence=f"Pattern: {pattern.decode('ascii', errors='replace')} in {fname}",
                                    details={"software": software_name},
                                ))
                                break  # One finding per file
                    except (PermissionError, OSError):
                        pass
        except Exception as e:
            logger.debug(f"Binary scan error for {software_name}: {e}")

        return results
