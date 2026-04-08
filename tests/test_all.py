#!/usr/bin/env python3
"""
SS-Tools Ultimate - Comprehensive Test Suite
Tests all core modules, database, keyword detection, bytecode analysis, and report generation.
"""
import os
import sys
import json
import time
import struct
import zipfile
import tempfile
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0
ERRORS = []

def test(name, condition, detail=""):
    global PASS, FAIL, ERRORS
    if condition:
        PASS += 1
        print(f"  ✅ {name}")
    else:
        FAIL += 1
        msg = f"  ❌ {name}" + (f" — {detail}" if detail else "")
        print(msg)
        ERRORS.append(msg)

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ══════════════════════════════════════════════════════════════
# TEST 1: Core Imports
# ══════════════════════════════════════════════════════════════
section("TEST 1: Core Imports")

try:
    from core.config import AppSettings, APP_NAME, APP_VERSION, MINECRAFT_LAUNCHER_PATHS, MINECRAFT_SCAN_DIRS
    test("Import core.config", True)
except Exception as e:
    test("Import core.config", False, str(e))

try:
    from core.utils import (ScanResult, ScanProgress, severity_label, severity_color,
                            format_size, format_duration, file_hash_md5, file_hash_sha256,
                            safe_read_file, parallel_execute)
    test("Import core.utils", True)
except Exception as e:
    test("Import core.utils", False, str(e))

try:
    from core.database import CheatDatabase
    test("Import core.database", True)
except Exception as e:
    test("Import core.database", False, str(e))

try:
    from core.keyword_detector import KeywordDetector
    test("Import core.keyword_detector", True)
except Exception as e:
    test("Import core.keyword_detector", False, str(e))

try:
    from core.minecraft_scanner import MinecraftScanner
    test("Import core.minecraft_scanner", True)
except Exception as e:
    test("Import core.minecraft_scanner", False, str(e))

try:
    from core.mods_scanner import ModsScanner, ModScanResult, BytecodeAnalyzer, JAVA_CLASS_MAGIC
    test("Import core.mods_scanner", True)
except Exception as e:
    test("Import core.mods_scanner", False, str(e))

try:
    from core.kernel_check import KernelCheck
    test("Import core.kernel_check", True)
except Exception as e:
    test("Import core.kernel_check", False, str(e))

try:
    from core.process_scanner import ProcessScanner
    test("Import core.process_scanner", True)
except Exception as e:
    test("Import core.process_scanner", False, str(e))

try:
    from core.string_deleted_scanner import StringDeletedScanner
    test("Import core.string_deleted_scanner", True)
except Exception as e:
    test("Import core.string_deleted_scanner", False, str(e))

try:
    from core.browser_scanner import BrowserScanner
    test("Import core.browser_scanner", True)
except Exception as e:
    test("Import core.browser_scanner", False, str(e))

try:
    from core.deleted_file_detector import DeletedFileDetector
    test("Import core.deleted_file_detector", True)
except Exception as e:
    test("Import core.deleted_file_detector", False, str(e))

try:
    from core.memory_scanner import MemoryScanner
    test("Import core.memory_scanner", True)
except Exception as e:
    test("Import core.memory_scanner", False, str(e))

try:
    from core.network_scanner import NetworkScanner
    test("Import core.network_scanner", True)
except Exception as e:
    test("Import core.network_scanner", False, str(e))

try:
    from core.evidence_collector import EvidenceCollector, ReportGenerator
    test("Import core.evidence_collector", True)
except Exception as e:
    test("Import core.evidence_collector", False, str(e))

try:
    from gui.i18n import I18n, TRANSLATIONS
    test("Import gui.i18n", True)
except Exception as e:
    test("Import gui.i18n", False, str(e))

try:
    from gui.styles import DARK_STYLESHEET
    test("Import gui.styles", True)
except Exception as e:
    test("Import gui.styles", False, str(e))


# ══════════════════════════════════════════════════════════════
# TEST 2: Database Loading & Validation
# ══════════════════════════════════════════════════════════════
section("TEST 2: Database Loading & Validation")

db = CheatDatabase()
test("Database loaded", db.data is not None and len(db.data) > 0)
test("Database version exists", db.version != "0.0.0", f"Got: {db.version}")
test(f"Version = {db.version}", db.version == "3.0.0")

test(f"Cheat clients: {len(db.cheat_clients)}", len(db.cheat_clients) >= 40)
test(f"Cheat modules: {len(db.cheat_modules)}", len(db.cheat_modules) >= 50)
test(f"Suspicious methods: {len(db.suspicious_methods)}", len(db.suspicious_methods) >= 30)
test(f"Suspicious imports: {len(db.suspicious_imports)}", len(db.suspicious_imports) >= 20)
test(f"Suspicious strings: {len(db.suspicious_strings)}", len(db.suspicious_strings) >= 30)
test(f"Cheat files: {len(db.cheat_files)}", len(db.cheat_files) >= 20)
test(f"Cheat URLs: {len(db.cheat_urls)}", len(db.cheat_urls) >= 20)
test(f"Cheat developers: {len(db.cheat_developers)}", len(db.cheat_developers) >= 10)
test(f"Obfuscation patterns: {len(db.obfuscation_patterns)}", len(db.obfuscation_patterns) >= 10)
test(f"Bytecode signatures: {len(db.bytecode_signatures)}", len(db.bytecode_signatures) >= 10)
test(f"Kernel driver sigs: {len(db.kernel_driver_signatures)}", len(db.kernel_driver_signatures) >= 30)
test(f"Suspicious processes: {len(db.suspicious_processes)}", len(db.suspicious_processes) >= 30)
test(f"Whitelist mods: {len(db.whitelist_mods)}", len(db.whitelist_mods) >= 80)
test(f"Whitelist processes: {len(db.whitelist_processes)}", len(db.whitelist_processes) >= 40)

total = (len(db.cheat_clients) + len(db.cheat_modules) + len(db.suspicious_methods) +
         len(db.suspicious_imports) + len(db.suspicious_strings) + len(db.cheat_files) +
         len(db.cheat_urls) + len(db.cheat_developers) + len(db.obfuscation_patterns) +
         len(db.bytecode_signatures) + len(db.kernel_driver_signatures) + len(db.suspicious_processes))
test(f"Total detection entries: {total} >= 300", total >= 300)

# Test singleton pattern
db2 = CheatDatabase()
test("Database is singleton", db is db2)

# Test keyword list generation
keywords = db.get_all_keywords()
test(f"get_all_keywords() returns {len(keywords)} keywords", len(keywords) >= 200)

# Test whitelist functions
test("sodium is whitelisted", db.is_mod_whitelisted("sodium"))
test("optifine is whitelisted", db.is_mod_whitelisted("optifine"))
test("fabric-api is whitelisted", db.is_mod_whitelisted("fabric-api"))
test("iris is whitelisted", db.is_mod_whitelisted("iris-shaders"))
test("wurst NOT whitelisted", not db.is_mod_whitelisted("wurst"))
test("impact NOT whitelisted", not db.is_mod_whitelisted("impact"))

test("java.exe is whitelisted process", db.is_process_whitelisted("java.exe"))
test("explorer.exe is whitelisted process", db.is_process_whitelisted("explorer.exe"))
test("cheatengine NOT whitelisted", not db.is_process_whitelisted("cheatengine"))

# Validate JSON structure integrity
for client in db.cheat_clients:
    assert "name" in client, f"Client missing 'name': {client}"
    assert "severity" in client, f"Client missing 'severity': {client}"
for module in db.cheat_modules:
    assert "name" in module, f"Module missing 'name': {module}"
    assert "category" in module, f"Module missing 'category': {module}"
test("All DB entries have required fields", True)


# ══════════════════════════════════════════════════════════════
# TEST 3: Keyword Detector - All Matching Modes
# ══════════════════════════════════════════════════════════════
section("TEST 3: Keyword Detector - All Matching Modes")

detector = KeywordDetector()
test("KeywordDetector instantiated", detector is not None)
test(f"Compiled {len(detector._compiled_patterns)} regex patterns", len(detector._compiled_patterns) >= 40)

# 3a. Exact keyword matching - cheat clients
results = detector.scan_text("I downloaded wurst client yesterday")
wurst_found = any(r.name == "Wurst" for r in results)
test("Exact match: 'wurst' detected", wurst_found)

results = detector.scan_text("player was using impact client on the server")
impact_found = any(r.name == "Impact" for r in results)
test("Exact match: 'impact' detected", impact_found)

results = detector.scan_text("meteorclient is a fabric cheat")
meteor_found = any(r.name == "Meteor" for r in results)
test("Alias match: 'meteorclient' -> Meteor", meteor_found)

results = detector.scan_text("liquidbounce+ with killaura module")
lb_found = any(r.name == "LiquidBounce" for r in results)
test("Alias match: 'liquidbounce+' -> LiquidBounce", lb_found)

# 3b. Cheat module detection
results = detector.scan_text("enable killaura and set reach to 4.5")
ka = any(r.name == "KillAura" for r in results)
reach = any(r.name == "Reach" for r in results)
test("Module match: KillAura detected", ka)
test("Module match: Reach detected", reach)

results = detector.scan_text("turning on flight and speed hack")
flight = any(r.name == "Flight" for r in results)
speed = any(r.name == "Speed" for r in results)
test("Module match: Flight detected", flight)
test("Module match: Speed detected", speed)

results = detector.scan_text("nofall, scaffold, and esp modules active")
nofall = any(r.name == "NoFall" for r in results)
scaffold = any(r.name == "Scaffold" for r in results)
esp = any(r.name == "ESP" for r in results)
test("Module match: NoFall detected", nofall)
test("Module match: Scaffold detected", scaffold)
test("Module match: ESP detected", esp)

# 3c. Suspicious method detection
results = detector.scan_text("void sendPacket(Packet p) { networkManager.sendPacket(p); }")
sp_found = any(r.name == "sendPacket" for r in results)
test("Suspicious method: sendPacket detected", sp_found)

results = detector.scan_text("boolean result = isOnGround(); player.setMotion(0, 0.42, 0);")
og = any(r.name == "isOnGround" for r in results)
sm = any(r.name == "setMotion" for r in results)
test("Suspicious method: isOnGround detected", og)
test("Suspicious method: setMotion detected", sm)

# 3d. Suspicious import detection
results = detector.scan_text("import java.lang.reflect.Method;\nimport sun.misc.Unsafe;")
reflect = any("reflect" in r.name.lower() for r in results)
unsafe = any("Unsafe" in r.name for r in results)
test("Suspicious import: java.lang.reflect detected", reflect)
test("Suspicious import: sun.misc.Unsafe detected", unsafe)

# 3e. Developer detection
results = detector.scan_text("Created by Alexander01998 for wurst")
dev = any(r.name == "Alexander01998" for r in results)
test("Developer match: Alexander01998 detected", dev)

# 3f. Regex pattern matching
results = detector.scan_text("bypass anticheat with disabler module enabled")
bypass = any("bypass" in r.description.lower() or "disabler" in r.name.lower() for r in results)
test("Regex pattern: bypass/disabler matched", bypass)

# 3g. Clean text should produce zero cheat results (false positive check)
results = detector.scan_text("Hello, I am a normal Minecraft player who enjoys building houses and farming.")
high_severity = [r for r in results if r.severity >= 70]
test("Clean text: zero high-severity findings (false positive check)", len(high_severity) == 0,
     f"Got {len(high_severity)} false positives")

results = detector.scan_text("I installed optifine and sodium for better FPS")
high_severity = [r for r in results if r.severity >= 70]
test("Legit mod names: zero high-severity findings", len(high_severity) == 0,
     f"Got {len(high_severity)} false positives")

# 3h. Fuzzy matching
fuzzy = detector.fuzzy_match("wrst cliient killaur", threshold=0.75)
test(f"Fuzzy match found {len(fuzzy)} results", len(fuzzy) >= 1)

fuzzy_results = detector.fuzzy_scan("wrst meteoor impactt", threshold=0.78)
test(f"Fuzzy scan found {len(fuzzy_results)} results", len(fuzzy_results) >= 1)

# 3i. URL scanning
url_results = detector.scan_url("https://wurstclient.net/download")
test("URL scan: wurstclient.net detected", len(url_results) >= 1)

url_results = detector.scan_url("https://impactclient.net/")
test("URL scan: impactclient.net detected", len(url_results) >= 1)

url_results = detector.scan_url("https://meteorclient.com/download")
test("URL scan: meteorclient.com detected", len(url_results) >= 1)

url_results = detector.scan_url("https://google.com")
test("URL scan: google.com clean (no match)", len(url_results) == 0)

url_results = detector.scan_url("https://discord.gg/wurst")
test("URL scan: discord.gg/wurst detected", len(url_results) >= 1)

# 3j. Filename scanning
fname_results = detector.scan_filename("wurst-7.35.jar")
test("Filename scan: wurst JAR detected", len(fname_results) >= 1)

fname_results = detector.scan_filename("killaura.json")
test("Filename scan: killaura.json detected", len(fname_results) >= 1)

fname_results = detector.scan_filename("sodium-fabric-0.5.jar")
test("Filename scan: sodium (legit) = low/no match", 
     all(r.severity < 80 for r in fname_results))

# 3k. Process scanning
proc_results = detector.scan_process("cheatengine.exe")
test("Process scan: cheatengine detected", len(proc_results) >= 1)

proc_results = detector.scan_process("autoclicker.exe")
test("Process scan: autoclicker detected", len(proc_results) >= 1)

proc_results = detector.scan_process("extreme-injector.exe")
test("Process scan: extreme-injector detected", len(proc_results) >= 1)

proc_results = detector.scan_process("chrome.exe")
test("Process scan: chrome.exe (whitelisted) = no match", len(proc_results) == 0)

proc_results = detector.scan_process("explorer.exe")
test("Process scan: explorer.exe (whitelisted) = no match", len(proc_results) == 0)


# ══════════════════════════════════════════════════════════════
# TEST 4: Bytecode Analyzer (Mods Scanner Core)
# ══════════════════════════════════════════════════════════════
section("TEST 4: Bytecode Analyzer")

analyzer = BytecodeAnalyzer()
test("BytecodeAnalyzer instantiated", analyzer is not None)

# Create a fake Java .class file with cheat strings in constant pool
def create_fake_class(strings_to_embed):
    """Build a minimal Java .class bytecode with given UTF8 constants."""
    buf = bytearray()
    buf += JAVA_CLASS_MAGIC                      # magic
    buf += struct.pack('>H', 0)                  # minor version
    buf += struct.pack('>H', 52)                 # major version (Java 8)
    cp_count = len(strings_to_embed) + 1         # +1 because pool is 1-indexed
    buf += struct.pack('>H', cp_count)
    
    for s in strings_to_embed:
        encoded = s.encode('utf-8')
        buf += bytes([1])                         # CONSTANT_Utf8
        buf += struct.pack('>H', len(encoded))
        buf += encoded
    
    # Minimal remaining class data
    buf += struct.pack('>H', 0x0001)             # access flags: public
    buf += struct.pack('>H', 0)                  # this_class (invalid but ok for our parser)
    buf += struct.pack('>H', 0)                  # super_class
    buf += struct.pack('>H', 0)                  # interfaces count
    buf += struct.pack('>H', 0)                  # fields count
    buf += struct.pack('>H', 0)                  # methods count
    buf += struct.pack('>H', 0)                  # attributes count
    return bytes(buf)

# 4a. Test with cheat client name embedded
class_data = create_fake_class(["com/example/Main", "Wurst Client v7", "net/minecraft/client"])
findings = analyzer.analyze_class(class_data, "com/example/Main")
wurst_found = any("Wurst" in f.get("description", "") for f in findings)
test("Bytecode: 'Wurst Client v7' string detected in constant pool", wurst_found)

# 4b. Test with cheat module names
class_data = create_fake_class(["KillAura", "sendPacket", "getEntityByID", "net/minecraft/network"])
findings = analyzer.analyze_class(class_data, "com/hack/Module")
ka_found = any("KillAura" in f.get("description", "") for f in findings)
sp_found = any("sendPacket" in f.get("description", "") for f in findings)
test("Bytecode: KillAura string detected", ka_found)
test("Bytecode: sendPacket method reference detected", sp_found)

# 4c. Test with suspicious imports
class_data = create_fake_class([
    "java/lang/reflect/Method", "sun/misc/Unsafe", 
    "org/objectweb/asm/ClassWriter", "io/netty/channel/Channel"
])
findings = analyzer.analyze_class(class_data, "com/obf/a")
reflect_found = any("reflect" in f.get("description", "").lower() for f in findings)
unsafe_found = any("Unsafe" in f.get("description", "") for f in findings)
test("Bytecode: reflection import detected", reflect_found)
test("Bytecode: Unsafe import detected", unsafe_found)

# 4d. Test obfuscation detection (short class name)
class_data = create_fake_class(["a", "b", "c"])
findings = analyzer.analyze_class(class_data, "a")
obf_found = any("obfuscated" in f.get("description", "").lower() for f in findings)
test("Bytecode: obfuscated short class name detected", obf_found)

# 4e. Test clean class (should have minimal/no findings)
class_data = create_fake_class([
    "com/example/mymod/MyMod", "net/minecraft/client/Minecraft",
    "org/spongepowered/asm/mixin/Mixin", "Initializing MyMod v1.0"
])
findings = analyzer.analyze_class(class_data, "com/example/mymod/MyMod")
high_findings = [f for f in findings if f.get("severity", 0) >= 80]
test("Bytecode: clean mod has few/no high-severity findings", len(high_findings) <= 1,
     f"Got {len(high_findings)} high-severity findings")

# 4f. Test with encoded/base64 string
import base64
encoded_str = base64.b64encode(b"This is a hidden cheat config string").decode()
class_data = create_fake_class([encoded_str, "com/cheat/Config"])
findings = analyzer.analyze_class(class_data, "com/cheat/Config")
b64_found = any("base64" in f.get("description", "").lower() or 
                 "encoded" in f.get("description", "").lower() for f in findings)
test("Bytecode: Base64 encoded string detected", b64_found)

# 4g. Test invalid class data
findings = analyzer.analyze_class(b"not a class file", "invalid")
test("Bytecode: invalid class returns empty findings", len(findings) == 0)

findings = analyzer.analyze_class(b"", "empty")
test("Bytecode: empty data returns empty findings", len(findings) == 0)

findings = analyzer.analyze_class(None, "none")
test("Bytecode: None data returns empty findings", len(findings) == 0)


# ══════════════════════════════════════════════════════════════
# TEST 5: Mods Scanner - JAR Processing
# ══════════════════════════════════════════════════════════════
section("TEST 5: Mods Scanner - JAR Processing")

# Create fake mod JARs for testing
with tempfile.TemporaryDirectory() as tmpdir:
    
    # 5a. Create a "cheat mod" JAR
    cheat_jar = os.path.join(tmpdir, "wurst-client-v7.35.jar")
    with zipfile.ZipFile(cheat_jar, 'w') as zf:
        # Add a class with cheat strings
        class_data = create_fake_class([
            "net/wurstclient/WurstClient", "KillAura", "sendPacket",
            "java/lang/reflect/Method", "Fly", "Speed", "NoFall"
        ])
        zf.writestr("net/wurstclient/WurstClient.class", class_data)
        zf.writestr("net/wurstclient/hack/KillAuraHack.class", 
                     create_fake_class(["KillAura", "attackEntity", "getEntityByID"]))
        # Add metadata
        zf.writestr("fabric.mod.json", json.dumps({
            "schemaVersion": 1,
            "id": "wurst",
            "name": "Wurst Client",
            "version": "7.35",
        }))
    
    # 5b. Create a "clean mod" JAR
    clean_jar = os.path.join(tmpdir, "sodium-fabric-0.5.3.jar")
    with zipfile.ZipFile(clean_jar, 'w') as zf:
        class_data = create_fake_class([
            "me/jellysquid/mods/sodium/SodiumMod",
            "net/minecraft/client/render/RenderLayer",
            "Initializing Sodium v0.5.3"
        ])
        zf.writestr("me/jellysquid/mods/sodium/SodiumMod.class", class_data)
        zf.writestr("fabric.mod.json", json.dumps({
            "schemaVersion": 1,
            "id": "sodium",
            "name": "Sodium",
            "version": "0.5.3",
        }))
    
    # 5c. Create a "suspicious mod" JAR (obfuscated)
    sus_jar = os.path.join(tmpdir, "mysterious-mod-1.0.jar")
    with zipfile.ZipFile(sus_jar, 'w') as zf:
        # Heavily obfuscated class with reflection
        class_data = create_fake_class([
            "java/lang/reflect/Method", "java/lang/reflect/Field",
            "getDeclaredMethod", "setAccessible", "invoke",
            "java/lang/Class", "forName",
            base64.b64encode(b"hidden_cheat_config").decode()
        ])
        zf.writestr("a.class", class_data)
        zf.writestr("b.class", create_fake_class(["c", "d", "e"]))
    
    # Now scan them
    scanner = ModsScanner()
    test("ModsScanner instantiated", scanner is not None)
    
    # Scan cheat mod
    result = scanner.scan_single_mod(cheat_jar)
    test(f"Cheat JAR status: {result.status}", result.status == "CHEAT_DETECTED",
         f"Expected CHEAT_DETECTED, got {result.status}")
    test(f"Cheat JAR severity: {result.severity}", result.severity >= 80)
    test(f"Cheat JAR findings: {len(result.findings)}", len(result.findings) >= 3)
    test(f"Cheat JAR classes scanned: {result.classes_scanned}", result.classes_scanned == 2)
    
    # Scan clean mod (should be whitelisted)
    result = scanner.scan_single_mod(clean_jar)
    test(f"Clean JAR (sodium) whitelisted: {result.is_whitelisted}", result.is_whitelisted)
    test(f"Clean JAR status: {result.status}", result.status == "CLEAN")
    
    # Scan suspicious mod
    result = scanner.scan_single_mod(sus_jar)
    test(f"Suspicious JAR status: {result.status}", result.status in ("SUSPICIOUS", "CHEAT_DETECTED"),
         f"Got {result.status}")
    test(f"Suspicious JAR findings: {len(result.findings)}", len(result.findings) >= 1)
    
    # Scan directory
    results = scanner.scan_directory(tmpdir)
    test(f"Directory scan found {len(results)} mods", len(results) == 3)
    cheats = [r for r in results if r.status == "CHEAT_DETECTED"]
    clean = [r for r in results if r.status == "CLEAN"]
    test(f"Directory scan: {len(cheats)} cheat(s) detected", len(cheats) >= 1)
    test(f"Directory scan: {len(clean)} clean mod(s)", len(clean) >= 1)
    
    # Test ModScanResult properties
    mr = ModScanResult(filepath="/test.jar", filename="test.jar", 
                       file_size=1024, md5="abc123")
    test("ModScanResult default status is CLEAN", mr.status == "CLEAN")
    mr.add_finding("TestClass", "test_type", "test finding", 85)
    test("ModScanResult auto-upgrades to CHEAT_DETECTED at sev>=80", mr.status == "CHEAT_DETECTED")
    test("ModScanResult severity updated", mr.severity == 85)
    
    mr2 = ModScanResult(filepath="/test2.jar", filename="test2.jar",
                        file_size=2048, md5="def456")
    mr2.add_finding("TestClass", "test_type", "suspicious", 55)
    test("ModScanResult SUSPICIOUS at sev 50-79", mr2.status == "SUSPICIOUS")


# ══════════════════════════════════════════════════════════════
# TEST 6: Utility Functions
# ══════════════════════════════════════════════════════════════
section("TEST 6: Utility Functions")

test("format_size(500)", format_size(500) == "500 B")
test("format_size(1024)", format_size(1024) == "1.0 KB")
test("format_size(1048576)", format_size(1048576) == "1.0 MB")
test("format_size(1073741824)", format_size(1073741824) == "1.00 GB")

test("format_duration(0.5)", format_duration(0.5) == "500ms")
test("format_duration(5.3)", format_duration(5.3) == "5.3s")
test("format_duration(125)", format_duration(125) == "2m 5s")

test("severity_label(95)", severity_label(95) == "CRITICAL")
test("severity_label(75)", severity_label(75) == "HIGH")
test("severity_label(55)", severity_label(55) == "MEDIUM")
test("severity_label(35)", severity_label(35) == "LOW")
test("severity_label(15)", severity_label(15) == "INFO")

test("severity_color(95) is red", severity_color(95) == "#FF1744")
test("severity_color(75) is orange", severity_color(75) == "#FF9100")
test("severity_color(5) is green", severity_color(5) == "#00E676")

# Test ScanResult
sr = ScanResult(scanner="Test", category="test", name="TestFinding",
                description="A test", severity=85, filepath="/test",
                evidence="test evidence")
test("ScanResult to_dict() works", "scanner" in sr.to_dict())
test("ScanResult severity clamped to 0-100", 
     ScanResult(scanner="T", category="t", name="t", description="t", severity=150).severity == 100)

# Test ScanProgress
sp = ScanProgress()
sp.start("Test", 10)
test("ScanProgress total", sp.total == 10)
sp.update("file1")
test("ScanProgress completed", sp.completed == 1)
test("ScanProgress pct", sp.get_progress_pct() == 10.0)
sp.add_result(sr)
test("ScanProgress results", len(sp.results) == 1)
test("ScanProgress cheat_count", sp.cheat_count == 1)

# Test file hashing
with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
    f.write(b"test content for hashing")
    tmpf = f.name
md5 = file_hash_md5(tmpf)
sha256 = file_hash_sha256(tmpf)
test("file_hash_md5 returns string", md5 is not None and len(md5) == 32)
test("file_hash_sha256 returns string", sha256 is not None and len(sha256) == 64)
os.unlink(tmpf)

# Test safe_read_file
with tempfile.NamedTemporaryFile(delete=False, suffix='.txt', mode='w', encoding='utf-8') as f:
    f.write("test file content\nline2")
    tmpf = f.name
content = safe_read_file(tmpf)
test("safe_read_file works", content == "test file content\nline2")
os.unlink(tmpf)

test("safe_read_file nonexistent returns None", safe_read_file("/nonexistent/file") is None)

# Test parallel_execute
results = parallel_execute(lambda x: x * 2, [1, 2, 3, 4, 5], max_workers=4)
test(f"parallel_execute returns {len(results)} results", len(results) == 5)


# ══════════════════════════════════════════════════════════════
# TEST 7: Settings & Configuration
# ══════════════════════════════════════════════════════════════
section("TEST 7: Settings & Configuration")

settings = AppSettings()
test("Default language is 'id'", settings.language == "id")
test("Default decompiler is 'CFR'", settings.decompiler == "CFR")
test("Default max_threads is 8", settings.max_threads == 8)
test("Default auto_update is True", settings.auto_update_db == True)
test("Default cache enabled", settings.cache_enabled == True)
test("Default deep_scan off", settings.deep_scan_mode == False)

test("APP_NAME set", APP_NAME == "SS-Tools Ultimate")
test("APP_VERSION set", APP_VERSION == "3.0.0")
test(f"Launcher paths: {len(MINECRAFT_LAUNCHER_PATHS)}", len(MINECRAFT_LAUNCHER_PATHS) >= 14)
test(f"Scan dirs: {len(MINECRAFT_SCAN_DIRS)}", len(MINECRAFT_SCAN_DIRS) >= 10)

# Test save/load cycle
import tempfile
settings.language = "en"
settings.decompiler = "FernFlower"
settings.save()
loaded = AppSettings.load()
test("Settings save/load: language persisted", loaded.language == "en")
test("Settings save/load: decompiler persisted", loaded.decompiler == "FernFlower")
# Reset
settings.language = "id"
settings.decompiler = "CFR"
settings.save()


# ══════════════════════════════════════════════════════════════
# TEST 8: i18n (Internationalization)
# ══════════════════════════════════════════════════════════════
section("TEST 8: Internationalization (i18n)")

i18n_id = I18n("id")
i18n_en = I18n("en")

test("ID translation: dashboard", i18n_id.t("dashboard") == "Dashboard")
test("ID translation: full_scan", i18n_id.t("full_scan") == "Full Auto Scan")
test("ID translation: cheater_detected", "CHEATER TERDETEKSI" in i18n_id.t("cheater_detected"))
test("ID translation: player_clean", "PLAYER BERSIH" in i18n_id.t("player_clean"))

test("EN translation: dashboard", i18n_en.t("dashboard") == "Dashboard")
test("EN translation: cheater_detected", "CHEATER DETECTED" in i18n_en.t("cheater_detected"))
test("EN translation: player_clean", "PLAYER CLEAN" in i18n_en.t("player_clean"))

# Test format arguments
msg = i18n_id.t("msg_scan_complete", time="5.3s")
test("ID format args: msg_scan_complete", "5.3s" in msg)

msg = i18n_en.t("msg_findings_found", count=42)
test("EN format args: msg_findings_found", "42" in msg)

# Test missing key returns key name
test("Missing key returns key", i18n_id.t("nonexistent_key") == "nonexistent_key")

# Test language switching
i18n = I18n("id")
i18n.set_language("en")
test("Language switch works", i18n.t("settings") == "Settings")
i18n.set_language("id")
test("Language switch back", i18n.t("settings") == "Pengaturan")

# Verify all keys exist in both languages
id_keys = set(TRANSLATIONS["id"].keys())
en_keys = set(TRANSLATIONS["en"].keys())
missing_in_en = id_keys - en_keys
missing_in_id = en_keys - id_keys
test(f"All ID keys exist in EN ({len(missing_in_en)} missing)", len(missing_in_en) == 0,
     f"Missing: {missing_in_en}")
test(f"All EN keys exist in ID ({len(missing_in_id)} missing)", len(missing_in_id) == 0,
     f"Missing: {missing_in_id}")


# ══════════════════════════════════════════════════════════════
# TEST 9: Report Generator
# ══════════════════════════════════════════════════════════════
section("TEST 9: Report Generator")

rg = ReportGenerator()
test("ReportGenerator instantiated", rg is not None)

# Generate report with test results
test_results = [
    ScanResult("TestScanner", "cheat_client", "Wurst", "Wurst client detected", 100,
               filepath="/mods/wurst.jar", evidence="Found in bytecode"),
    ScanResult("ModsScanner", "cheat_module", "KillAura", "KillAura module found", 95,
               filepath="/mods/hack.jar", evidence="Class: com/hack/KillAura"),
    ScanResult("ProcessScanner", "suspicious_process", "cheatengine", "Cheat Engine running", 100,
               evidence="PID: 1234"),
    ScanResult("BrowserScanner", "cheat_url", "wurstclient.net", "Cheat website visited", 90,
               evidence="https://wurstclient.net/download"),
    ScanResult("KernelCheck", "cheat_driver", "dbk64.sys", "Cheat Engine driver", 100,
               filepath="C:\\Windows\\System32\\drivers\\dbk64.sys"),
    ScanResult("MemoryScanner", "info", "Java process", "Java process found", 20),
]

report_path = rg.generate_html_report(
    test_results,
    scan_duration=12.5,
    player_name="TestPlayer123",
    staff_name="StaffMember",
    server_name="TestServer",
)
test("Report generated", os.path.exists(report_path))

report_content = open(report_path, 'r', encoding='utf-8').read()
test("Report contains player name", "TestPlayer123" in report_content)
test("Report contains staff name", "StaffMember" in report_content)
test("Report contains server name", "TestServer" in report_content)
test("Report contains CHEATER DETECTED", "CHEATER DETECTED" in report_content)
test("Report contains Wurst finding", "Wurst" in report_content)
test("Report contains KillAura finding", "KillAura" in report_content)
test("Report contains severity badges", "CRITICAL" in report_content)
test("Report is valid HTML", "<html" in report_content and "</html>" in report_content)
test("Report has styling", "<style>" in report_content)
test(f"Report size: {len(report_content)} chars", len(report_content) > 3000)

# Test clean report
clean_results = [
    ScanResult("TestScanner", "info", "Scan complete", "No issues found", 10),
]
clean_report_path = rg.generate_html_report(
    clean_results, scan_duration=8.2,
    player_name="CleanPlayer", staff_name="Staff", server_name="Server",
)
clean_content = open(clean_report_path, 'r', encoding='utf-8').read()
test("Clean report contains PLAYER CLEAN", "PLAYER CLEAN" in clean_content)
test("Clean report contains player name", "CleanPlayer" in clean_content)


# ══════════════════════════════════════════════════════════════
# TEST 10: Evidence Collector
# ══════════════════════════════════════════════════════════════
section("TEST 10: Evidence Collector")

ec = EvidenceCollector()
test("EvidenceCollector instantiated", ec is not None)
test("Evidence directory created", os.path.exists(ec.evidence_path))

# Save scan results
results_path = ec.save_scan_results(test_results)
test("Scan results saved", os.path.exists(results_path))
saved_data = json.load(open(results_path, 'r', encoding='utf-8'))
test(f"Saved {len(saved_data)} results", len(saved_data) == len(test_results))

# Test collect file
with tempfile.NamedTemporaryFile(delete=False, suffix='.jar') as f:
    f.write(b"fake jar content")
    tmpf = f.name
collected = ec.collect_file(tmpf, "test_mod.jar")
test("File collected to evidence", collected is not None and os.path.exists(collected))
os.unlink(tmpf)


# ══════════════════════════════════════════════════════════════
# TEST 11: Scanner Instantiation (non-Windows graceful handling)
# ══════════════════════════════════════════════════════════════
section("TEST 11: Scanner Instantiation & Graceful Degradation")

# These scanners use Windows APIs but should instantiate without error
progress = ScanProgress()

ps = ProcessScanner(progress)
test("ProcessScanner instantiated", ps is not None)
# On Linux, psutil works so we can actually scan
try:
    results = ps.scan()
    test(f"ProcessScanner.scan() returned {len(results)} results (no crash)", True)
except Exception as e:
    test("ProcessScanner.scan() no crash", False, str(e))

kc = KernelCheck(progress)
test("KernelCheck instantiated", kc is not None)
# On Linux, should return graceful warning
try:
    results = kc.scan()
    test(f"KernelCheck.scan() returned {len(results)} results (graceful)", True)
except Exception as e:
    test("KernelCheck.scan() no crash", False, str(e))

ms = MemoryScanner(progress)
test("MemoryScanner instantiated", ms is not None)
try:
    results = ms.scan()
    test(f"MemoryScanner.scan() returned {len(results)} results", True)
except Exception as e:
    test("MemoryScanner.scan() no crash", False, str(e))

ns = NetworkScanner(progress)
test("NetworkScanner instantiated", ns is not None)
try:
    results = ns.scan()
    test(f"NetworkScanner.scan() returned {len(results)} results", True)
except Exception as e:
    test("NetworkScanner.scan() no crash", False, str(e))

bs = BrowserScanner(progress)
test("BrowserScanner instantiated", bs is not None)

dfd = DeletedFileDetector(progress)
test("DeletedFileDetector instantiated", dfd is not None)

sds = StringDeletedScanner(progress)
test("StringDeletedScanner instantiated", sds is not None)

mcs = MinecraftScanner(progress)
test("MinecraftScanner instantiated", mcs is not None)
info = mcs.get_installation_info()
test(f"MinecraftScanner.get_installation_info() returned (no crash)", True)


# ══════════════════════════════════════════════════════════════
# TEST 12: Edge Cases & Robustness
# ══════════════════════════════════════════════════════════════
section("TEST 12: Edge Cases & Robustness")

# Empty string scan
results = detector.scan_text("")
test("Empty string scan: no crash", True)
test("Empty string scan: no results", len(results) == 0)

# Very long string scan
long_text = "normal text " * 10000
results = detector.scan_text(long_text)
test("Very long string scan: no crash", True)

# Unicode text
results = detector.scan_text("こんにちは Minecraft プレイヤー 日本語テスト")
test("Unicode text scan: no crash", True)

# Special characters
results = detector.scan_text("!@#$%^&*()_+-={}[]|\\:\";<>?,./~`")
test("Special chars scan: no crash", True)

# Scan text with actual cheat mixed in Unicode
results = detector.scan_text("プレイヤーが wurst を使用しています")
wurst_in_unicode = any(r.name == "Wurst" for r in results)
test("Cheat in Unicode text detected", wurst_in_unicode)

# Test concurrent database access
import threading
errors = []
def db_access():
    try:
        db = CheatDatabase()
        _ = db.cheat_clients
        _ = db.get_all_keywords()
    except Exception as e:
        errors.append(str(e))

threads = [threading.Thread(target=db_access) for _ in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()
test("Concurrent DB access: thread-safe", len(errors) == 0,
     f"Errors: {errors}")

# Test corrupt JAR handling
with tempfile.NamedTemporaryFile(delete=False, suffix='.jar') as f:
    f.write(b"this is not a valid zip/jar file")
    corrupt_jar = f.name
result = scanner.scan_single_mod(corrupt_jar)
test("Corrupt JAR: no crash", True)
test("Corrupt JAR: has finding about corruption", 
     any("corrupt" in f.get("type", "").lower() or "corrupt" in f.get("description", "").lower() 
         for f in result.findings))
os.unlink(corrupt_jar)

# Test empty JAR
with tempfile.NamedTemporaryFile(delete=False, suffix='.jar') as f:
    with zipfile.ZipFile(f.name, 'w') as zf:
        pass  # empty zip
    empty_jar = f.name
result = scanner.scan_single_mod(empty_jar)
test("Empty JAR: no crash", True)
test("Empty JAR: status is CLEAN", result.status == "CLEAN")
os.unlink(empty_jar)


# ══════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print(f"  FINAL RESULTS")
print(f"=" * 60)
print(f"  ✅ Passed: {PASS}")
print(f"  ❌ Failed: {FAIL}")
print(f"  Total:   {PASS + FAIL}")
print(f"  Rate:    {PASS / (PASS + FAIL) * 100:.1f}%")

if ERRORS:
    print(f"\n  Failed tests:")
    for e in ERRORS:
        print(f"  {e}")

print(f"{'=' * 60}")
sys.exit(0 if FAIL == 0 else 1)
