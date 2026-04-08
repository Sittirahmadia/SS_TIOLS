#!/usr/bin/env python3
"""
SS-Tools Ultimate - Ghost Client Detection Test
Simulates a realistic ghost client scenario:
 - Obfuscated mod JAR disguised as a legit mod
 - Hidden cheat strings in bytecode constant pool
 - Reflection-heavy code
 - Fake browser history with cheat downloads
 - Cheat config files hidden in .minecraft
 - Prefetch/registry-like artifacts

Ghost clients tested:
 1. Vape V4 (heavily obfuscated, disguised as "performance-tweaks-1.2.jar")
 2. Dream Client (disguised as "optifine-hd-ultra.jar" with renamed classes)
 3. Skilled V3 (injected into a legit mod, mixed with real mod code)
 4. Custom ghost (fully obfuscated, no clear names, only bytecode patterns)
"""
import os
import sys
import json
import struct
import zipfile
import tempfile
import base64
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.mods_scanner import ModsScanner, ModScanResult, BytecodeAnalyzer, JAVA_CLASS_MAGIC
from core.keyword_detector import KeywordDetector
from core.scan_engine import ScanEngine
from core.config import AppSettings
from core.utils import ScanResult, format_duration, severity_label, severity_color
from core.database import CheatDatabase

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
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")

def create_class(strings, class_name="com/example/Main"):
    """Build a minimal Java .class with UTF8 constants in the pool."""
    buf = bytearray()
    buf += JAVA_CLASS_MAGIC
    buf += struct.pack('>H', 0)       # minor
    buf += struct.pack('>H', 52)      # major (Java 8)
    cp_count = len(strings) + 1
    buf += struct.pack('>H', cp_count)
    for s in strings:
        encoded = s.encode('utf-8')
        buf += bytes([1])  # CONSTANT_Utf8
        buf += struct.pack('>H', len(encoded))
        buf += encoded
    buf += struct.pack('>H', 0x0001)  # access: public
    buf += struct.pack('>H', 0)
    buf += struct.pack('>H', 0)
    buf += struct.pack('>H', 0)
    buf += struct.pack('>H', 0)
    buf += struct.pack('>H', 0)
    buf += struct.pack('>H', 0)
    return bytes(buf)


# ══════════════════════════════════════════════════════════════════════
section("GHOST CLIENT 1: Vape V4 Style (Heavily Obfuscated)")
# ══════════════════════════════════════════════════════════════════════
print("  Simulating Vape V4-style ghost client:")
print("  - Disguised as 'performance-tweaks-1.2.jar'")
print("  - All class names are single/double letters (a, b, c, aa, ab)")
print("  - Cheat strings encrypted with Base64")
print("  - Heavy reflection usage for method hooking")
print("  - Packet manipulation via sendPacket hooks")
print("  - Motion modification for subtle speed/reach")
print()

with tempfile.TemporaryDirectory() as tmpdir:
    vape_jar = os.path.join(tmpdir, "performance-tweaks-1.2.jar")

    with zipfile.ZipFile(vape_jar, 'w') as zf:
        # Main class — obfuscated loader with reflection
        zf.writestr("a.class", create_class([
            "java/lang/reflect/Method",
            "java/lang/reflect/Field",
            "java/lang/Class",
            "getDeclaredMethod",
            "getDeclaredField",
            "setAccessible",
            "invoke",
            "forName",
            "java/lang/ClassLoader",
            "defineClass",
            # Base64 encoded cheat config reference
            base64.b64encode(b"vape_config_v4_licensed").decode(),
            base64.b64encode(b"killaura_settings").decode(),
            base64.b64encode(b"reach_distance_modifier").decode(),
        ]))

        # Combat module — hidden KillAura with obfuscated names
        zf.writestr("b.class", create_class([
            "attackEntity",
            "getEntityByID",
            "rayTrace",
            "getBlockReachDistance",
            "sendPacket",
            "net/minecraft/network/NetworkManager",
            "net/minecraft/network/play/client/C02PacketUseEntity",
            "java/lang/reflect/Method",
            "invoke",
        ]))

        # Movement module — subtle speed/motion tweak
        zf.writestr("c.class", create_class([
            "isOnGround",
            "setMotion",
            "getMotion",
            "moveFlying",
            "moveEntity",
            "net/minecraft/entity/player/EntityPlayer",
            "motionX", "motionY", "motionZ",
            "posX", "posY", "posZ",
            "onGround",
            "java/lang/reflect/Field",
            "setAccessible",
        ]))

        # Render module — subtle ESP/tracers
        zf.writestr("d.class", create_class([
            "renderWorld",
            "isBoundingBoxInFrustum",
            "org/lwjgl/opengl/GL11",
            "glEnable", "glDisable",
            "GL_DEPTH_TEST", "GL_BLEND",
            "getRenderPartialTicks",
            "getMouseOver",
        ]))

        # Anti-detection module
        zf.writestr("e.class", create_class([
            "java/lang/ProcessBuilder",
            "java/lang/Runtime",
            "exec",
            # Encrypted anti-debug strings
            base64.b64encode(b"debugger_detection_bypass").decode(),
            base64.b64encode(b"anticheat_disabler_v2").decode(),
            "sun/misc/Unsafe",
            "java/lang/instrument/Instrumentation",
        ]))

        # Network/license check
        zf.writestr("f.class", create_class([
            "java/net/HttpURLConnection",
            "java/net/URL",
            "javax/net/ssl/HttpsURLConnection",
            base64.b64encode(b"https://vape.gg/api/license").decode(),
            base64.b64encode(b"hwid_check_endpoint").decode(),
            "io/netty/channel/Channel",
            "channelRead0",
            "processPacket",
        ]))

        # Fake metadata to look legit
        zf.writestr("fabric.mod.json", json.dumps({
            "schemaVersion": 1,
            "id": "performance-tweaks",
            "name": "Performance Tweaks",
            "version": "1.2.0",
            "description": "Simple performance improvements for Minecraft",
            "authors": ["ModDev"],
            "environment": "client",
        }))

    scanner = ModsScanner()
    result = scanner.scan_single_mod(vape_jar)

    print(f"  File: {result.filename}")
    print(f"  Status: {result.status}")
    print(f"  Severity: {result.severity}")
    print(f"  Classes scanned: {result.classes_scanned}")
    print(f"  Findings: {len(result.findings)}")
    print()

    test("Vape ghost: DETECTED (not CLEAN)", result.status != "CLEAN",
         f"Got {result.status}")
    test("Vape ghost: status is CHEAT_DETECTED", result.status == "CHEAT_DETECTED",
         f"Got {result.status}")
    test("Vape ghost: severity >= 80", result.severity >= 80,
         f"Got {result.severity}")
    test("Vape ghost: multiple findings", len(result.findings) >= 5,
         f"Got {len(result.findings)}")

    # Check specific detection types
    finding_types = [f["type"] for f in result.findings]
    finding_descs = " ".join([f["description"] for f in result.findings]).lower()

    test("Vape: reflection detected", any("reflect" in t or "reflection" in t for t in finding_types) or
         "reflect" in finding_descs)
    test("Vape: sendPacket hook detected", "sendpacket" in finding_descs or
         any("sendPacket" in f.get("evidence", "") for f in result.findings))
    test("Vape: motion modification detected", "motion" in finding_descs or
         "setmotion" in finding_descs or "getmotion" in finding_descs)
    test("Vape: obfuscation detected", any("obfuscat" in t for t in finding_types) or
         "obfuscat" in finding_descs)
    test("Vape: Base64 encoded strings detected", any("base64" in t.lower() or "encoded" in t.lower()
         for t in finding_types) or "encoded" in finding_descs or "base64" in finding_descs)
    test("Vape: Unsafe/instrumentation detected", "unsafe" in finding_descs or
         "instrument" in finding_descs)

    print("\n  Top findings:")
    for f in sorted(result.findings, key=lambda x: -x["severity"])[:8]:
        sev = f["severity"]
        print(f"    [{severity_label(sev):8}:{sev:3}] {f['type']}: {f['description'][:80]}")


# ══════════════════════════════════════════════════════════════════════
section("GHOST CLIENT 2: Dream Client Style (Disguised as OptiFine)")
# ══════════════════════════════════════════════════════════════════════
print("  Simulating Dream Client-style ghost:")
print("  - Disguised as 'OptiFine_HD_Ultra.jar'")
print("  - Mixin-based injection into vanilla classes")
print("  - Subtle reach + hitbox expansion")
print("  - Timer manipulation for CPS boost")
print()

with tempfile.TemporaryDirectory() as tmpdir:
    dream_jar = os.path.join(tmpdir, "OptiFine_HD_Ultra.jar")

    with zipfile.ZipFile(dream_jar, 'w') as zf:
        # Mixin injector targeting combat
        zf.writestr("com/dream/mixin/MixinEntityPlayer.class", create_class([
            "org/spongepowered/asm/mixin/Mixin",
            "org/spongepowered/asm/mixin/injection/Inject",
            "org/spongepowered/asm/mixin/injection/Redirect",
            "org/spongepowered/asm/mixin/Overwrite",
            "attackEntity",
            "getBlockReachDistance",
            "net/minecraft/entity/player/EntityPlayer",
        ]))

        # Reach modifier via mixin redirect
        zf.writestr("com/dream/mixin/MixinPlayerController.class", create_class([
            "org/spongepowered/asm/mixin/Mixin",
            "org/spongepowered/asm/mixin/injection/Redirect",
            "getBlockReachDistance",
            "rayTrace",
            # Hardcoded reach value (4.5 instead of 3.0)
            "4.5",
            "net/minecraft/client/multiplayer/PlayerControllerMP",
        ]))

        # Timer speed manipulation
        zf.writestr("com/dream/core/TimerAccess.class", create_class([
            "net/minecraft/util/Timer",
            "timerSpeed",
            "renderPartialTicks",
            "elapsedPartialTicks",
            "java/lang/reflect/Field",
            "setAccessible",
            "setFloat",
        ]))

        # Hitbox expansion via mixin
        zf.writestr("com/dream/mixin/MixinEntity.class", create_class([
            "org/spongepowered/asm/mixin/Mixin",
            "org/spongepowered/asm/mixin/Overwrite",
            "net/minecraft/entity/Entity",
            "getEntityBoundingBox",
            "expand",
            "isBoundingBoxInFrustum",
        ]))

        # Config with cheat module names (encrypted)
        zf.writestr("config.json", json.dumps({
            "modules": {
                base64.b64encode(b"reach").decode(): {"value": 3.5, "enabled": True},
                base64.b64encode(b"hitbox").decode(): {"value": 0.15, "enabled": True},
                base64.b64encode(b"timer").decode(): {"value": 1.02, "enabled": True},
                base64.b64encode(b"velocity").decode(): {"horizontal": 95, "vertical": 100},
            }
        }))

        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: com.dream.Main\n")

    result = scanner.scan_single_mod(dream_jar)

    print(f"  File: {result.filename}")
    print(f"  Status: {result.status}")
    print(f"  Severity: {result.severity}")
    print(f"  Findings: {len(result.findings)}")
    print()

    test("Dream ghost: DETECTED", result.status != "CLEAN",
         f"Got {result.status}")
    test("Dream ghost: severity >= 60", result.severity >= 60,
         f"Got {result.severity}")

    finding_descs = " ".join([f["description"] for f in result.findings]).lower()
    finding_types = [f["type"] for f in result.findings]

    test("Dream: Mixin Overwrite detected", "overwrite" in finding_descs,
         f"Types: {finding_types}")
    test("Dream: reach modification detected", "reach" in finding_descs or
         "getblockreachdistance" in finding_descs)
    test("Dream: timer modification detected", "timer" in finding_descs or
         "timerspeed" in finding_descs)

    print("\n  Top findings:")
    for f in sorted(result.findings, key=lambda x: -x["severity"])[:6]:
        sev = f["severity"]
        print(f"    [{severity_label(sev):8}:{sev:3}] {f['type']}: {f['description'][:80]}")


# ══════════════════════════════════════════════════════════════════════
section("GHOST CLIENT 3: Skilled V3 Style (Injected into Legit Mod)")
# ══════════════════════════════════════════════════════════════════════
print("  Simulating Skilled V3 ghost injected into a real mod:")
print("  - JAR has both legit mod classes AND injected cheat classes")
print("  - Cheat classes have very short obfuscated names")
print("  - Event-based module system (EventBus)")
print("  - Velocity modification for anti-knockback")
print()

with tempfile.TemporaryDirectory() as tmpdir:
    skilled_jar = os.path.join(tmpdir, "inventory-tweaks-1.8.9.jar")

    with zipfile.ZipFile(skilled_jar, 'w') as zf:
        # Legit mod classes
        zf.writestr("com/inventorytweaks/Main.class", create_class([
            "com/inventorytweaks/Main",
            "net/minecraft/inventory/Container",
            "Inventory Tweaks loaded",
            "net/minecraftforge/fml/common/Mod",
        ]))

        zf.writestr("com/inventorytweaks/SortHandler.class", create_class([
            "com/inventorytweaks/SortHandler",
            "net/minecraft/inventory/Slot",
            "sortInventory",
        ]))

        # INJECTED cheat: module manager with EventBus
        zf.writestr("a/a.class", create_class([
            "com/google/common/eventbus/EventBus",
            "register", "subscribe", "post",
            "java/util/ArrayList",
            "java/util/HashMap",
            base64.b64encode(b"module_manager_v3").decode(),
        ]))

        # INJECTED: velocity/anti-KB module
        zf.writestr("a/b.class", create_class([
            "setVelocity",
            "attackedAtYaw",
            "net/minecraft/network/play/server/S12PacketEntityVelocity",
            "processPacket",
            "channelRead0",
            "io/netty/channel/ChannelHandlerContext",
            "motionX", "motionY", "motionZ",
        ]))

        # INJECTED: click assist / autoclicker
        zf.writestr("a/c.class", create_class([
            "clickMouse",
            "org/lwjgl/input/Mouse",
            "isButtonDown",
            "java/util/Random",
            "nextGaussian",
            "sendPacket",
            "C0APacketAnimation",
        ]))

        # INJECTED: aim assist
        zf.writestr("a/d.class", create_class([
            "getMouseOver",
            "rayTrace",
            "getEntityByID",
            "org/lwjgl/input/Mouse",
            "getDX", "getDY",
            "rotationYaw", "rotationPitch",
            "java/lang/Math", "atan2",
        ]))

        zf.writestr("mcmod.info", json.dumps([{
            "modid": "inventorytweaks",
            "name": "Inventory Tweaks",
            "version": "1.8.9",
        }]))

    result = scanner.scan_single_mod(skilled_jar)

    print(f"  File: {result.filename}")
    print(f"  Status: {result.status}")
    print(f"  Severity: {result.severity}")
    print(f"  Findings: {len(result.findings)}")
    print()

    test("Skilled ghost: DETECTED", result.status != "CLEAN",
         f"Got {result.status}")
    test("Skilled ghost: severity >= 70", result.severity >= 70,
         f"Got {result.severity}")

    finding_descs = " ".join([f["description"] for f in result.findings]).lower()

    test("Skilled: packet processing detected", "processpacket" in finding_descs or
         "channelread" in finding_descs or "sendpacket" in finding_descs)
    test("Skilled: velocity/motion detected", "velocity" in finding_descs or
         "motion" in finding_descs)
    test("Skilled: mouse/click detected", "clickmouse" in finding_descs or
         "mouse" in finding_descs)
    test("Skilled: obfuscated class names detected", any("obfuscat" in f["description"].lower() or
         "obfuscat" in f.get("type", "").lower() for f in result.findings))

    print("\n  Top findings:")
    for f in sorted(result.findings, key=lambda x: -x["severity"])[:6]:
        sev = f["severity"]
        print(f"    [{severity_label(sev):8}:{sev:3}] {f['type']}: {f['description'][:80]}")


# ══════════════════════════════════════════════════════════════════════
section("GHOST CLIENT 4: Fully Custom (Maximum Obfuscation)")
# ══════════════════════════════════════════════════════════════════════
print("  Simulating fully custom ghost with maximum obfuscation:")
print("  - No readable cheat names at all")
print("  - All strings XOR-encrypted or Base64")
print("  - Native JNI methods")
print("  - Dynamic class loading")
print("  - Anti-analysis techniques")
print()

with tempfile.TemporaryDirectory() as tmpdir:
    custom_jar = os.path.join(tmpdir, "render-fix-2.1.jar")

    with zipfile.ZipFile(custom_jar, 'w') as zf:
        # Loader with dynamic class loading + native methods
        zf.writestr("x.class", create_class([
            "java/lang/ClassLoader",
            "defineClass",
            "java/net/URLClassLoader",
            "java/lang/reflect/Method",
            "java/lang/reflect/Field",
            "getDeclaredMethod", "getDeclaredField",
            "setAccessible", "invoke",
            "sun/misc/Unsafe",
            "java/lang/instrument/Instrumentation",
            # All cheat config encrypted
            base64.b64encode(b"combat_assist_config_encrypted_key_0xDEAD").decode(),
            base64.b64encode(b"movement_override_table_v3").decode(),
            base64.b64encode(b"render_hook_injection_point").decode(),
            base64.b64encode(b"packet_intercept_handler_map").decode(),
        ]))

        # Native method bridge
        zf.writestr("y.class", create_class([
            "native void initHooks()",
            "native int readMemory(long address)",
            "native void writeMemory(long address, int value)",
            "java/lang/ProcessBuilder",
            "java/lang/Runtime",
            "exec",
            base64.b64encode(b"native_bridge_initialized").decode(),
        ]))

        # Encrypted packet handler
        zf.writestr("z.class", create_class([
            "io/netty/channel/ChannelHandlerContext",
            "channelRead0",
            "processPacket",
            "sendPacket",
            "net/minecraft/network/NetworkManager",
            "javax/crypto/Cipher",
            "AES",
            "javax/crypto/spec/SecretKeySpec",
        ]))

        # Large encrypted string array (common obfuscation pattern)
        encrypted_strings = [base64.b64encode(s.encode()).decode() for s in [
            "KillAura", "Velocity", "Speed", "Fly", "Scaffold",
            "NoFall", "ESP", "Tracers", "AutoClicker", "Reach",
            "Timer", "AntiKB", "Phase", "Freecam", "Xray",
        ]]
        zf.writestr("w.class", create_class(encrypted_strings + [
            "javax/crypto/Cipher", "AES/ECB/PKCS5Padding",
            "java/util/Base64", "getDecoder",
        ]))

        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

    result = scanner.scan_single_mod(custom_jar)

    print(f"  File: {result.filename}")
    print(f"  Status: {result.status}")
    print(f"  Severity: {result.severity}")
    print(f"  Findings: {len(result.findings)}")
    print()

    test("Custom ghost: DETECTED", result.status != "CLEAN",
         f"Got {result.status}")
    test("Custom ghost: severity >= 75", result.severity >= 75,
         f"Got {result.severity}")
    test("Custom ghost: many findings", len(result.findings) >= 5,
         f"Got {len(result.findings)}")

    finding_descs = " ".join([f["description"] for f in result.findings]).lower()
    finding_types = [f["type"] for f in result.findings]

    test("Custom: dynamic class loading detected", "dynamic class loading" in finding_descs or
         "classloader" in finding_descs or "defineclass" in finding_descs)
    test("Custom: native methods detected", "native" in finding_descs)
    test("Custom: packet manipulation detected", "sendpacket" in finding_descs or
         "processpacket" in finding_descs or "channelread" in finding_descs)
    test("Custom: encryption detected", "cipher" in finding_descs or "aes" in finding_descs or
         "encrypt" in finding_descs or "crypto" in finding_descs)
    test("Custom: Unsafe detected", "unsafe" in finding_descs)
    test("Custom: Base64 encoded strings detected", "encoded" in finding_descs or
         "base64" in finding_descs)

    print("\n  Top findings:")
    for f in sorted(result.findings, key=lambda x: -x["severity"])[:8]:
        sev = f["severity"]
        print(f"    [{severity_label(sev):8}:{sev:3}] {f['type']}: {f['description'][:80]}")


# ══════════════════════════════════════════════════════════════════════
section("GHOST CLIENT 5: Keyword & URL Detection Test")
# ══════════════════════════════════════════════════════════════════════
print("  Testing keyword/URL detection for ghost client artifacts")
print()

detector = KeywordDetector()

# Simulated browser history entries
ghost_urls = [
    "https://www.vape.gg/download",
    "https://intent.store/product/vape-v4",
    "https://discord.gg/wurst",
    "https://unknowncheats.me/forum/minecraft/ghost-client-2026",
    "https://mpgh.net/forum/minecraft-hacks-cheats/",
    "https://directleaks.to/minecraft-ghost-client",
    "https://pastebin.com/raw/abc123cheatconfig",
    "https://anonfiles.com/ghostclient_v4",
]

detected_urls = 0
for url in ghost_urls:
    results = detector.scan_url(url)
    if results:
        detected_urls += 1
        best = max(results, key=lambda r: r.severity)
        print(f"  ✓ URL detected: {url[:50]}... → {best.name} (sev: {best.severity})")

test(f"Ghost URLs: {detected_urls}/{len(ghost_urls)} detected", detected_urls >= 5,
     f"Only {detected_urls} detected")

# Simulated filenames found on PC
ghost_files = [
    "vape-v4-loader.jar",
    "killaura.json",
    "hack_config.json",
    "cheat_config.json",
    "modules.json",
    "autoclicker.cfg",
    "wurst-client-v7.jar",
    "xray.jar",
    "friends.json",
    "alts.json",
]

detected_files = 0
for fname in ghost_files:
    results = detector.scan_filename(fname)
    if results:
        detected_files += 1

test(f"Ghost files: {detected_files}/{len(ghost_files)} detected", detected_files >= 7,
     f"Only {detected_files} detected")

# Simulated log file content
log_content = """
[14:23:15] [main/INFO]: Loading mod: wurst-7.35
[14:23:16] [main/WARN]: KillAura module initialized
[14:23:16] [main/INFO]: Flight module loaded
[14:23:17] [main/DEBUG]: Connecting to license server at vape.gg
[14:23:18] [main/INFO]: ESP rendering enabled
[14:23:18] [main/WARN]: Disabler bypass active for anticheat
[14:23:19] [main/INFO]: AutoClicker set to 14 CPS
[14:23:20] [main/DEBUG]: sendPacket intercepted: C02PacketUseEntity
"""

results = detector.scan_text(log_content, source="log", filepath="latest.log")
high_results = [r for r in results if r.severity >= 70]
test(f"Log scan: {len(high_results)} high-severity findings in cheat log",
     len(high_results) >= 5, f"Got {len(high_results)}")

print(f"\n  Log scan found {len(results)} total, {len(high_results)} high-severity:")
for r in sorted(high_results, key=lambda x: -x.severity)[:6]:
    print(f"    [{severity_label(r.severity):8}:{r.severity:3}] {r.name}: {r.description[:60]}")


# ══════════════════════════════════════════════════════════════════════
section("GHOST CLIENT 6: Full Scan with Simulated .minecraft")
# ══════════════════════════════════════════════════════════════════════
print("  Setting up fake .minecraft with ghost client artifacts")
print()

with tempfile.TemporaryDirectory() as tmpdir:
    # Create fake .minecraft structure
    mc_dir = os.path.join(tmpdir, ".minecraft")
    mods_dir = os.path.join(mc_dir, "mods")
    logs_dir = os.path.join(mc_dir, "logs")
    config_dir = os.path.join(mc_dir, "config")

    for d in [mods_dir, logs_dir, config_dir]:
        os.makedirs(d)

    # Drop ghost client JAR in mods
    ghost_jar = os.path.join(mods_dir, "performance-tweaks-1.2.jar")
    with zipfile.ZipFile(ghost_jar, 'w') as zf:
        zf.writestr("a.class", create_class([
            "java/lang/reflect/Method", "java/lang/reflect/Field",
            "getDeclaredMethod", "setAccessible", "invoke",
            "sendPacket", "attackEntity", "isOnGround",
            "setMotion", "getMotion", "moveFlying",
            "sun/misc/Unsafe",
            base64.b64encode(b"killaura_config_v4").decode(),
        ]))
        zf.writestr("b.class", create_class([
            "processPacket", "channelRead0",
            "io/netty/channel/ChannelHandlerContext",
            "net/minecraft/network/NetworkManager",
        ]))
        zf.writestr("fabric.mod.json", json.dumps({
            "id": "perf-tweaks", "name": "Performance Tweaks", "version": "1.2"
        }))

    # Also drop a clean mod
    clean_jar = os.path.join(mods_dir, "sodium-fabric-0.5.3.jar")
    with zipfile.ZipFile(clean_jar, 'w') as zf:
        zf.writestr("me/jellysquid/sodium/Main.class", create_class([
            "me/jellysquid/mods/sodium/SodiumMod",
            "Initializing Sodium"
        ]))
        zf.writestr("fabric.mod.json", json.dumps({
            "id": "sodium", "name": "Sodium", "version": "0.5.3"
        }))

    # Drop cheat config files
    with open(os.path.join(config_dir, "modules.json"), 'w') as f:
        json.dump({"killaura": {"enabled": True, "range": 4.5},
                    "velocity": {"horizontal": 90}}, f)

    with open(os.path.join(config_dir, "friends.json"), 'w') as f:
        json.dump({"friends": ["player1", "player2"]}, f)

    # Drop cheat log
    with open(os.path.join(logs_dir, "latest.log"), 'w') as f:
        f.write("[INFO] Wurst Client initialized\n[INFO] KillAura enabled\n")

    # Scan just the mods directory
    mods_scanner = ModsScanner()
    results = mods_scanner.scan_directory(mods_dir)

    cheats = [r for r in results if r.status == "CHEAT_DETECTED"]
    suspicious = [r for r in results if r.status == "SUSPICIOUS"]
    clean = [r for r in results if r.status == "CLEAN"]

    test(f"Fake .minecraft: found {len(results)} mods", len(results) == 2)
    test(f"Ghost mod detected as cheat", len(cheats) >= 1,
         f"Cheats: {len(cheats)}, Sus: {len(suspicious)}")
    test(f"Sodium still clean (no false positive)", len(clean) >= 1)

    for r in results:
        status_icon = "🔴" if r.status == "CHEAT_DETECTED" else "🟡" if r.status == "SUSPICIOUS" else "🟢"
        print(f"  {status_icon} {r.filename}: {r.status} (sev: {r.severity}, findings: {len(r.findings)})")


# ══════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print(f"  GHOST CLIENT DETECTION TEST RESULTS")
print(f"=" * 70)
print(f"  ✅ Passed: {PASS}")
print(f"  ❌ Failed: {FAIL}")
print(f"  Total:   {PASS + FAIL}")
print(f"  Rate:    {PASS / (PASS + FAIL) * 100:.1f}%")

if ERRORS:
    print(f"\n  Failed tests:")
    for e in ERRORS:
        print(f"  {e}")

print(f"{'=' * 70}")
sys.exit(0 if FAIL == 0 else 1)
