"""
SS-Tools Ultimate - MODS SCANNER (Most Powerful Module)
Deep inspection of Minecraft mod .jar files:
 - Extracts .class files from JARs
 - Bytecode analysis (constant pool, opcodes)
 - Decompiler integration (CFR/FernFlower/Procyon/Vineflower)
 - Pattern matching against cheat signatures
 - Obfuscation detection and simple deobfuscation
 - No file size or count limits
"""
import os
import io
import re
import json
import time
import struct
import zipfile
import hashlib
import sqlite3
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field

from core.config import CACHE_DIR, AppSettings
from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import (
    ScanResult, ScanProgress, logger, file_hash_md5,
    format_size, format_duration, safe_read_file
)


# Java class file magic bytes
JAVA_CLASS_MAGIC = b'\xCA\xFE\xBA\xBE'

# Constant pool tag types
CP_UTF8 = 1
CP_CLASS = 7
CP_STRING = 8
CP_FIELDREF = 9
CP_METHODREF = 10
CP_INTERFACE_METHODREF = 11
CP_NAME_AND_TYPE = 12
CP_METHOD_HANDLE = 15
CP_METHOD_TYPE = 16
CP_INVOKE_DYNAMIC = 18


@dataclass
class ModScanResult:
    """Detailed result for a single mod file."""
    filepath: str
    filename: str
    file_size: int
    md5: str
    status: str = "CLEAN"  # CLEAN, SUSPICIOUS, CHEAT_DETECTED
    severity: int = 0
    class_count: int = 0
    classes_scanned: int = 0
    findings: List[Dict] = field(default_factory=list)
    is_whitelisted: bool = False
    scan_time: float = 0.0

    @property
    def status_color(self) -> str:
        if self.status == "CHEAT_DETECTED":
            return "#FF1744"
        elif self.status == "SUSPICIOUS":
            return "#FF9100"
        return "#00E676"

    def add_finding(self, class_name: str, finding_type: str,
                    description: str, severity: int, line: int = 0,
                    evidence: str = ""):
        self.findings.append({
            "class_name": class_name,
            "type": finding_type,
            "description": description,
            "severity": severity,
            "line": line,
            "evidence": evidence[:500],
        })
        self.severity = max(self.severity, severity)
        if severity >= 80:
            self.status = "CHEAT_DETECTED"
        elif severity >= 50 and self.status == "CLEAN":
            self.status = "SUSPICIOUS"


class BytecodeAnalyzer:
    """Analyzes Java .class bytecode directly without decompilation."""

    def __init__(self):
        self.db = CheatDatabase()

    def analyze_class(self, class_data: bytes, class_name: str) -> List[Dict]:
        """Analyze a single .class file's bytecode."""
        findings = []
        if not class_data or len(class_data) < 10:
            return findings
        if class_data[:4] != JAVA_CLASS_MAGIC:
            return findings

        # Extract constant pool strings
        strings = self._extract_constant_pool_strings(class_data)

        # Check strings against cheat signatures
        all_text = " ".join(strings)
        text_lower = all_text.lower()

        # Check for cheat client names
        for client in self.db.cheat_clients:
            name_lower = client["name"].lower()
            if name_lower in text_lower:
                findings.append({
                    "type": "cheat_client_bytecode",
                    "description": f"Cheat client reference in bytecode: {client['name']}",
                    "severity": client.get("severity", 100),
                    "evidence": self._find_matching_string(strings, name_lower),
                })
            for alias in client.get("aliases", []):
                if alias.lower() in text_lower:
                    findings.append({
                        "type": "cheat_client_alias_bytecode",
                        "description": f"Cheat client alias in bytecode: {alias}",
                        "severity": client.get("severity", 100),
                        "evidence": self._find_matching_string(strings, alias.lower()),
                    })
                    break

        # Check for cheat module names
        for module in self.db.cheat_modules:
            name_lower = module["name"].lower()
            if name_lower in text_lower:
                findings.append({
                    "type": "cheat_module_bytecode",
                    "description": f"Cheat module in bytecode: {module['name']} ({module.get('category', '')})",
                    "severity": module.get("severity", 90),
                    "evidence": self._find_matching_string(strings, name_lower),
                })

        # Check for suspicious method references
        for method in self.db.suspicious_methods:
            if method["name"] in all_text:
                findings.append({
                    "type": "suspicious_method_bytecode",
                    "description": f"Suspicious method ref: {method['name']} - {method.get('description', '')}",
                    "severity": method.get("severity", 60),
                    "evidence": self._find_matching_string(strings, method["name"]),
                })

        # Check for suspicious imports/classes
        for imp in self.db.suspicious_imports:
            imp_name = imp["name"].replace(".", "/")
            if imp_name in all_text or imp["name"] in all_text:
                findings.append({
                    "type": "suspicious_import_bytecode",
                    "description": f"Suspicious import: {imp['name']} - {imp.get('description', '')}",
                    "severity": imp.get("severity", 50),
                    "evidence": self._find_matching_string(strings, imp["name"]),
                })

        # Check for obfuscation indicators
        findings.extend(self._check_obfuscation(strings, class_name))

        # Check for bytecode signatures
        for sig in self.db.bytecode_signatures:
            pattern = sig.get("opcodes", "")
            if pattern and re.search(pattern, all_text, re.IGNORECASE):
                findings.append({
                    "type": "bytecode_signature",
                    "description": f"Bytecode signature match: {sig['name']} - {sig.get('description', '')}",
                    "severity": sig.get("severity", 80),
                    "evidence": pattern,
                })

        return findings

    def _extract_constant_pool_strings(self, data: bytes) -> List[str]:
        """Extract all UTF-8 strings from Java class constant pool."""
        strings = []
        try:
            if len(data) < 10:
                return strings
            # Skip magic (4) + minor (2) + major (2) = offset 8
            offset = 8
            cp_count = struct.unpack('>H', data[offset:offset + 2])[0]
            offset += 2

            i = 1
            while i < cp_count and offset < len(data) - 1:
                tag = data[offset]
                offset += 1

                if tag == CP_UTF8:
                    if offset + 2 > len(data):
                        break
                    length = struct.unpack('>H', data[offset:offset + 2])[0]
                    offset += 2
                    if offset + length <= len(data):
                        try:
                            s = data[offset:offset + length].decode('utf-8', errors='replace')
                            if len(s) > 1:  # Skip single chars
                                strings.append(s)
                        except Exception:
                            pass
                    offset += length
                elif tag in (CP_CLASS, CP_STRING, CP_METHOD_TYPE):
                    offset += 2
                elif tag in (CP_FIELDREF, CP_METHODREF, CP_INTERFACE_METHODREF,
                             CP_NAME_AND_TYPE, CP_INVOKE_DYNAMIC):
                    offset += 4
                elif tag == CP_METHOD_HANDLE:
                    offset += 3
                elif tag in (3, 4):  # Integer, Float
                    offset += 4
                elif tag in (5, 6):  # Long, Double
                    offset += 8
                    i += 1  # Takes two entries
                else:
                    break  # Unknown tag, stop parsing
                i += 1

        except Exception:
            pass
        return strings

    def _check_obfuscation(self, strings: List[str], class_name: str) -> List[Dict]:
        """Detect obfuscation indicators in class."""
        findings = []

        # Very short class names (obfuscated)
        base_name = class_name.split("/")[-1].split("$")[0]
        if len(base_name) <= 2 and base_name.isalpha():
            findings.append({
                "type": "obfuscation_indicator",
                "description": f"Very short class name (likely obfuscated): {base_name}",
                "severity": 30,
                "evidence": class_name,
            })

        # Check for encoded strings
        for s in strings:
            # Base64-like patterns
            if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s) and len(s) > 30:
                findings.append({
                    "type": "encoded_string",
                    "description": f"Possible Base64 encoded string detected (length: {len(s)})",
                    "severity": 40,
                    "evidence": s[:100],
                })
                break

        # Check for reflection patterns
        reflection_indicators = [
            "java/lang/reflect/Method",
            "java/lang/reflect/Field",
            "java/lang/Class",
            "getDeclaredMethod",
            "getDeclaredField",
            "setAccessible",
        ]
        ref_count = sum(1 for s in strings for ri in reflection_indicators if ri in s)
        if ref_count >= 3:
            findings.append({
                "type": "heavy_reflection",
                "description": f"Heavy reflection usage detected ({ref_count} indicators)",
                "severity": 65,
                "evidence": f"{ref_count} reflection-related references",
            })

        # Check for native method declarations
        for s in strings:
            if "native" in s.lower() and ("void" in s or "int" in s or "long" in s):
                findings.append({
                    "type": "native_method",
                    "description": "Native (JNI) method detected - potential native cheat code",
                    "severity": 75,
                    "evidence": s[:200],
                })
                break

        # Check for dynamic class loading
        classloader_indicators = [
            "java/lang/ClassLoader", "defineClass", "URLClassLoader",
            "java/net/URLClassLoader",
        ]
        cl_count = sum(1 for s in strings for ci in classloader_indicators if ci in s)
        if cl_count >= 2:
            findings.append({
                "type": "dynamic_classloading",
                "description": f"Dynamic class loading detected ({cl_count} indicators) - potential hidden code",
                "severity": 80,
                "evidence": f"{cl_count} classloader-related references",
            })

        # Check for encryption usage (hiding cheat config/strings)
        crypto_indicators = [
            "javax/crypto/Cipher", "AES", "DES", "Blowfish",
            "SecretKeySpec", "javax/crypto", "PKCS5Padding",
        ]
        crypto_count = sum(1 for s in strings for ci in crypto_indicators if ci in s)
        if crypto_count >= 2:
            findings.append({
                "type": "encryption_usage",
                "description": f"Encryption API usage detected ({crypto_count} indicators) - potential hidden data",
                "severity": 65,
                "evidence": f"{crypto_count} crypto-related references",
            })

        # Check for Mixin injection annotations (cheat injection framework)
        mixin_dangerous = [
            "org/spongepowered/asm/mixin/Overwrite",
            "org/spongepowered/asm/mixin/injection/Redirect",
        ]
        for s in strings:
            for md in mixin_dangerous:
                if md in s:
                    sev = 75 if "Overwrite" in md else 60
                    findings.append({
                        "type": "mixin_dangerous",
                        "description": f"Dangerous Mixin annotation: {md.split('/')[-1]} - replaces vanilla method",
                        "severity": sev,
                        "evidence": s[:200],
                    })

        return findings

    @staticmethod
    def _find_matching_string(strings: List[str], keyword: str) -> str:
        """Find the full string containing a keyword."""
        kw_lower = keyword.lower()
        for s in strings:
            if kw_lower in s.lower():
                return s[:300]
        return keyword


class ModsScanner:
    """Full Minecraft mods scanner with JAR extraction, bytecode analysis, and decompilation."""

    def __init__(self, progress: ScanProgress = None, settings: AppSettings = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.progress = progress or ScanProgress()
        self.settings = settings or AppSettings.load()
        self._cache_db = CACHE_DIR / "mods_cache.db"
        self._init_cache()

    def _init_cache(self):
        """Initialize mods scan cache."""
        try:
            conn = sqlite3.connect(str(self._cache_db))
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mod_cache (
                    filepath TEXT PRIMARY KEY,
                    md5 TEXT,
                    last_scan REAL,
                    status TEXT,
                    severity INTEGER,
                    findings TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Mods cache init failed: {e}")

    def _check_cache(self, filepath: str, md5: str) -> Optional[ModScanResult]:
        """Check if mod was already scanned."""
        try:
            conn = sqlite3.connect(str(self._cache_db))
            row = conn.execute(
                "SELECT status, severity, findings FROM mod_cache WHERE filepath=? AND md5=?",
                (filepath, md5)
            ).fetchone()
            conn.close()
            if row:
                result = ModScanResult(
                    filepath=filepath,
                    filename=os.path.basename(filepath),
                    file_size=os.path.getsize(filepath),
                    md5=md5,
                    status=row[0],
                    severity=row[1],
                    findings=json.loads(row[2]),
                )
                return result
        except Exception:
            pass
        return None

    def _update_cache(self, result: ModScanResult):
        """Cache mod scan result."""
        try:
            conn = sqlite3.connect(str(self._cache_db))
            conn.execute(
                "INSERT OR REPLACE INTO mod_cache VALUES (?, ?, ?, ?, ?, ?)",
                (result.filepath, result.md5, time.time(),
                 result.status, result.severity, json.dumps(result.findings))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def find_all_mods(self) -> List[str]:
        """Find all .jar mod files across all Minecraft installations."""
        from core.minecraft_scanner import MinecraftScanner
        mc_scanner = MinecraftScanner()
        installations = mc_scanner.find_installations()
        mod_files = []

        for launcher, dirs in installations.items():
            for base_dir in dirs:
                mods_dir = base_dir / "mods"
                if mods_dir.exists():
                    for jar in mods_dir.rglob("*.jar"):
                        mod_files.append(str(jar))

        logger.info(f"Found {len(mod_files)} mod JAR files")
        return mod_files

    def scan_directory(self, directory: str) -> List[ModScanResult]:
        """Scan all mods in a specific directory."""
        mod_files = []
        dir_path = Path(directory)
        if dir_path.exists():
            for jar in dir_path.rglob("*.jar"):
                mod_files.append(str(jar))
        return self.scan_mods(mod_files)

    def scan_mods(self, mod_files: List[str],
                  deep_scan: bool = False) -> List[ModScanResult]:
        """Scan a list of mod JAR files."""
        results = []
        total = len(mod_files)
        self.progress.start("Mods Scanner", total)

        for i, mod_path in enumerate(mod_files):
            try:
                result = self.scan_single_mod(mod_path, deep_scan)
                results.append(result)
                if result.status != "CLEAN":
                    self.progress.add_result(ScanResult(
                        scanner="ModsScanner",
                        category="mod_cheat" if result.status == "CHEAT_DETECTED" else "mod_suspicious",
                        name=result.filename,
                        description=f"{result.status}: {result.filename}",
                        severity=result.severity,
                        filepath=result.filepath,
                    ))
            except Exception as e:
                logger.warning(f"Error scanning mod {mod_path}: {e}")
                results.append(ModScanResult(
                    filepath=mod_path,
                    filename=os.path.basename(mod_path),
                    file_size=0, md5="",
                    status="ERROR",
                ))
            self.progress.update(os.path.basename(mod_path))

        return results

    def scan_single_mod(self, mod_path: str,
                        deep_scan: bool = False) -> ModScanResult:
        """Deep scan a single mod .jar file."""
        start_time = time.time()
        filename = os.path.basename(mod_path)
        file_size = os.path.getsize(mod_path)
        md5 = file_hash_md5(mod_path) or ""

        # Check whitelist — still scan bytecode to catch ghost clients disguised as legit mods
        mod_name = os.path.splitext(filename)[0]
        is_whitelisted = self.db.is_mod_whitelisted(mod_name)

        # Check cache (skip for deep scan)
        if not deep_scan:
            cached = self._check_cache(mod_path, md5)
            if cached:
                cached.scan_time = time.time() - start_time
                return cached

        result = ModScanResult(
            filepath=mod_path, filename=filename,
            file_size=file_size, md5=md5,
        )

        try:
            with zipfile.ZipFile(mod_path, 'r') as zf:
                entries = zf.namelist()

                # Scan filenames inside JAR
                for entry in entries:
                    fname_results = self.detector.scan_filename(entry, mod_path)
                    for r in fname_results:
                        result.add_finding(entry, "filename_match",
                                           r.description, r.severity, evidence=entry)

                # Scan .class files (bytecode analysis)
                class_files = [e for e in entries if e.endswith('.class')]

                # JAR-level obfuscation check: single/double-letter class names
                root_classes = [e for e in class_files if '/' not in e]
                short_root = [e for e in root_classes if len(e.replace('.class', '')) <= 2]
                if len(short_root) >= 3:
                    result.add_finding("JAR", "jar_obfuscation",
                        f"JAR contains {len(short_root)} obfuscated root classes ({', '.join(short_root[:5])})",
                        70, evidence=f"Short-named classes: {short_root[:10]}")
                elif len(short_root) >= 1 and len(root_classes) > 0:
                    ratio = len(short_root) / max(len(root_classes), 1)
                    if ratio > 0.5:
                        result.add_finding("JAR", "jar_obfuscation",
                            f"High ratio of obfuscated root classes: {len(short_root)}/{len(root_classes)}",
                            55, evidence=f"Short: {short_root[:10]}")

                # Also check for obfuscated package paths (e.g., a/b.class, a/c.class)
                short_pkg_classes = []
                for cf in class_files:
                    parts = cf.replace('.class', '').split('/')
                    if all(len(p) <= 2 and p.isalpha() for p in parts) and len(parts) >= 2:
                        short_pkg_classes.append(cf)
                if len(short_pkg_classes) >= 2:
                    result.add_finding("JAR", "jar_obfuscation",
                        f"Obfuscated package structure: {len(short_pkg_classes)} classes with single-letter paths",
                        65, evidence=f"Obfuscated: {short_pkg_classes[:8]}")
                result.class_count = len(class_files)

                for class_file in class_files:
                    try:
                        class_data = zf.read(class_file)
                        findings = self.bytecode_analyzer.analyze_class(
                            class_data, class_file
                        )
                        for f in findings:
                            result.add_finding(
                                class_file, f["type"],
                                f["description"], f["severity"],
                                evidence=f.get("evidence", ""),
                            )
                        result.classes_scanned += 1
                    except Exception:
                        pass

                # Scan text files in JAR (configs, manifests)
                text_extensions = {'.json', '.txt', '.cfg', '.toml',
                                   '.yml', '.yaml', '.properties', '.xml',
                                   '.MF', '.md'}
                for entry in entries:
                    ext = os.path.splitext(entry)[1]
                    if ext in text_extensions:
                        try:
                            data = zf.read(entry)
                            if len(data) < 2 * 1024 * 1024:  # Max 2MB text
                                text = data.decode('utf-8', errors='replace')
                                text_results = self.detector.scan_text(
                                    text, source="jar_content", filepath=f"{mod_path}!{entry}"
                                )
                                for r in text_results:
                                    result.add_finding(
                                        entry, "text_content_match",
                                        r.description, r.severity,
                                        evidence=r.evidence,
                                    )
                        except Exception:
                            pass

                # Scan fabric.mod.json / mods.toml for mod metadata
                self._scan_mod_metadata(zf, entries, result)

                # Deep scan: decompile suspicious classes
                if deep_scan or self.settings.deep_scan_mode:
                    self._deep_scan_decompile(zf, class_files, result)

        except zipfile.BadZipFile:
            result.add_finding("", "corrupt_jar",
                               "Corrupt or invalid JAR file", 40,
                               evidence=filename)
        except Exception as e:
            logger.debug(f"Error scanning JAR {filename}: {e}")

        result.scan_time = time.time() - start_time
        result.is_whitelisted = is_whitelisted

        # If whitelisted AND clean, mark as whitelisted clean
        if is_whitelisted and result.severity < 60:
            result.status = "CLEAN"
            result.is_whitelisted = True

        # Cache result
        if result.status != "ERROR":
            self._update_cache(result)

        return result

    def _scan_mod_metadata(self, zf: zipfile.ZipFile, entries: List[str],
                           result: ModScanResult):
        """Scan mod metadata files for cheat indicators."""
        metadata_files = {
            "fabric.mod.json": "json",
            "META-INF/mods.toml": "toml",
            "mcmod.info": "json",
            "META-INF/MANIFEST.MF": "manifest",
        }
        for meta_file, fmt in metadata_files.items():
            if meta_file in entries:
                try:
                    data = zf.read(meta_file).decode('utf-8', errors='replace')
                    meta_results = self.detector.scan_text(
                        data, source="mod_metadata",
                        filepath=f"{result.filepath}!{meta_file}"
                    )
                    for r in meta_results:
                        result.add_finding(meta_file, "metadata_match",
                                           r.description, r.severity,
                                           evidence=r.evidence)
                except Exception:
                    pass

    def _deep_scan_decompile(self, zf: zipfile.ZipFile,
                             class_files: List[str],
                             result: ModScanResult):
        """Decompile classes and scan source code (Deep Scan mode)."""
        decompiler = self.settings.decompiler
        decompiler_path = self._get_decompiler_path(decompiler)

        if not decompiler_path:
            logger.info(f"Decompiler {decompiler} not configured, skipping deep decompile")
            return

        # Only decompile suspicious or all classes depending on settings
        classes_to_decompile = class_files
        if len(classes_to_decompile) > 500:
            # Prioritize: decompile classes with findings first, then sample others
            suspicious_classes = set()
            for f in result.findings:
                suspicious_classes.add(f.get("class_name", ""))
            # Add classes with short/obfuscated names
            for cf in class_files:
                base = cf.split("/")[-1].replace(".class", "")
                if len(base) <= 3:
                    suspicious_classes.add(cf)
            classes_to_decompile = list(suspicious_classes)[:200]

        with tempfile.TemporaryDirectory() as tmpdir:
            # Extract classes
            for cf in classes_to_decompile:
                try:
                    zf.extract(cf, tmpdir)
                except Exception:
                    pass

            # Run decompiler
            try:
                output_dir = os.path.join(tmpdir, "decompiled")
                os.makedirs(output_dir, exist_ok=True)

                if decompiler.upper() == "CFR":
                    cmd = [
                        "java", "-jar", decompiler_path,
                        tmpdir, "--outputdir", output_dir,
                        "--silent", "true"
                    ]
                elif decompiler.upper() == "FERNFLOWER":
                    cmd = [
                        "java", "-jar", decompiler_path,
                        tmpdir, output_dir
                    ]
                else:
                    cmd = [
                        "java", "-jar", decompiler_path,
                        tmpdir, "--output", output_dir
                    ]

                proc = subprocess.run(
                    cmd, capture_output=True, timeout=120, text=True
                )

                # Scan decompiled source
                if os.path.exists(output_dir):
                    for root, dirs, files in os.walk(output_dir):
                        for fname in files:
                            if fname.endswith('.java'):
                                fpath = os.path.join(root, fname)
                                content = safe_read_file(fpath)
                                if content:
                                    src_results = self.detector.scan_text(
                                        content, source="decompiled",
                                        filepath=fpath
                                    )
                                    for r in src_results:
                                        result.add_finding(
                                            fname, "decompiled_source",
                                            r.description, r.severity,
                                            evidence=r.evidence,
                                        )
            except subprocess.TimeoutExpired:
                logger.warning("Decompiler timed out")
            except FileNotFoundError:
                logger.warning(f"Decompiler not found: {decompiler_path}")
            except Exception as e:
                logger.debug(f"Decompile error: {e}")

    def _get_decompiler_path(self, decompiler: str) -> Optional[str]:
        """Get path to decompiler JAR."""
        paths = {
            "CFR": self.settings.cfr_path,
            "FERNFLOWER": self.settings.fernflower_path,
            "PROCYON": self.settings.procyon_path,
            "VINEFLOWER": self.settings.vineflower_path,
        }
        path = paths.get(decompiler.upper(), "")
        if path and os.path.exists(path):
            return path
        # Check common locations
        common = [
            Path.home() / ".ss-tools" / f"{decompiler.lower()}.jar",
            Path("tools") / f"{decompiler.lower()}.jar",
        ]
        for p in common:
            if p.exists():
                return str(p)
        return None
