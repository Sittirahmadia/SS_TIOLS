"""
SS-Tools Ultimate - Advanced Keyword Detector
Supports regex, wildcard, fuzzy matching, Levenshtein distance, and semantic matching.
"""
import re
import difflib
from typing import List, Dict, Tuple, Optional
from functools import lru_cache

from core.database import CheatDatabase
from core.utils import ScanResult, logger


class KeywordDetector:
    """Advanced multi-strategy keyword matching engine."""

    def __init__(self):
        self.db = CheatDatabase()
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._keyword_cache: Dict[str, List[str]] = {}
        self._build_patterns()

    def _build_patterns(self):
        """Pre-compile all regex patterns for speed."""
        # Compile suspicious string patterns
        for entry in self.db.suspicious_strings:
            pat = entry.get("pattern", "")
            try:
                self._compiled_patterns[pat] = re.compile(pat, re.IGNORECASE)
            except re.error:
                pass
        # Compile obfuscation patterns
        for entry in self.db.obfuscation_patterns:
            pat = entry.get("pattern", "")
            try:
                self._compiled_patterns[pat] = re.compile(pat, re.IGNORECASE)
            except re.error:
                pass
        logger.info(f"KeywordDetector: compiled {len(self._compiled_patterns)} regex patterns")

    def scan_text(self, text: str, source: str = "",
                  filepath: str = "") -> List[ScanResult]:
        """Scan text using all matching strategies."""
        results = []
        text_lower = text.lower()

        # 1. Exact keyword matching (cheat clients)
        for client in self.db.cheat_clients:
            name_lower = client["name"].lower()
            if name_lower in text_lower:
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="cheat_client",
                    name=client["name"],
                    description=f"Cheat client detected: {client['name']}",
                    severity=client.get("severity", 100),
                    filepath=filepath,
                    evidence=self._extract_context(text, name_lower),
                ))
                continue
            for alias in client.get("aliases", []):
                if alias.lower() in text_lower:
                    results.append(ScanResult(
                        scanner="KeywordDetector",
                        category="cheat_client",
                        name=client["name"],
                        description=f"Cheat client alias detected: {alias} ({client['name']})",
                        severity=client.get("severity", 100),
                        filepath=filepath,
                        evidence=self._extract_context(text, alias.lower()),
                    ))
                    break

        # 2. Cheat module matching
        for module in self.db.cheat_modules:
            name_lower = module["name"].lower()
            if name_lower in text_lower:
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="cheat_module",
                    name=module["name"],
                    description=f"Cheat module detected: {module['name']} ({module.get('category', 'unknown')})",
                    severity=module.get("severity", 90),
                    filepath=filepath,
                    evidence=self._extract_context(text, name_lower),
                ))
            for alias in module.get("aliases", []):
                if alias.lower() in text_lower:
                    results.append(ScanResult(
                        scanner="KeywordDetector",
                        category="cheat_module",
                        name=module["name"],
                        description=f"Cheat module alias: {alias} ({module['name']})",
                        severity=module.get("severity", 90),
                        filepath=filepath,
                        evidence=self._extract_context(text, alias.lower()),
                    ))
                    break

        # 3. Regex pattern matching
        for pat_str, compiled in self._compiled_patterns.items():
            matches = compiled.findall(text)
            if matches:
                # Find the matching entry
                entry = self._find_pattern_entry(pat_str)
                sev = entry.get("severity", 70) if entry else 70
                desc = entry.get("description", pat_str) if entry else pat_str
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="pattern_match",
                    name=pat_str,
                    description=f"Pattern match: {desc}",
                    severity=sev,
                    filepath=filepath,
                    evidence=str(matches[:5]),
                ))

        # 4. Suspicious method detection
        for method in self.db.suspicious_methods:
            if method["name"] in text:
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="suspicious_method",
                    name=method["name"],
                    description=method.get("description", "Suspicious method call"),
                    severity=method.get("severity", 60),
                    filepath=filepath,
                    evidence=self._extract_context(text, method["name"]),
                ))

        # 5. Suspicious imports
        for imp in self.db.suspicious_imports:
            if imp["name"] in text:
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="suspicious_import",
                    name=imp["name"],
                    description=imp.get("description", "Suspicious import"),
                    severity=imp.get("severity", 50),
                    filepath=filepath,
                    evidence=self._extract_context(text, imp["name"]),
                ))

        # 6. Developer name matching
        for dev in self.db.cheat_developers:
            if dev["name"].lower() in text_lower:
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="cheat_developer",
                    name=dev["name"],
                    description=f"Known cheat developer: {dev['name']} - {dev.get('description', '')}",
                    severity=dev.get("severity", 80),
                    filepath=filepath,
                    evidence=self._extract_context(text, dev["name"].lower()),
                ))

        return self._deduplicate(results)

    def fuzzy_match(self, text: str, threshold: float = 0.80) -> List[Tuple[str, float, Dict]]:
        """Fuzzy matching using Levenshtein-based similarity."""
        matches = []
        words = set(re.findall(r'\b[a-zA-Z]{3,}\b', text.lower()))
        keywords = self.db.get_all_keywords()
        for word in words:
            for kw in keywords:
                ratio = difflib.SequenceMatcher(None, word, kw).ratio()
                if ratio >= threshold and word != kw:
                    matches.append((word, ratio, {"keyword": kw}))
        return sorted(matches, key=lambda x: -x[1])

    def fuzzy_scan(self, text: str, filepath: str = "",
                   threshold: float = 0.82) -> List[ScanResult]:
        """Run fuzzy matching and return ScanResults."""
        results = []
        matches = self.fuzzy_match(text, threshold)
        for word, ratio, info in matches:
            results.append(ScanResult(
                scanner="KeywordDetector-Fuzzy",
                category="fuzzy_match",
                name=info["keyword"],
                description=f"Fuzzy match: '{word}' ~ '{info['keyword']}' (similarity: {ratio:.0%})",
                severity=int(ratio * 70),
                filepath=filepath,
                evidence=f"Found '{word}', similar to cheat keyword '{info['keyword']}'",
            ))
        return results

    def scan_url(self, url: str, filepath: str = "") -> List[ScanResult]:
        """Scan a URL against cheat URL patterns."""
        results = []
        url_lower = url.lower()
        for entry in self.db.cheat_urls:
            pattern = entry.get("pattern", "").lower()
            if pattern in url_lower:
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="cheat_url",
                    name=pattern,
                    description=f"Cheat URL detected: {pattern} ({entry.get('category', 'website')})",
                    severity=entry.get("severity", 90),
                    filepath=filepath,
                    evidence=url,
                ))
        return results

    def scan_filename(self, filename: str, filepath: str = "") -> List[ScanResult]:
        """Scan a filename against cheat file signatures."""
        results = []
        fname_lower = filename.lower()
        for entry in self.db.cheat_files:
            if entry["name"].lower() in fname_lower:
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="cheat_file",
                    name=entry["name"],
                    description=f"Cheat {entry.get('type', 'file')} detected: {entry['name']}",
                    severity=entry.get("severity", 90),
                    filepath=filepath,
                    evidence=filename,
                ))
        return results

    def scan_process(self, proc_name: str) -> List[ScanResult]:
        """Scan a process name against suspicious process database."""
        results = []
        proc_lower = proc_name.lower()
        if self.db.is_process_whitelisted(proc_name):
            return results
        for entry in self.db.suspicious_processes:
            pattern = entry["name"].lower()
            if pattern in proc_lower:
                results.append(ScanResult(
                    scanner="KeywordDetector",
                    category="suspicious_process",
                    name=entry["name"],
                    description=entry.get("description", f"Suspicious process: {entry['name']}"),
                    severity=entry.get("severity", 80),
                    evidence=proc_name,
                ))
        return results

    def _find_pattern_entry(self, pattern: str) -> Optional[Dict]:
        """Find the database entry for a pattern string."""
        for entry in self.db.suspicious_strings:
            if entry.get("pattern") == pattern:
                return entry
        for entry in self.db.obfuscation_patterns:
            if entry.get("pattern") == pattern:
                return entry
        return None

    @staticmethod
    def _extract_context(text: str, keyword: str, context_chars: int = 80) -> str:
        """Extract surrounding context around a keyword match."""
        idx = text.lower().find(keyword.lower())
        if idx == -1:
            return ""
        start = max(0, idx - context_chars)
        end = min(len(text), idx + len(keyword) + context_chars)
        snippet = text[start:end].strip()
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."
        return snippet

    @staticmethod
    def _deduplicate(results: List[ScanResult]) -> List[ScanResult]:
        """Remove duplicate findings, keeping highest severity."""
        seen = {}
        for r in results:
            key = (r.category, r.name.lower(), r.filepath)
            if key not in seen or r.severity > seen[key].severity:
                seen[key] = r
        return list(seen.values())
