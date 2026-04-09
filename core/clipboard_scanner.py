"""
SS-Tools Ultimate - Clipboard Scanner
Detects suspicious content in system clipboard.
Scans: URLs, file paths, cheat client names, malicious keywords.
"""
import ctypes
import subprocess
import re
from typing import List, Optional
from pathlib import Path

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import ScanResult, ScanProgress, logger


class ClipboardScanner:
    """Scans system clipboard for suspicious content."""

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()

    def scan(self) -> List[ScanResult]:
        """Run full clipboard scan."""
        results = []
        self.progress.start("Clipboard Scanner", 1)

        try:
            self.progress.update("Reading clipboard content...")
            
            # Get clipboard content
            clipboard_content = self._get_clipboard_content()
            
            if not clipboard_content or len(clipboard_content) < 2:
                return results  # Empty clipboard

            # Analyze clipboard content
            results.extend(self._analyze_content(clipboard_content))

        except Exception as e:
            logger.warning(f"Clipboard Scanner failed: {e}")
            # Don't report error - clipboard access is optional

        return results

    def _get_clipboard_content(self) -> Optional[str]:
        """Get content from system clipboard."""
        try:
            # Try PowerShell method (most reliable)
            proc = subprocess.run(
                ["powershell", "-Command", "Get-Clipboard"],
                capture_output=True, text=True, timeout=5
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass

        # Fallback: Try xclip (Linux)
        try:
            proc = subprocess.run(
                ["xclip", "-selection", "clipboard", "-o"],
                capture_output=True, text=True, timeout=5
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            pass

        return None

    def _analyze_content(self, content: str) -> List[ScanResult]:
        """Analyze clipboard content for suspicious indicators."""
        results = []
        content_lower = content.lower()

        # Limit analysis to reasonable clipboard sizes
        if len(content) > 100000:
            content = content[:100000]
            content_lower = content.lower()

        # Check for cheat client names
        for client in self.db.cheat_clients:
            client_name = client["name"].lower()
            if client_name in content_lower:
                results.append(ScanResult(
                    scanner="ClipboardScanner",
                    category="clipboard_cheat_client",
                    name=client["name"],
                    description=f"Cheat client name in clipboard: {client['name']}",
                    severity=client.get("severity", 80),
                    evidence=f"Content contains: {client['name']}",
                    details={"client": client["name"], "content_length": len(content)}
                ))
                break  # Only report once per clipboard

        # Check for suspicious URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            # Check URL against cheat database
            url_results = self.detector.scan_url(url, filepath="clipboard")
            for r in url_results:
                r.scanner = "ClipboardScanner"
                r.category = "clipboard_url"
                r.description = f"Suspicious URL in clipboard: {r.description}"
                r.severity = min(r.severity + 10, 100)
                results.append(r)

        # Check for suspicious file paths
        path_patterns = [
            r'(?:C:|D:)\\[^\s<>"{}|\\^`\[\]]*',  # Windows paths
            r'(?:/home|/root|/tmp)/[^\s<>"{}|\\^`\[\]]*',  # Linux paths
        ]
        
        for pattern in path_patterns:
            paths = re.findall(pattern, content)
            for path in paths:
                path_lower = path.lower()
                
                # Check for suspicious path keywords
                suspicious_keywords = [
                    "cheat", "hack", "crack", "trainer", "mod",
                    "inject", "hook", "bypass", "aimbot", "esp"
                ]
                
                for keyword in suspicious_keywords:
                    if keyword in path_lower:
                        results.append(ScanResult(
                            scanner="ClipboardScanner",
                            category="clipboard_suspicious_path",
                            name="Suspicious Path",
                            description=f"Suspicious file path in clipboard: {path}",
                            severity=65,
                            evidence=f"Contains: {keyword}",
                            details={"path": path, "keyword": keyword}
                        ))
                        break

        # Check for suspicious keywords
        for keyword in self.db.suspicious_keywords[:20]:  # Limit to prevent false flags
            keyword_lower = keyword.lower()
            if len(keyword_lower) > 3 and keyword_lower in content_lower:
                # Double-check it's not a common word
                common_words = ["the", "and", "for", "with", "from", "that", "this"]
                if keyword_lower not in common_words:
                    results.append(ScanResult(
                        scanner="ClipboardScanner",
                        category="clipboard_keyword",
                        name="Suspicious Keyword",
                        description=f"Suspicious keyword in clipboard: {keyword}",
                        severity=50,
                        evidence=f"Found: {keyword}",
                        details={"keyword": keyword}
                    ))
                    break  # Only report once

        # Check for base64 encoded content (often used to hide malicious code)
        if len(content) > 20 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', content.replace('\n', '')):
            if len(content) > 50:  # Only flag longer base64 strings
                results.append(ScanResult(
                    scanner="ClipboardScanner",
                    category="clipboard_encoded",
                    name="Encoded Content",
                    description="Base64 encoded content in clipboard (may hide malicious code)",
                    severity=55,
                    evidence=f"Content appears to be Base64 encoded (length: {len(content)})",
                    details={"encoding": "base64", "content_length": len(content)}
                ))

        return results
