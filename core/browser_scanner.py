"""
SS-Tools Ultimate - Browser Scanner
Scans Chrome, Firefox, Edge browser data for cheat-related evidence.
History, downloads, cookies, cache, extensions, bookmarks.
"""
import os
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta

from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.utils import ScanResult, ScanProgress, logger, safe_read_file


class BrowserScanner:
    """Scans browser data for cheat-related evidence."""

    BROWSER_PATHS = {
        "Chrome": {
            "base": [
                "{LOCALAPPDATA}/Google/Chrome/User Data",
            ],
            "history": "History",
            "downloads": "History",
            "cookies": "Cookies",
            "bookmarks": "Bookmarks",
            "extensions": "Extensions",
        },
        "Edge": {
            "base": [
                "{LOCALAPPDATA}/Microsoft/Edge/User Data",
            ],
            "history": "History",
            "downloads": "History",
            "cookies": "Cookies",
            "bookmarks": "Bookmarks",
            "extensions": "Extensions",
        },
        "Firefox": {
            "base": [
                "{APPDATA}/Mozilla/Firefox/Profiles",
            ],
            "history": "places.sqlite",
            "downloads": "places.sqlite",
            "cookies": "cookies.sqlite",
            "bookmarks": "places.sqlite",
        },
        "Opera": {
            "base": [
                "{APPDATA}/Opera Software/Opera Stable",
            ],
            "history": "History",
            "downloads": "History",
            "bookmarks": "Bookmarks",
        },
        "Brave": {
            "base": [
                "{LOCALAPPDATA}/BraveSoftware/Brave-Browser/User Data",
            ],
            "history": "History",
            "downloads": "History",
            "bookmarks": "Bookmarks",
        },
    }

    def __init__(self, progress: ScanProgress = None):
        self.db = CheatDatabase()
        self.detector = KeywordDetector()
        self.progress = progress or ScanProgress()
        
        # Pornography detection keywords for Chrome history
        self.porn_keywords = {
            "pornhub", "xvideos", "xnxx", "redtube", "porn", "xxx", "sex",
            "adult", "nsfw", "18+", "nude", "naked", "explicit", "webcam",
            "cam4", "xhamster", "youporn", "spankbang", "pornographic",
            "eporner", "tube8", "xbabe", "thepornsite", "porntube",
            "beeg", "porntrex", "vporn", "efukt"
        }
        self.porn_domains = [
            "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com",
            "xhamster.com", "youporn.com", "spankbang.com", "cam4.com",
            "eporner.com", "tube8.com", "xbabe.com", "beeg.com",
            "porntrex.com", "vporn.com", "efukt.com"
        ]

    def scan(self) -> List[ScanResult]:
        """Scan all browsers for cheat evidence."""
        results = []
        browsers_found = self._find_browsers()
        total_steps = len(browsers_found) * 5  # history, downloads, bookmarks, extensions, pornography
        self.progress.start("Browser Scanner", max(total_steps, 1))

        for browser_name, profiles in browsers_found.items():
            for profile_path in profiles:
                # Scan history
                self.progress.update(f"{browser_name} history...")
                results.extend(self._scan_history(browser_name, profile_path))

                # Scan downloads
                self.progress.update(f"{browser_name} downloads...")
                results.extend(self._scan_downloads(browser_name, profile_path))

                # Scan bookmarks
                self.progress.update(f"{browser_name} bookmarks...")
                results.extend(self._scan_bookmarks(browser_name, profile_path))

                # Scan extensions
                self.progress.update(f"{browser_name} extensions...")
                results.extend(self._scan_extensions(browser_name, profile_path))
                
                # Scan for pornography in Chrome/Edge/Brave history
                if browser_name in ("Chrome", "Edge", "Brave"):
                    self.progress.update(f"{browser_name} adult content...")
                    results.extend(self._scan_pornography(browser_name, profile_path))

        return results

    def _find_browsers(self) -> Dict[str, List[Path]]:
        """Find installed browsers and their profile directories."""
        found = {}
        for browser, config in self.BROWSER_PATHS.items():
            profiles = []
            for base_template in config["base"]:
                base = self._expand_path(base_template)
                if base and base.exists():
                    if browser == "Firefox":
                        # Firefox has random profile dirs
                        for item in base.iterdir():
                            if item.is_dir():
                                profiles.append(item)
                    else:
                        # Chromium browsers: check Default and Profile N
                        default = base / "Default"
                        if default.exists():
                            profiles.append(default)
                        for i in range(1, 10):
                            prof = base / f"Profile {i}"
                            if prof.exists():
                                profiles.append(prof)
            if profiles:
                found[browser] = profiles
                logger.info(f"Found {browser}: {len(profiles)} profiles")
        return found

    def _scan_history(self, browser: str, profile: Path) -> List[ScanResult]:
        """Scan browser history for cheat URLs."""
        results = []
        config = self.BROWSER_PATHS.get(browser, {})
        history_file = config.get("history", "History")
        db_path = profile / history_file

        if not db_path.exists():
            return results

        try:
            # Copy to temp to avoid lock issues
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name
            shutil.copy2(db_path, tmp_path)

            conn = sqlite3.connect(tmp_path)
            if browser == "Firefox":
                query = "SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 5000"
            else:
                query = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 5000"

            cursor = conn.execute(query)
            for row in cursor:
                url = row[0] or ""
                title = row[1] or ""

                # Check URL against cheat database
                url_results = self.detector.scan_url(url, filepath=f"{browser}/History")
                for r in url_results:
                    r.scanner = "BrowserScanner"
                    r.details["browser"] = browser
                    r.details["title"] = title
                    r.description = f"[{browser}] {r.description}"
                results.extend(url_results)

                # Check title and URL text
                combined = f"{url} {title}"
                text_results = self.detector.scan_text(
                    combined, source="browser_history",
                    filepath=f"{browser}/History"
                )
                for r in text_results:
                    r.scanner = "BrowserScanner"
                    r.details["browser"] = browser
                    r.details["url"] = url
                    r.description = f"[{browser} History] {r.description}"
                results.extend(text_results)

            conn.close()
            os.unlink(tmp_path)
        except Exception as e:
            logger.debug(f"History scan error ({browser}): {e}")
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return results

    def _scan_downloads(self, browser: str, profile: Path) -> List[ScanResult]:
        """Scan browser downloads for cheat files."""
        results = []
        config = self.BROWSER_PATHS.get(browser, {})
        dl_file = config.get("downloads", "History")
        db_path = profile / dl_file

        if not db_path.exists():
            return results

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name
            shutil.copy2(db_path, tmp_path)

            conn = sqlite3.connect(tmp_path)
            if browser == "Firefox":
                query = """
                    SELECT mp.url, ma.content
                    FROM moz_annos ma
                    JOIN moz_places mp ON ma.place_id = mp.id
                    WHERE ma.anno_attribute_id IN (
                        SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI'
                    )
                    ORDER BY ma.dateAdded DESC LIMIT 1000
                """
            else:
                query = """
                    SELECT tab_url, target_path, total_bytes, end_time
                    FROM downloads
                    ORDER BY end_time DESC LIMIT 1000
                """

            try:
                cursor = conn.execute(query)
                for row in cursor:
                    url = row[0] or ""
                    target = row[1] or "" if len(row) > 1 else ""

                    combined = f"{url} {target}"
                    # Check URL
                    url_results = self.detector.scan_url(url, filepath=f"{browser}/Downloads")
                    for r in url_results:
                        r.scanner = "BrowserScanner"
                        r.details["browser"] = browser
                        r.details["download_path"] = target
                        r.description = f"[{browser} Download] {r.description}"
                        r.severity = min(r.severity + 10, 100)
                    results.extend(url_results)

                    # Check filename
                    if target:
                        fname = os.path.basename(target)
                        fname_results = self.detector.scan_filename(
                            fname, filepath=f"{browser}/Downloads"
                        )
                        for r in fname_results:
                            r.scanner = "BrowserScanner"
                            r.details["browser"] = browser
                            r.details["url"] = url
                            r.description = f"[{browser} Download] {r.description}"
                            r.severity = min(r.severity + 15, 100)
                        results.extend(fname_results)

                    # Text scan
                    text_results = self.detector.scan_text(
                        combined, source="browser_download",
                        filepath=f"{browser}/Downloads"
                    )
                    for r in text_results:
                        r.scanner = "BrowserScanner"
                        r.details["browser"] = browser
                    results.extend(text_results)
            except sqlite3.OperationalError:
                pass

            conn.close()
            os.unlink(tmp_path)
        except Exception as e:
            logger.debug(f"Downloads scan error ({browser}): {e}")
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return results

    def _scan_bookmarks(self, browser: str, profile: Path) -> List[ScanResult]:
        """Scan browser bookmarks for cheat URLs."""
        results = []
        config = self.BROWSER_PATHS.get(browser, {})

        if browser == "Firefox":
            return self._scan_firefox_bookmarks(profile)

        bookmarks_file = profile / config.get("bookmarks", "Bookmarks")
        if not bookmarks_file.exists():
            return results

        try:
            content = safe_read_file(str(bookmarks_file))
            if content:
                data = json.loads(content)
                urls = self._extract_chromium_bookmarks(data)
                for url, title in urls:
                    url_results = self.detector.scan_url(url, filepath=f"{browser}/Bookmarks")
                    for r in url_results:
                        r.scanner = "BrowserScanner"
                        r.details["browser"] = browser
                        r.details["title"] = title
                        r.description = f"[{browser} Bookmark] {r.description}"
                    results.extend(url_results)
        except Exception as e:
            logger.debug(f"Bookmarks scan error ({browser}): {e}")

        return results

    def _extract_chromium_bookmarks(self, data: dict, urls: list = None) -> List[tuple]:
        """Recursively extract URLs from Chromium bookmarks JSON."""
        if urls is None:
            urls = []
        if isinstance(data, dict):
            if data.get("type") == "url":
                urls.append((data.get("url", ""), data.get("name", "")))
            for key, val in data.items():
                if isinstance(val, (dict, list)):
                    self._extract_chromium_bookmarks(val, urls)
        elif isinstance(data, list):
            for item in data:
                self._extract_chromium_bookmarks(item, urls)
        return urls

    def _scan_firefox_bookmarks(self, profile: Path) -> List[ScanResult]:
        """Scan Firefox bookmarks from places.sqlite."""
        results = []
        db_path = profile / "places.sqlite"
        if not db_path.exists():
            return results

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name
            shutil.copy2(db_path, tmp_path)

            conn = sqlite3.connect(tmp_path)
            cursor = conn.execute("""
                SELECT mp.url, mb.title
                FROM moz_bookmarks mb
                JOIN moz_places mp ON mb.fk = mp.id
                WHERE mp.url IS NOT NULL
                LIMIT 2000
            """)
            for row in cursor:
                url = row[0] or ""
                title = row[1] or ""
                url_results = self.detector.scan_url(url, filepath="Firefox/Bookmarks")
                for r in url_results:
                    r.scanner = "BrowserScanner"
                    r.details["browser"] = "Firefox"
                    r.details["title"] = title
                    r.description = f"[Firefox Bookmark] {r.description}"
                results.extend(url_results)

            conn.close()
            os.unlink(tmp_path)
        except Exception as e:
            logger.debug(f"Firefox bookmarks error: {e}")
        return results

    def _scan_extensions(self, browser: str, profile: Path) -> List[ScanResult]:
        """Scan browser extensions for suspicious ones."""
        results = []
        if browser == "Firefox":
            return self._scan_firefox_extensions(profile)

        ext_dir = profile / "Extensions"
        if not ext_dir.exists():
            return results

        try:
            for ext_folder in ext_dir.iterdir():
                if ext_folder.is_dir():
                    # Check manifest.json
                    for version_dir in ext_folder.iterdir():
                        manifest = version_dir / "manifest.json"
                        if manifest.exists():
                            content = safe_read_file(str(manifest))
                            if content:
                                try:
                                    mdata = json.loads(content)
                                    ext_name = mdata.get("name", "")
                                    ext_desc = mdata.get("description", "")
                                    combined = f"{ext_name} {ext_desc}"
                                    text_results = self.detector.scan_text(
                                        combined, source="extension",
                                        filepath=str(manifest)
                                    )
                                    for r in text_results:
                                        r.scanner = "BrowserScanner"
                                        r.details["browser"] = browser
                                        r.details["extension"] = ext_name
                                        r.description = f"[{browser} Extension] {r.description}"
                                    results.extend(text_results)
                                except json.JSONDecodeError:
                                    pass
        except Exception as e:
            logger.debug(f"Extensions scan error ({browser}): {e}")

        return results

    def _scan_firefox_extensions(self, profile: Path) -> List[ScanResult]:
        """Scan Firefox extensions."""
        results = []
        ext_file = profile / "extensions.json"
        if ext_file.exists():
            try:
                content = safe_read_file(str(ext_file))
                if content:
                    data = json.loads(content)
                    for addon in data.get("addons", []):
                        name = addon.get("name", "")
                        desc = addon.get("description", "")
                        combined = f"{name} {desc}"
                        text_results = self.detector.scan_text(
                            combined, source="firefox_extension",
                            filepath=str(ext_file)
                        )
                        for r in text_results:
                            r.scanner = "BrowserScanner"
                            r.details["browser"] = "Firefox"
                            r.details["extension"] = name
                        results.extend(text_results)
            except Exception as e:
                logger.debug(f"Firefox extensions error: {e}")
        return results

    def _scan_pornography(self, browser: str, profile: Path) -> List[ScanResult]:
        """Scan browser history for adult/pornography content."""
        results = []
        history_file = self.BROWSER_PATHS.get(browser, {}).get("history", "History")
        db_path = profile / history_file

        if not db_path.exists():
            return results

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name
            shutil.copy2(db_path, tmp_path)

            conn = sqlite3.connect(tmp_path)
            query = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 5000"
            
            cursor = conn.execute(query)
            for row in cursor:
                url = (row[0] or "").lower()
                title = (row[1] or "").lower()
                
                # Check for pornography domains and keywords
                is_porn = False
                porn_type = ""
                
                for domain in self.porn_domains:
                    if domain in url:
                        is_porn = True
                        porn_type = domain.split(".")[0].capitalize()
                        break
                
                if not is_porn:
                    for keyword in self.porn_keywords:
                        if keyword in url or keyword in title:
                            is_porn = True
                            porn_type = keyword.capitalize()
                            break
                
                if is_porn:
                    results.append(ScanResult(
                        scanner="BrowserScanner",
                        category="adult_content",
                        name=f"{browser} Adult Content",
                        description=f"[{browser}] Adult/Pornography site visited: {porn_type}",
                        severity=40,  # Lower severity for adult content
                        filepath=str(profile),
                        evidence=f"URL: {url[:100]}...",
                        details={
                            "browser": browser,
                            "url": url,
                            "type": porn_type,
                            "title": title[:100]
                        }
                    ))
            
            conn.close()
            os.unlink(tmp_path)
        except Exception as e:
            logger.debug(f"Pornography scan error ({browser}): {e}")
            try:
                os.unlink(tmp_path)
            except:
                pass

        return results

    @staticmethod
    def _expand_path(template: str) -> Optional[Path]:
        """Expand environment variable path template."""
        replacements = {
            "{LOCALAPPDATA}": os.environ.get("LOCALAPPDATA", ""),
            "{APPDATA}": os.environ.get("APPDATA", ""),
            "{USERPROFILE}": os.environ.get("USERPROFILE", ""),
            "{HOME}": str(Path.home()),
        }
        result = template
        for key, value in replacements.items():
            result = result.replace(key, value)
        p = Path(result)
        return p if p.exists() else None
