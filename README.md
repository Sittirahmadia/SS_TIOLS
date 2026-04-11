# Minecraft SS AntiCheat Scanner v1.0

**Production-ready Anti-Cheat Screenshare Tool for Minecraft**

A professional desktop application designed for Minecraft server staff to perform screenshare (SS) inspections. Detects all types of cheats using multi-layer detection (hash + signature + behavior + memory + bytecode analysis) with an extremely low false positive rate thanks to smart whitelisting of legitimate gaming software.

**Requires:** Windows 10/11 with Administrator privileges (auto-requests UAC elevation).

---

## Features

### 1. Cheat Signature Database
- 760+ cheat signature entries in JSON format
- Regex, wildcard, fuzzy matching, and Levenshtein distance
- Cheat clients, modules, developers, files, URLs, Discord invites
- Auto-update database from GitHub
- SHA-256 hash-based detection for known cheat executables

### 2. Minecraft Scanner (Enhanced)
- Scans all launchers: Official, TLauncher, CurseForge, MultiMC, Prism, GDLauncher, ATLauncher, HMCL, SKLauncher, Badlion, Lunar, Feather, LabyMod, etc.
- Recursively scans .minecraft directory (mods/, versions/, libraries/, shaderpacks/, resourcepacks/)
- **JVM argument scanning** - detects -javaagent, -noverify, suspicious classpath entries
- **Fabric/Forge mod list inspection** - reads fabric.mod.json and mods.toml metadata
- Multi-threaded + SQLite caching for performance
- Whitelist for legitimate vanilla mods and popular modpacks

### 3. Mods Scanner (Deep .jar Inspection)
- Extracts ALL .class files from every .jar file
- Direct bytecode analysis (constant pool, opcodes)
- Decompiler integration (CFR, FernFlower, Procyon, Vineflower)
- Detects KillAura, Reach, Flight, Speed, XRay, ESP, etc.
- Obfuscation detection, reflection analysis, native methods, mixin hooks
- No file size/count limits, cached results for repeat scans

### 4. Kernel Check (Enhanced Anti-Rootkit)
- Enumerates all loaded kernel drivers (driverquery)
- Digital signature verification for every driver
- **Minifilter (fltmc) driver scanning** for hidden file interceptors
- **SSDT hook detection** via cross-view analysis
- Database of 30+ known exploit/cheat drivers
- Hidden driver detection (cross-view WMI vs driverquery)
- Trusted signer whitelist (Microsoft, Logitech, Razer, Corsair, etc.)

### 5. Process & DLL Scanner (Enhanced)
- Full process list + loaded DLL scanning
- **SHA-256 hash matching** against known cheat executable hashes
- Gaming software whitelist (Logitech G HUB, Razer Synapse, Corsair iCUE, SteelSeries GG, etc.)
- Detects macro.exe, 198macros, ZenithMacro, AutoClicker Pro, etc.
- DLL injection detection in Java/Minecraft processes

### 6. Memory Forensic Scanner
- Scans process memory regions using Windows API (ctypes)
- Detects deleted/hidden cheat strings still in RAM
- Java agent and classpath analysis
- Targets Minecraft JVM + mouse software processes

### 7. String Deleted Scanner (Forensic)
- Recycle Bin + $Recycle.Bin + System Volume Information
- Temp folders, Prefetch files, Registry artifacts
- Windows Event Logs & USN Journal
- Recovers and analyzes file signatures even if partially deleted

### 8. Browser Scanner (Enhanced)
- Chrome, Edge, Firefox, Opera, Brave support
- Scan history, downloads, bookmarks, extensions
- Deteksi URL website cheat, forum, download link

### 8. Deleted File Detector
- Deteksi file yang baru dihapus selama sesi SS
- Monitoring Recycle Bin real-time

### 9. Memory Scanner
- Scan memory maps proses Java/Minecraft
- Deteksi injected DLL dan suspicious modules
- Deteksi Java agents

### 10. Network Scanner
- Scan koneksi aktif ke server mencurigakan
- Scan DNS cache untuk domain cheat
- Cek modifikasi hosts file

### 9. Mouse Software Scanner (Enhanced)
- Scans Logitech G Hub, Razer Synapse, Bloody/A4Tech, Corsair iCUE, SteelSeries GG
- Deep macro profile/script inspection for suspicious bindings
- **Binary scanning** of .exe/.dll files for embedded cheat strings
- Standalone macro tool detection (ZenithMacros, 198Macros, ToadClicker, etc.)
- AutoHotkey script analysis

### 10. Deleted File Scanner
- Scans Recycle Bin for recently deleted cheat files
- Monitors file deletions during SS session
- MFT/USN Journal analysis
- Sysmon log integration

### 11. Evidence Collector & Report Generator
- Automatic screenshot capture
- Process list export
- Evidence folder organization
- Professional HTML report generation

### Multi-Layer Detection
Each finding goes through up to 5 detection layers:
1. **Hash** - SHA-256 hash matching against known cheat file hashes
2. **Signature** - String/pattern signature matching from the database
3. **Behavior** - Behavioral analysis (timing patterns, injection techniques)
4. **Memory** - In-memory string scanning via Windows API
5. **Bytecode** - Java bytecode constant pool analysis for .class files

### Smart Whitelist (Zero False Positives)
Legitimate gaming software is whitelisted to prevent false flags:
- Logitech G HUB, Razer Synapse, Corsair iCUE, SteelSeries GG
- HyperX NGENUITY, Roccat Swarm, ASUS ROG Armoury Crate
- Glorious Core, BenQ Zowie, MSI Dragon Center
- Only macro **contents** are inspected, not the software itself

---

## Installation

### Requirements
- **OS:** Windows 10/11 (64-bit)
- **Python:** 3.11 or 3.12
- **RAM:** Minimum 4 GB
- **Disk:** 200 MB free space
- **Privileges:** Administrator (auto-requested via UAC)

### Install from Source

```bash
# Clone repository
git clone https://github.com/Sittirahmadia/SS_TIOLS.git
cd SS_TIOLS

# Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application (will auto-request admin)
python main.py
```

### Download .exe (Release)
Download from the [Releases](https://github.com/Sittirahmadia/SS_TIOLS/releases) page.

---

## Penggunaan

### GUI Mode (Default)
```bash
python main.py
```

### CLI Mode
```bash
# Full scan
python main.py --cli --scan full --verbose

# Mods scan saja
python main.py --cli --scan mods --deep

# Kernel check saja
python main.py --cli --scan kernel

# Export hasil ke JSON
python main.py --cli --scan full -o results.json

# Generate report HTML
python main.py --cli --scan full --report --player "PlayerName" --staff "StaffName" --server "ServerName"

# Multiple scan types
python main.py --cli --scan "mods,kernel,process"
```

### Panduan Lengkap di Dalam Aplikasi
- **Welcome Screen** muncul saat pertama kali dijalankan
- Klik tombol **📖 Panduan** di Dashboard untuk panduan lengkap
- Setiap tombol memiliki **tooltip** penjelasan

---

## Build .exe dengan PyInstaller

```bash
# Install PyInstaller
pip install pyinstaller

# Build menggunakan spec file (direkomendasikan)
pyinstaller ss_tools.spec

# Atau build manual
pyinstaller --onefile --noconsole --name "SS-Tools-Ultimate" ^
    --add-data "data/cheat_keywords.json;data" ^
    main.py

# Hasil .exe ada di folder dist/
```

---

## Update Database Cheat

### Otomatis
Database akan otomatis ter-update saat aplikasi dibuka (jika koneksi internet tersedia).
Bisa dinonaktifkan di Settings.

### Manual
```bash
# Via CLI
python main.py --update-db

# Via GUI
Settings > Update Database Now
```

### Edit Manual
File database ada di `data/cheat_keywords.json`. Format JSON yang mudah diedit.
Tambahkan entry baru sesuai kategori yang tersedia.

---

## Struktur Proyek

```
SS_TOOLS/
├── main.py                    # Entry point
├── requirements.txt           # Dependencies
├── ss_tools.spec             # PyInstaller spec
├── README.md                 # Dokumentasi
├── core/                     # Core scanner modules
│   ├── __init__.py
│   ├── config.py             # Konfigurasi aplikasi
│   ├── utils.py              # Utility functions
│   ├── database.py           # Database manager
│   ├── keyword_detector.py   # Advanced keyword matching
│   ├── minecraft_scanner.py  # Minecraft installation scanner
│   ├── mods_scanner.py       # Deep mod JAR scanner
│   ├── kernel_check.py       # Kernel driver scanner
│   ├── process_scanner.py    # Running process scanner
│   ├── string_deleted_scanner.py  # Forensic deleted strings
│   ├── browser_scanner.py    # Browser data scanner
│   ├── deleted_file_detector.py   # Recent deletion detector
│   ├── memory_scanner.py     # Process memory scanner
│   ├── network_scanner.py    # Network connection scanner
│   └── evidence_collector.py # Evidence & report generator
├── gui/                      # PyQt6 GUI
│   ├── __init__.py
│   ├── main_window.py        # Main application window
│   ├── styles.py             # Dark theme stylesheet
│   └── i18n.py               # Internationalization (ID/EN)
├── data/                     # Data files
│   └── cheat_keywords.json   # Cheat signature database (350+ entries)
└── .github/
    └── workflows/
        └── build.yml         # GitHub Actions build workflow
```

---

## Kontribusi

1. Fork repository ini
2. Buat branch fitur baru: `git checkout -b fitur-baru`
3. Commit perubahan: `git commit -m "Tambah fitur baru"`
4. Push ke branch: `git push origin fitur-baru`
5. Buat Pull Request

### Menambah Entry Database
Edit `data/cheat_keywords.json` dan tambahkan entry baru sesuai kategori:
- `cheat_clients` - Nama cheat client
- `cheat_modules` - Nama module cheat (KillAura, Fly, dll)
- `suspicious_methods` - Method Java yang mencurigakan
- `suspicious_imports` - Import Java yang mencurigakan
- `suspicious_strings` - Pattern regex string cheat
- `cheat_files` - Nama file/folder cheat
- `cheat_urls` - URL website/forum cheat
- `cheat_developers` - Nama developer cheat terkenal
- `obfuscation_patterns` - Pattern obfuscation
- `bytecode_signatures` - Signature bytecode cheat
- `kernel_driver_signatures` - Signature kernel driver exploit/cheat
- `suspicious_processes` - Nama proses mencurigakan
- `whitelist_mods` - Mod yang aman (tidak akan di-flag)
- `whitelist_processes` - Proses yang aman

---

## Lisensi

MIT License - Silakan gunakan dan modifikasi sesuai kebutuhan.

---

**SS-Tools Ultimate v3.0** — Senjata pamungkas anti-cheat Minecraft 2026.
