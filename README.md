# SS-Tools Ultimate v3.0

**Anti-Cheat Screenshare Tool Terbaik untuk Minecraft**

SS-Tools Ultimate adalah aplikasi desktop profesional yang dirancang untuk staff server Minecraft dalam melakukan screenshare (SS) terhadap player yang dicurigai menggunakan cheat. Tool ini mampu mendeteksi semua jenis cheat dengan akurasi mendekati 100% dan zero false positive.

---

## Fitur Utama

### 1. Cheat Detector Keyword (Advanced)
- Database 350+ entry keyword cheat dalam format JSON
- Support regex, wildcard, fuzzy matching, Levenshtein distance
- Deteksi nama cheat client, module, developer, file, folder, URL, Discord invite
- Auto-update database melalui GitHub

### 2. Minecraft Scanner
- Scan otomatis semua launcher: Official, TLauncher, CurseForge, MultiMC, Prism Launcher, GDLauncher, ATLauncher, HMCL, SKLauncher, Badlion, Lunar, Feather, LabyMod, dll
- Scan folder mods, logs, config, saves, resourcepacks, versions, libraries
- Multi-threading + caching untuk performa optimal
- Whitelist resmi mod vanilla + modpack populer

### 3. Mods Scanner (Deep Inspection)
- Ekstrak semua .class dari file .jar mod
- Analisis bytecode langsung (constant pool, opcodes)
- Integrasi decompiler (CFR, FernFlower, Procyon, Vineflower)
- Deteksi pattern cheat: KillAura, Reach, Flight, Speed, XRay, ESP, dll
- Deteksi obfuscation, reflection, native methods, mixin hooks
- Tidak ada batasan jumlah/ukuran file mod
- Cache hasil scan untuk performa ulang

### 4. Kernel Check (Anti-Rootkit)
- Enumerasi semua loaded kernel drivers
- Cek digital signature setiap driver
- Database 30+ known exploit/cheat driver
- Deteksi hidden drivers (cross-view scanning)
- Deteksi driver baru dimuat saat sesi SS

### 5. Process Scanner
- Scan semua running process + loaded DLL
- Deteksi auto-clicker, macro, injector, debugger
- Scan DLL yang di-inject ke proses Java/Minecraft

### 6. String Deleted Scanner (Forensic)
- Scan Recycle Bin, temp folders, prefetch files
- Scan registry (RecentDocs, RunMRU, AppCompatFlags)
- Scan Windows Event Logs & USN Journal

### 7. Browser Scanner
- Support Chrome, Edge, Firefox, Opera, Brave
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

### 11. Evidence Collector & Report Generator
- Screenshot otomatis
- Export process list
- Simpan hasil scan ke folder Evidence
- Generate report HTML profesional

---

## Instalasi

### Persyaratan
- **OS:** Windows 10/11 (64-bit)
- **Python:** 3.11 atau 3.12
- **RAM:** Minimal 4 GB
- **Disk:** 200 MB ruang kosong

### Install dari Source

```bash
# Clone repository
git clone https://github.com/Sittirahmadia/SS_TIOLS.git
cd SS_TIOLS

# Buat virtual environment (opsional tapi direkomendasikan)
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Jalankan aplikasi
python main.py
```

### Download .exe (Release)
Download file `SS-Tools-Ultimate.exe` dari halaman [Releases](https://github.com/Sittirahmadia/SS_TIOLS/releases).

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
