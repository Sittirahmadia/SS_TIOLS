"""
SS-Tools Ultimate - Internationalization (i18n)
Supports Indonesian (id) and English (en).
"""

TRANSLATIONS = {
    "id": {
        # Main Window
        "app_title": "SS-Tools Ultimate v3.0 - Anti-Cheat Screenshare Tool",
        "dashboard": "Dashboard",
        "minecraft_scan": "Minecraft Scanner",
        "mods_scanner": "Mods Scanner",
        "kernel_check": "Kernel Check",
        "process_scan": "Process Scanner",
        "browser_scan": "Browser Scanner",
        "deleted_scan": "Deleted Scanner",
        "memory_scan": "Memory Scanner",
        "network_scan": "Network Scanner",
        "settings": "Pengaturan",
        "guide": "Panduan",
        "about": "Tentang",

        # Dashboard
        "full_scan": "Full Auto Scan",
        "stop_scan": "Hentikan Scan",
        "player_name": "Nama Player",
        "staff_name": "Nama Staff",
        "server_name": "Nama Server",
        "scan_status": "Status Scan",
        "idle": "Menunggu...",
        "scanning": "Sedang Scan...",
        "scan_complete": "Scan Selesai!",
        "cheater_detected": "⚠ CHEATER TERDETEKSI ⚠",
        "player_clean": "✓ PLAYER BERSIH ✓",
        "total_findings": "Total Temuan",
        "critical_findings": "Temuan Kritis",
        "high_findings": "Temuan Tinggi",
        "medium_findings": "Temuan Sedang",
        "low_findings": "Temuan Rendah",
        "scan_duration": "Durasi Scan",
        "generate_report": "Buat Laporan",
        "collect_evidence": "Kumpulkan Bukti",
        "export_results": "Ekspor Hasil",

        # Mods Scanner
        "mods_scanner_title": "Mods Scanner - Deep Inspection",
        "scan_all_mods": "Scan Semua Mods",
        "scan_directory": "Scan Folder Tertentu",
        "deep_scan": "Deep Scan Mode",
        "normal_scan": "Normal Scan",
        "mod_name": "Nama Mod",
        "mod_status": "Status",
        "mod_severity": "Tingkat",
        "mod_classes": "Jumlah Class",
        "mod_findings": "Temuan",
        "mod_size": "Ukuran",
        "clean": "BERSIH",
        "suspicious": "MENCURIGAKAN",
        "cheat_detected": "CHEAT TERDETEKSI",
        "whitelisted": "WHITELIST",
        "class_name": "Nama Class",
        "finding_type": "Tipe Temuan",
        "description": "Deskripsi",
        "severity": "Keparahan",
        "evidence": "Bukti",
        "no_mods_found": "Tidak ada mod ditemukan. Pastikan Minecraft terinstall.",
        "scanning_mod": "Scanning mod: {name}",
        "classes_scanned": "{count} class sudah di-scan",
        "eta": "Estimasi selesai: {time}",

        # Kernel Check
        "kernel_check_title": "Kernel Check - Anti-Rootkit Scanner",
        "start_kernel_check": "Mulai Kernel Check",
        "kernel_deep_scan": "Kernel Deep Scan",
        "driver_name": "Nama Driver",
        "driver_status": "Status",
        "driver_type": "Tipe",
        "driver_path": "Path",
        "driver_signed": "Signature",
        "kernel_warning": "⚠ Kernel Check membutuhkan hak Administrator untuk hasil terbaik.",
        "kernel_cheat_detected": "KERNEL CHEAT TERDETEKSI",
        "kernel_clean": "Tidak ada kernel cheat terdeteksi",
        "hidden_driver": "Driver Tersembunyi Terdeteksi",
        "unsigned_driver": "Driver Tanpa Tanda Tangan Digital",

        # Process Scanner
        "process_name": "Nama Proses",
        "process_pid": "PID",
        "process_path": "Lokasi",
        "process_memory": "Memori",

        # Browser Scanner
        "browser_name": "Browser",
        "url": "URL",
        "title": "Judul",
        "download_path": "Lokasi Download",

        # Settings
        "language": "Bahasa",
        "indonesian": "Bahasa Indonesia",
        "english": "English",
        "decompiler_setting": "Decompiler",
        "auto_update": "Auto-update database",
        "max_threads": "Maksimal Thread",
        "scan_timeout": "Timeout Scan (detik)",
        "cache_enabled": "Aktifkan Cache",
        "deep_scan_default": "Deep Scan sebagai default",
        "save_settings": "Simpan Pengaturan",
        "reset_settings": "Reset ke Default",
        "update_database": "Update Database Sekarang",
        "database_version": "Versi Database",
        "decompiler_path": "Lokasi File Decompiler (.jar)",
        "browse": "Pilih...",

        # Guide / Help
        "guide_title": "Panduan Penggunaan SS-Tools Ultimate",
        "guide_welcome": "Selamat Datang di SS-Tools Ultimate!",
        "guide_intro": (
            "SS-Tools Ultimate adalah alat screenshare (SS) profesional untuk mendeteksi "
            "semua jenis cheat di Minecraft. Tool ini dirancang untuk staff server Minecraft "
            "yang melakukan screenshare terhadap player yang dicurigai menggunakan cheat."
        ),
        "guide_quick_start": "Panduan Cepat",
        "guide_step1": "1. Masukkan nama player, nama staff, dan nama server di Dashboard.",
        "guide_step2": "2. Klik 'Full Auto Scan' untuk melakukan scan otomatis semua modul.",
        "guide_step3": "3. Tunggu sampai scan selesai. Hasil akan ditampilkan di Dashboard.",
        "guide_step4": "4. Jika ada temuan, klik detail untuk melihat penjelasan lengkap.",
        "guide_step5": "5. Klik 'Buat Laporan' untuk membuat report HTML profesional.",
        "guide_mods_title": "Panduan Mods Scanner",
        "guide_mods_1": "• Mods Scanner akan otomatis menemukan semua file .jar mod di PC.",
        "guide_mods_2": "• Setiap mod akan diekstrak, dianalisis bytecodenya, dan dicek pattern cheat.",
        "guide_mods_3": "• Gunakan 'Deep Scan' untuk analisis lebih mendalam (termasuk decompile).",
        "guide_mods_4": "• Status: BERSIH (hijau), MENCURIGAKAN (kuning), CHEAT TERDETEKSI (merah).",
        "guide_mods_5": "• Klik nama mod untuk melihat detail temuan per .class file.",
        "guide_kernel_title": "Panduan Kernel Check",
        "guide_kernel_1": "• Kernel Check mendeteksi cheat yang berjalan di level kernel (driver .sys).",
        "guide_kernel_2": "• Jalankan aplikasi sebagai Administrator untuk hasil terbaik.",
        "guide_kernel_3": "• Tool akan memeriksa semua driver yang termuat di Windows.",
        "guide_kernel_4": "• Driver yang tidak memiliki tanda tangan digital akan ditandai.",
        "guide_kernel_5": "• Database berisi 30+ driver exploit/cheat yang diketahui.",
        "guide_tips_title": "Tips Penting",
        "guide_tip1": "• Selalu jalankan sebagai Administrator untuk akses penuh.",
        "guide_tip2": "• Gunakan Full Auto Scan terlebih dahulu, baru scan manual jika perlu.",
        "guide_tip3": "• Hasil dengan severity 80+ hampir pasti cheat - langsung tindak.",
        "guide_tip4": "• Gunakan 'Kumpulkan Bukti' untuk menyimpan bukti otomatis.",
        "guide_tip5": "• Report HTML bisa langsung dikirim ke head-staff atau owner.",

        # Welcome Screen
        "welcome_title": "Selamat Datang di SS-Tools Ultimate!",
        "welcome_subtitle": "Anti-Cheat Screenshare Tool Terbaik untuk Minecraft",
        "welcome_desc": (
            "SS-Tools Ultimate akan membantu Anda mendeteksi semua jenis cheat "
            "di komputer player dengan akurasi tinggi dan zero false positive."
        ),
        "welcome_features": "Fitur Utama:",
        "welcome_f1": "✓ Scan otomatis semua launcher Minecraft",
        "welcome_f2": "✓ Deep inspection mod .jar (bytecode + decompile)",
        "welcome_f3": "✓ Kernel-level cheat detection",
        "welcome_f4": "✓ Forensic deleted file recovery",
        "welcome_f5": "✓ Browser history & download scanner",
        "welcome_f6": "✓ Auto evidence collection & report generation",
        "welcome_start": "Mulai Sekarang",
        "welcome_show_guide": "Lihat Panduan Lengkap",
        "welcome_dont_show": "Jangan tampilkan lagi",

        # Status messages
        "msg_scan_started": "Scan dimulai...",
        "msg_scan_complete": "Scan selesai dalam {time}",
        "msg_findings_found": "{count} temuan ditemukan",
        "msg_no_findings": "Tidak ada temuan - player bersih!",
        "msg_report_generated": "Laporan berhasil dibuat: {path}",
        "msg_evidence_collected": "Bukti berhasil dikumpulkan",
        "msg_db_updated": "Database berhasil diupdate ke v{version}",
        "msg_db_uptodate": "Database sudah versi terbaru",
        "msg_settings_saved": "Pengaturan tersimpan",
        "msg_error": "Error: {error}",
        "msg_admin_required": "Beberapa fitur membutuhkan hak Administrator",
    },

    "en": {
        "app_title": "SS-Tools Ultimate v3.0 - Anti-Cheat Screenshare Tool",
        "dashboard": "Dashboard",
        "minecraft_scan": "Minecraft Scanner",
        "mods_scanner": "Mods Scanner",
        "kernel_check": "Kernel Check",
        "process_scan": "Process Scanner",
        "browser_scan": "Browser Scanner",
        "deleted_scan": "Deleted Scanner",
        "memory_scan": "Memory Scanner",
        "network_scan": "Network Scanner",
        "settings": "Settings",
        "guide": "Guide",
        "about": "About",

        "full_scan": "Full Auto Scan",
        "stop_scan": "Stop Scan",
        "player_name": "Player Name",
        "staff_name": "Staff Name",
        "server_name": "Server Name",
        "scan_status": "Scan Status",
        "idle": "Idle...",
        "scanning": "Scanning...",
        "scan_complete": "Scan Complete!",
        "cheater_detected": "⚠ CHEATER DETECTED ⚠",
        "player_clean": "✓ PLAYER CLEAN ✓",
        "total_findings": "Total Findings",
        "critical_findings": "Critical Findings",
        "high_findings": "High Findings",
        "medium_findings": "Medium Findings",
        "low_findings": "Low Findings",
        "scan_duration": "Scan Duration",
        "generate_report": "Generate Report",
        "collect_evidence": "Collect Evidence",
        "export_results": "Export Results",

        "mods_scanner_title": "Mods Scanner - Deep Inspection",
        "scan_all_mods": "Scan All Mods",
        "scan_directory": "Scan Specific Directory",
        "deep_scan": "Deep Scan Mode",
        "normal_scan": "Normal Scan",
        "mod_name": "Mod Name",
        "mod_status": "Status",
        "mod_severity": "Severity",
        "mod_classes": "Class Count",
        "mod_findings": "Findings",
        "mod_size": "Size",
        "clean": "CLEAN",
        "suspicious": "SUSPICIOUS",
        "cheat_detected": "CHEAT DETECTED",
        "whitelisted": "WHITELISTED",
        "class_name": "Class Name",
        "finding_type": "Finding Type",
        "description": "Description",
        "severity": "Severity",
        "evidence": "Evidence",
        "no_mods_found": "No mods found. Make sure Minecraft is installed.",
        "scanning_mod": "Scanning mod: {name}",
        "classes_scanned": "{count} classes scanned",
        "eta": "ETA: {time}",

        "kernel_check_title": "Kernel Check - Anti-Rootkit Scanner",
        "start_kernel_check": "Start Kernel Check",
        "kernel_deep_scan": "Kernel Deep Scan",
        "driver_name": "Driver Name",
        "driver_status": "Status",
        "driver_type": "Type",
        "driver_path": "Path",
        "driver_signed": "Signature",
        "kernel_warning": "⚠ Kernel Check requires Administrator privileges for best results.",
        "kernel_cheat_detected": "KERNEL CHEAT DETECTED",
        "kernel_clean": "No kernel cheats detected",
        "hidden_driver": "Hidden Driver Detected",
        "unsigned_driver": "Unsigned Driver",

        "process_name": "Process Name",
        "process_pid": "PID",
        "process_path": "Path",
        "process_memory": "Memory",

        "browser_name": "Browser",
        "url": "URL",
        "title": "Title",
        "download_path": "Download Path",

        "language": "Language",
        "indonesian": "Bahasa Indonesia",
        "english": "English",
        "decompiler_setting": "Decompiler",
        "auto_update": "Auto-update database",
        "max_threads": "Max Threads",
        "scan_timeout": "Scan Timeout (seconds)",
        "cache_enabled": "Enable Cache",
        "deep_scan_default": "Deep Scan as default",
        "save_settings": "Save Settings",
        "reset_settings": "Reset to Default",
        "update_database": "Update Database Now",
        "database_version": "Database Version",
        "decompiler_path": "Decompiler File Path (.jar)",
        "browse": "Browse...",

        "guide_title": "SS-Tools Ultimate User Guide",
        "guide_welcome": "Welcome to SS-Tools Ultimate!",
        "guide_intro": (
            "SS-Tools Ultimate is a professional screenshare (SS) tool for detecting "
            "all types of cheats in Minecraft. Designed for server staff performing "
            "screenshares on suspected cheating players."
        ),
        "guide_quick_start": "Quick Start Guide",
        "guide_step1": "1. Enter player name, staff name, and server name in Dashboard.",
        "guide_step2": "2. Click 'Full Auto Scan' to run automatic scan of all modules.",
        "guide_step3": "3. Wait for scan to complete. Results appear on Dashboard.",
        "guide_step4": "4. If findings exist, click details for full explanation.",
        "guide_step5": "5. Click 'Generate Report' to create a professional HTML report.",
        "guide_mods_title": "Mods Scanner Guide",
        "guide_mods_1": "• Mods Scanner automatically finds all .jar mod files on the PC.",
        "guide_mods_2": "• Each mod is extracted, bytecode analyzed, and checked for cheat patterns.",
        "guide_mods_3": "• Use 'Deep Scan' for deeper analysis (includes decompilation).",
        "guide_mods_4": "• Status: CLEAN (green), SUSPICIOUS (yellow), CHEAT DETECTED (red).",
        "guide_mods_5": "• Click mod name to see detailed findings per .class file.",
        "guide_kernel_title": "Kernel Check Guide",
        "guide_kernel_1": "• Kernel Check detects cheats running at kernel level (.sys drivers).",
        "guide_kernel_2": "• Run the application as Administrator for best results.",
        "guide_kernel_3": "• Tool checks all loaded drivers in Windows.",
        "guide_kernel_4": "• Unsigned drivers will be flagged.",
        "guide_kernel_5": "• Database contains 30+ known exploit/cheat drivers.",
        "guide_tips_title": "Important Tips",
        "guide_tip1": "• Always run as Administrator for full access.",
        "guide_tip2": "• Use Full Auto Scan first, then manual scans if needed.",
        "guide_tip3": "• Results with severity 80+ are almost certainly cheats - take action.",
        "guide_tip4": "• Use 'Collect Evidence' to save evidence automatically.",
        "guide_tip5": "• HTML report can be sent directly to head-staff or server owner.",

        "welcome_title": "Welcome to SS-Tools Ultimate!",
        "welcome_subtitle": "The Best Anti-Cheat Screenshare Tool for Minecraft",
        "welcome_desc": (
            "SS-Tools Ultimate helps you detect all types of cheats on a player's "
            "computer with high accuracy and zero false positives."
        ),
        "welcome_features": "Key Features:",
        "welcome_f1": "✓ Auto-scan all Minecraft launchers",
        "welcome_f2": "✓ Deep mod .jar inspection (bytecode + decompile)",
        "welcome_f3": "✓ Kernel-level cheat detection",
        "welcome_f4": "✓ Forensic deleted file recovery",
        "welcome_f5": "✓ Browser history & download scanner",
        "welcome_f6": "✓ Auto evidence collection & report generation",
        "welcome_start": "Get Started",
        "welcome_show_guide": "View Full Guide",
        "welcome_dont_show": "Don't show again",

        "msg_scan_started": "Scan started...",
        "msg_scan_complete": "Scan completed in {time}",
        "msg_findings_found": "{count} findings detected",
        "msg_no_findings": "No findings - player is clean!",
        "msg_report_generated": "Report generated: {path}",
        "msg_evidence_collected": "Evidence collected successfully",
        "msg_db_updated": "Database updated to v{version}",
        "msg_db_uptodate": "Database is up to date",
        "msg_settings_saved": "Settings saved",
        "msg_error": "Error: {error}",
        "msg_admin_required": "Some features require Administrator privileges",
    }
}


class I18n:
    """Simple internationalization manager."""

    def __init__(self, lang: str = "id"):
        self.lang = lang

    def t(self, key: str, **kwargs) -> str:
        """Translate a key with optional format arguments."""
        text = TRANSLATIONS.get(self.lang, {}).get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except (KeyError, IndexError):
                pass
        return text

    def set_language(self, lang: str):
        """Switch language."""
        if lang in TRANSLATIONS:
            self.lang = lang

    @property
    def available_languages(self):
        return list(TRANSLATIONS.keys())
