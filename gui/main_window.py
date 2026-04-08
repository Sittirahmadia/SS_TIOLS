"""
SS-Tools Ultimate - Main Window
Professional PyQt6 GUI with all scanner tabs, dashboard, and integrated guide.
"""
import os
import sys
import time
import json
import threading
import webbrowser
from pathlib import Path
from typing import List, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit, QProgressBar,
    QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem,
    QGroupBox, QCheckBox, QComboBox, QSpinBox, QFileDialog,
    QSplitter, QFrame, QDialog, QScrollArea, QHeaderView,
    QStatusBar, QMenuBar, QMenu, QMessageBox, QGridLayout,
    QSizePolicy, QSpacerItem, QToolTip, QStyleFactory
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation,
    QEasingCurve, QUrl, QPoint
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QIcon, QPixmap, QPainter,
    QLinearGradient, QBrush, QPen, QAction, QDesktopServices,
    QFontDatabase
)

from gui.styles import DARK_STYLESHEET
from gui.i18n import I18n
from core.config import (
    AppSettings, APP_NAME, APP_VERSION, EVIDENCE_DIR,
    REPORTS_DIR, DECOMPILER_OPTIONS
)
from core.utils import (
    ScanResult, ScanProgress, logger, severity_color,
    severity_label, format_duration, format_size, get_file_timestamp
)
from core.database import CheatDatabase
from core.keyword_detector import KeywordDetector
from core.minecraft_scanner import MinecraftScanner
from core.mods_scanner import ModsScanner, ModScanResult
from core.kernel_check import KernelCheck
from core.process_scanner import ProcessScanner
from core.string_deleted_scanner import StringDeletedScanner
from core.browser_scanner import BrowserScanner
from core.deleted_file_detector import DeletedFileDetector
from core.memory_scanner import MemoryScanner
from core.network_scanner import NetworkScanner
from core.evidence_collector import EvidenceCollector, ReportGenerator


# ─── Worker Thread ────────────────────────────────────────────────────
class ScanWorker(QThread):
    """Background worker for running scans."""
    progress_update = pyqtSignal(str, int, int)  # module, current, total
    result_found = pyqtSignal(dict)
    scan_finished = pyqtSignal(list, float)  # results, duration
    mod_result = pyqtSignal(object)  # ModScanResult
    status_update = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, scan_type: str = "full", settings: AppSettings = None,
                 mod_dir: str = "", deep_scan: bool = False):
        super().__init__()
        self.scan_type = scan_type
        self.settings = settings or AppSettings.load()
        self.mod_dir = mod_dir
        self.deep_scan = deep_scan
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        start_time = time.time()
        all_results = []
        try:
            progress = ScanProgress()
            progress.add_callback(lambda p: self.progress_update.emit(
                p.current_module, p.completed, p.total
            ))

            scanners = self._get_scanners(progress)

            for name, scanner_func in scanners:
                if not self._running:
                    break
                self.status_update.emit(f"Running {name}...")
                try:
                    results = scanner_func()
                    all_results.extend(results)
                    for r in results:
                        self.result_found.emit(r.to_dict())
                except Exception as e:
                    logger.error(f"{name} error: {e}")
                    self.error_occurred.emit(f"{name}: {str(e)}")

        except Exception as e:
            self.error_occurred.emit(str(e))

        duration = time.time() - start_time
        self.scan_finished.emit(all_results, duration)

    def _get_scanners(self, progress):
        """Get list of scanners based on scan type."""
        scanners = []

        if self.scan_type == "full":
            scanners = [
                ("Minecraft Scanner", lambda: MinecraftScanner(progress).scan_all()),
                ("Process Scanner", lambda: ProcessScanner(progress).scan()),
                ("Browser Scanner", lambda: BrowserScanner(progress).scan()),
                ("Deleted String Scanner", lambda: StringDeletedScanner(progress).scan()),
                ("Deleted File Detector", lambda: DeletedFileDetector(progress).scan()),
                ("Memory Scanner", lambda: MemoryScanner(progress).scan()),
                ("Network Scanner", lambda: NetworkScanner(progress).scan()),
            ]
            if self.settings.kernel_check_enabled:
                scanners.append(("Kernel Check", lambda: KernelCheck(progress).scan()))

        elif self.scan_type == "mods":
            def mods_scan():
                scanner = ModsScanner(progress, self.settings)
                if self.mod_dir:
                    results = scanner.scan_directory(self.mod_dir)
                else:
                    mod_files = scanner.find_all_mods()
                    results = scanner.scan_mods(mod_files, self.deep_scan)
                # Emit individual mod results
                scan_results = []
                for mr in results:
                    self.mod_result.emit(mr)
                    if mr.status != "CLEAN":
                        scan_results.append(ScanResult(
                            scanner="ModsScanner",
                            category="mod_" + mr.status.lower(),
                            name=mr.filename,
                            description=f"{mr.status}: {mr.filename} (severity: {mr.severity})",
                            severity=mr.severity,
                            filepath=mr.filepath,
                        ))
                return scan_results
            scanners = [("Mods Scanner", mods_scan)]

        elif self.scan_type == "kernel":
            scanners = [("Kernel Check", lambda: KernelCheck(progress).scan())]

        elif self.scan_type == "minecraft":
            scanners = [("Minecraft Scanner", lambda: MinecraftScanner(progress).scan_all())]

        elif self.scan_type == "process":
            scanners = [("Process Scanner", lambda: ProcessScanner(progress).scan())]

        elif self.scan_type == "browser":
            scanners = [("Browser Scanner", lambda: BrowserScanner(progress).scan())]

        elif self.scan_type == "deleted":
            scanners = [
                ("Deleted String Scanner", lambda: StringDeletedScanner(progress).scan()),
                ("Deleted File Detector", lambda: DeletedFileDetector(progress).scan()),
            ]

        elif self.scan_type == "memory":
            scanners = [("Memory Scanner", lambda: MemoryScanner(progress).scan())]

        elif self.scan_type == "network":
            scanners = [("Network Scanner", lambda: NetworkScanner(progress).scan())]

        return scanners


# ─── Stat Card Widget ─────────────────────────────────────────────────
class StatCard(QFrame):
    """Stylish stat card for dashboard."""

    def __init__(self, title: str, value: str = "0", color: str = "#58a6ff"):
        super().__init__()
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet(f"""
            QFrame {{
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 12px;
                padding: 15px;
            }}
            QFrame:hover {{
                border-color: {color};
                background: #1c2128;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        self.value_label = QLabel(value)
        self.value_label.setFont(QFont("Segoe UI", 28, QFont.Weight.Black))
        self.value_label.setStyleSheet(f"color: {color}; background: transparent; border: none;")
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.title_label = QLabel(title)
        self.title_label.setFont(QFont("Segoe UI", 10))
        self.title_label.setStyleSheet("color: #8b949e; background: transparent; border: none;")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

    def set_value(self, value: str):
        self.value_label.setText(value)

    def set_color(self, color: str):
        self.value_label.setStyleSheet(f"color: {color}; background: transparent; border: none;")


# ─── Welcome Dialog ───────────────────────────────────────────────────
class WelcomeDialog(QDialog):
    """Welcome/splash screen shown on first launch."""

    def __init__(self, i18n: I18n, parent=None):
        super().__init__(parent)
        self.i18n = i18n
        self.setWindowTitle(i18n.t("welcome_title"))
        self.setFixedSize(600, 520)
        self.setStyleSheet("""
            QDialog { background: #0d1117; border: 2px solid #30363d; border-radius: 16px; }
        """)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(40, 30, 40, 30)

        # Title
        title = QLabel(self.i18n.t("welcome_title"))
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Black))
        title.setStyleSheet("color: #58a6ff;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setWordWrap(True)
        layout.addWidget(title)

        subtitle = QLabel(self.i18n.t("welcome_subtitle"))
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet("color: #8b949e;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background: #30363d; max-height: 1px;")
        layout.addWidget(sep)

        # Description
        desc = QLabel(self.i18n.t("welcome_desc"))
        desc.setFont(QFont("Segoe UI", 11))
        desc.setStyleSheet("color: #c9d1d9;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Features
        features_label = QLabel(self.i18n.t("welcome_features"))
        features_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        features_label.setStyleSheet("color: #3fb950;")
        layout.addWidget(features_label)

        for key in ["welcome_f1", "welcome_f2", "welcome_f3",
                     "welcome_f4", "welcome_f5", "welcome_f6"]:
            fl = QLabel(self.i18n.t(key))
            fl.setFont(QFont("Segoe UI", 11))
            fl.setStyleSheet("color: #e6edf3; padding-left: 10px;")
            layout.addWidget(fl)

        layout.addSpacerItem(QSpacerItem(0, 10, QSizePolicy.Policy.Minimum,
                                          QSizePolicy.Policy.Expanding))

        # Buttons
        btn_layout = QHBoxLayout()
        self.guide_btn = QPushButton(self.i18n.t("welcome_show_guide"))
        self.guide_btn.setObjectName("secondaryBtn")
        self.guide_btn.clicked.connect(self.reject)

        self.start_btn = QPushButton(self.i18n.t("welcome_start"))
        self.start_btn.setStyleSheet("""
            QPushButton { background: #238636; color: white; border-radius: 10px;
                          padding: 12px 30px; font-size: 15px; font-weight: 800; }
            QPushButton:hover { background: #2ea043; }
        """)
        self.start_btn.clicked.connect(self.accept)

        btn_layout.addWidget(self.guide_btn)
        btn_layout.addWidget(self.start_btn)
        layout.addLayout(btn_layout)

        # Don't show again
        self.dont_show = QCheckBox(self.i18n.t("welcome_dont_show"))
        self.dont_show.setStyleSheet("color: #8b949e;")
        layout.addWidget(self.dont_show, alignment=Qt.AlignmentFlag.AlignCenter)


# ─── Guide Dialog ─────────────────────────────────────────────────────
class GuideDialog(QDialog):
    """Full guide/help dialog."""

    def __init__(self, i18n: I18n, parent=None):
        super().__init__(parent)
        self.i18n = i18n
        self.setWindowTitle(i18n.t("guide_title"))
        self.setMinimumSize(700, 600)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(12)
        content_layout.setContentsMargins(30, 20, 30, 20)

        # Title
        title = QLabel(self.i18n.t("guide_title"))
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Black))
        title.setStyleSheet("color: #58a6ff;")
        content_layout.addWidget(title)

        # Intro
        intro = QLabel(self.i18n.t("guide_intro"))
        intro.setWordWrap(True)
        intro.setFont(QFont("Segoe UI", 11))
        intro.setStyleSheet("color: #c9d1d9;")
        content_layout.addWidget(intro)

        self._add_section(content_layout, self.i18n.t("guide_quick_start"), [
            "guide_step1", "guide_step2", "guide_step3",
            "guide_step4", "guide_step5",
        ])

        self._add_section(content_layout, self.i18n.t("guide_mods_title"), [
            "guide_mods_1", "guide_mods_2", "guide_mods_3",
            "guide_mods_4", "guide_mods_5",
        ])

        self._add_section(content_layout, self.i18n.t("guide_kernel_title"), [
            "guide_kernel_1", "guide_kernel_2", "guide_kernel_3",
            "guide_kernel_4", "guide_kernel_5",
        ])

        self._add_section(content_layout, self.i18n.t("guide_tips_title"), [
            "guide_tip1", "guide_tip2", "guide_tip3",
            "guide_tip4", "guide_tip5",
        ])

        content_layout.addSpacerItem(QSpacerItem(0, 20, QSizePolicy.Policy.Minimum,
                                                    QSizePolicy.Policy.Expanding))

        scroll.setWidget(content)
        layout.addWidget(scroll)

        close_btn = QPushButton("OK")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def _add_section(self, layout, title, keys):
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background: #30363d; max-height: 1px;")
        layout.addWidget(sep)

        lbl = QLabel(title)
        lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lbl.setStyleSheet("color: #3fb950; margin-top: 10px;")
        layout.addWidget(lbl)

        for key in keys:
            item = QLabel(self.i18n.t(key))
            item.setWordWrap(True)
            item.setFont(QFont("Segoe UI", 11))
            item.setStyleSheet("color: #e6edf3; padding-left: 8px;")
            layout.addWidget(item)


# ─── Main Window ──────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    """SS-Tools Ultimate main application window."""

    def __init__(self):
        super().__init__()
        self.settings = AppSettings.load()
        self.i18n = I18n(self.settings.language)
        self.db = CheatDatabase()
        self.scan_results: List[ScanResult] = []
        self.mod_results: List[ModScanResult] = []
        self.worker: Optional[ScanWorker] = None
        self.scan_start_time = 0.0
        self.evidence_collector = EvidenceCollector()
        self.report_generator = ReportGenerator()

        self._setup_window()
        self._build_menu_bar()
        self._build_ui()
        self._build_status_bar()

        # Auto-update database
        if self.settings.auto_update_db:
            self.db.auto_update_async(self._on_db_update)

        # Show welcome on first run
        self._check_first_run()

    def _setup_window(self):
        self.setWindowTitle(self.i18n.t("app_title"))
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        self.setStyleSheet(DARK_STYLESHEET)

    def _build_menu_bar(self):
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        export_action = QAction("Export Results (JSON)", self)
        export_action.triggered.connect(self._export_results)
        file_menu.addAction(export_action)

        report_action = QAction(self.i18n.t("generate_report"), self)
        report_action.triggered.connect(self._generate_report)
        file_menu.addAction(report_action)

        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Scan menu
        scan_menu = menubar.addMenu("Scan")
        full_scan = QAction(self.i18n.t("full_scan"), self)
        full_scan.triggered.connect(lambda: self._start_scan("full"))
        scan_menu.addAction(full_scan)

        mods_scan = QAction(self.i18n.t("scan_all_mods"), self)
        mods_scan.triggered.connect(lambda: self._start_scan("mods"))
        scan_menu.addAction(mods_scan)

        kernel_scan = QAction(self.i18n.t("start_kernel_check"), self)
        kernel_scan.triggered.connect(lambda: self._start_scan("kernel"))
        scan_menu.addAction(kernel_scan)

        # Help menu
        help_menu = menubar.addMenu("Help")
        guide_action = QAction(self.i18n.t("guide"), self)
        guide_action.triggered.connect(self._show_guide)
        help_menu.addAction(guide_action)

        about_action = QAction(self.i18n.t("about"), self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Build all tabs
        self.tabs.addTab(self._build_dashboard_tab(), self.i18n.t("dashboard"))
        self.tabs.addTab(self._build_mods_tab(), self.i18n.t("mods_scanner"))
        self.tabs.addTab(self._build_kernel_tab(), self.i18n.t("kernel_check"))
        self.tabs.addTab(self._build_results_tab(), "All Results")
        self.tabs.addTab(self._build_settings_tab(), self.i18n.t("settings"))

        main_layout.addWidget(self.tabs)

    def _build_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel(self.i18n.t("idle"))
        self.status_bar.addWidget(self.status_label, 1)
        self.db_version_label = QLabel(f"DB: v{self.db.version}")
        self.status_bar.addPermanentWidget(self.db_version_label)

    # ── Dashboard Tab ─────────────────────────────────────────────────
    def _build_dashboard_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title row
        title_row = QHBoxLayout()
        title = QLabel(f"{APP_NAME}")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Black))
        title.setStyleSheet("color: #58a6ff;")
        title_row.addWidget(title)
        title_row.addStretch()

        # Language switcher
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["Bahasa Indonesia", "English"])
        self.lang_combo.setCurrentIndex(0 if self.settings.language == "id" else 1)
        self.lang_combo.currentIndexChanged.connect(self._switch_language)
        self.lang_combo.setFixedWidth(160)
        title_row.addWidget(QLabel("🌐"))
        title_row.addWidget(self.lang_combo)

        guide_btn = QPushButton(f"📖 {self.i18n.t('guide')}")
        guide_btn.setObjectName("secondaryBtn")
        guide_btn.setFixedWidth(120)
        guide_btn.setToolTip("Buka panduan penggunaan lengkap")
        guide_btn.clicked.connect(self._show_guide)
        title_row.addWidget(guide_btn)

        layout.addLayout(title_row)

        # Info input row
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 12px; }
        """)
        info_layout = QHBoxLayout(info_frame)

        self.player_input = QLineEdit()
        self.player_input.setPlaceholderText(self.i18n.t("player_name"))
        self.player_input.setToolTip("Masukkan nama player yang di-screenshare")
        self.staff_input = QLineEdit()
        self.staff_input.setPlaceholderText(self.i18n.t("staff_name"))
        self.staff_input.setToolTip("Masukkan nama staff yang melakukan SS")
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText(self.i18n.t("server_name"))
        self.server_input.setToolTip("Masukkan nama server Minecraft")

        for w in [self.player_input, self.staff_input, self.server_input]:
            info_layout.addWidget(w)

        layout.addWidget(info_frame)

        # Action buttons
        btn_row = QHBoxLayout()
        self.full_scan_btn = QPushButton(f"🔍  {self.i18n.t('full_scan')}")
        self.full_scan_btn.setStyleSheet("""
            QPushButton { background: #238636; color: white; border-radius: 10px;
                          padding: 14px 30px; font-size: 16px; font-weight: 800;
                          min-width: 200px; }
            QPushButton:hover { background: #2ea043; }
            QPushButton:disabled { background: #21262d; color: #484f58; }
        """)
        self.full_scan_btn.setToolTip("Jalankan scan otomatis semua modul sekaligus")
        self.full_scan_btn.clicked.connect(lambda: self._start_scan("full"))
        btn_row.addWidget(self.full_scan_btn)

        self.stop_btn = QPushButton(f"⏹  {self.i18n.t('stop_scan')}")
        self.stop_btn.setObjectName("dangerBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        btn_row.addWidget(self.stop_btn)

        btn_row.addStretch()

        self.report_btn = QPushButton(f"📄 {self.i18n.t('generate_report')}")
        self.report_btn.setObjectName("secondaryBtn")
        self.report_btn.setToolTip("Buat laporan HTML profesional dari hasil scan")
        self.report_btn.clicked.connect(self._generate_report)
        btn_row.addWidget(self.report_btn)

        self.evidence_btn = QPushButton(f"📦 {self.i18n.t('collect_evidence')}")
        self.evidence_btn.setObjectName("secondaryBtn")
        self.evidence_btn.setToolTip("Kumpulkan bukti otomatis (screenshot, process list, results)")
        self.evidence_btn.clicked.connect(self._collect_evidence)
        btn_row.addWidget(self.evidence_btn)

        layout.addLayout(btn_row)

        # Verdict
        self.verdict_label = QLabel(self.i18n.t("idle"))
        self.verdict_label.setFont(QFont("Segoe UI", 32, QFont.Weight.Black))
        self.verdict_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.verdict_label.setStyleSheet("""
            QLabel { color: #8b949e; background: #161b22; border: 2px solid #30363d;
                     border-radius: 16px; padding: 24px; margin: 8px 0; }
        """)
        layout.addWidget(self.verdict_label)

        # Stats cards
        stats_row = QHBoxLayout()
        self.stat_critical = StatCard(self.i18n.t("critical_findings"), "0", "#FF1744")
        self.stat_high = StatCard(self.i18n.t("high_findings"), "0", "#FF9100")
        self.stat_medium = StatCard(self.i18n.t("medium_findings"), "0", "#FFD600")
        self.stat_low = StatCard(self.i18n.t("low_findings"), "0", "#00E676")
        self.stat_duration = StatCard(self.i18n.t("scan_duration"), "--", "#58a6ff")

        for card in [self.stat_critical, self.stat_high, self.stat_medium,
                     self.stat_low, self.stat_duration]:
            stats_row.addWidget(card)
        layout.addLayout(stats_row)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumHeight(30)
        layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(self.progress_label)

        # Recent findings table
        findings_group = QGroupBox(f"{self.i18n.t('total_findings')} (Recent)")
        findings_layout = QVBoxLayout(findings_group)
        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels([
            "Scanner", "Category", "Name", "Severity", "Description"
        ])
        self.findings_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        findings_layout.addWidget(self.findings_table)
        layout.addWidget(findings_group)

        return tab

    # ── Mods Scanner Tab ──────────────────────────────────────────────
    def _build_mods_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QHBoxLayout()
        title = QLabel(self.i18n.t("mods_scanner_title"))
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        header.addWidget(title)
        header.addStretch()

        self.deep_scan_check = QCheckBox(self.i18n.t("deep_scan"))
        self.deep_scan_check.setToolTip(
            "Aktifkan Deep Scan untuk decompile dan analisis source code "
            "(lebih lambat tapi lebih akurat)"
        )
        header.addWidget(self.deep_scan_check)

        layout.addLayout(header)

        # Buttons
        btn_row = QHBoxLayout()
        self.scan_mods_btn = QPushButton(f"🔍 {self.i18n.t('scan_all_mods')}")
        self.scan_mods_btn.setToolTip("Scan semua mod .jar di semua launcher Minecraft")
        self.scan_mods_btn.clicked.connect(lambda: self._start_scan("mods"))
        btn_row.addWidget(self.scan_mods_btn)

        self.scan_dir_btn = QPushButton(f"📁 {self.i18n.t('scan_directory')}")
        self.scan_dir_btn.setObjectName("secondaryBtn")
        self.scan_dir_btn.setToolTip("Pilih folder mods tertentu untuk di-scan")
        self.scan_dir_btn.clicked.connect(self._scan_mods_directory)
        btn_row.addWidget(self.scan_dir_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Progress
        self.mods_progress = QProgressBar()
        self.mods_progress.setTextVisible(True)
        self.mods_progress.setFormat("Ready")
        self.mods_progress.setMinimumHeight(28)
        layout.addWidget(self.mods_progress)

        self.mods_status_label = QLabel("")
        self.mods_status_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(self.mods_status_label)

        # Splitter: mod list + detail
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Mod results table
        self.mods_table = QTableWidget(0, 6)
        self.mods_table.setHorizontalHeaderLabels([
            self.i18n.t("mod_name"), self.i18n.t("mod_status"),
            self.i18n.t("mod_severity"), self.i18n.t("mod_classes"),
            self.i18n.t("mod_findings"), self.i18n.t("mod_size")
        ])
        self.mods_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.mods_table.setAlternatingRowColors(True)
        self.mods_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.mods_table.itemSelectionChanged.connect(self._on_mod_selected)
        splitter.addWidget(self.mods_table)

        # Detail panel
        detail_frame = QFrame()
        detail_frame.setStyleSheet("""
            QFrame { background: #161b22; border: 1px solid #30363d; border-radius: 8px; }
        """)
        detail_layout = QVBoxLayout(detail_frame)

        self.mod_detail_title = QLabel("Select a mod to view details")
        self.mod_detail_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.mod_detail_title.setStyleSheet("color: #58a6ff; border: none;")
        detail_layout.addWidget(self.mod_detail_title)

        self.mod_detail_tree = QTreeWidget()
        self.mod_detail_tree.setHeaderLabels([
            "Class / Finding", "Type", "Severity", "Evidence"
        ])
        self.mod_detail_tree.setAlternatingRowColors(True)
        self.mod_detail_tree.setStyleSheet("border: none;")
        detail_layout.addWidget(self.mod_detail_tree)

        splitter.addWidget(detail_frame)
        splitter.setSizes([400, 300])

        layout.addWidget(splitter)
        return tab

    # ── Kernel Check Tab ──────────────────────────────────────────────
    def _build_kernel_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Header
        title = QLabel(self.i18n.t("kernel_check_title"))
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(title)

        # Warning
        warning = QLabel(self.i18n.t("kernel_warning"))
        warning.setStyleSheet("""
            QLabel { background: #2d1f00; border: 1px solid #d29922;
                     border-radius: 8px; padding: 12px; color: #e3b341; }
        """)
        warning.setWordWrap(True)
        layout.addWidget(warning)

        # Buttons
        btn_row = QHBoxLayout()
        self.kernel_scan_btn = QPushButton(f"🛡 {self.i18n.t('start_kernel_check')}")
        self.kernel_scan_btn.setToolTip("Scan semua kernel driver untuk mendeteksi cheat/rootkit")
        self.kernel_scan_btn.clicked.connect(lambda: self._start_scan("kernel"))
        btn_row.addWidget(self.kernel_scan_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Kernel verdict
        self.kernel_verdict = QLabel(self.i18n.t("idle"))
        self.kernel_verdict.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        self.kernel_verdict.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.kernel_verdict.setStyleSheet("""
            QLabel { background: #161b22; border: 1px solid #30363d;
                     border-radius: 12px; padding: 16px; color: #8b949e; }
        """)
        layout.addWidget(self.kernel_verdict)

        # Results table
        self.kernel_table = QTableWidget(0, 5)
        self.kernel_table.setHorizontalHeaderLabels([
            "Driver", "Category", "Severity", "Description", "Evidence"
        ])
        self.kernel_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.kernel_table.setAlternatingRowColors(True)
        layout.addWidget(self.kernel_table)

        return tab

    # ── All Results Tab ───────────────────────────────────────────────
    def _build_results_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("All Scan Results")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(title)

        self.all_results_table = QTableWidget(0, 6)
        self.all_results_table.setHorizontalHeaderLabels([
            "Scanner", "Category", "Name", "Severity", "File Path", "Description"
        ])
        self.all_results_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        self.all_results_table.setAlternatingRowColors(True)
        self.all_results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        layout.addWidget(self.all_results_table)

        return tab

    # ── Settings Tab ──────────────────────────────────────────────────
    def _build_settings_tab(self) -> QWidget:
        tab = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(16)
        layout.setContentsMargins(30, 20, 30, 20)

        title = QLabel(self.i18n.t("settings"))
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(title)

        # General settings
        general_group = QGroupBox("General")
        gl = QGridLayout(general_group)

        gl.addWidget(QLabel(self.i18n.t("language")), 0, 0)
        self.settings_lang = QComboBox()
        self.settings_lang.addItems([self.i18n.t("indonesian"), self.i18n.t("english")])
        self.settings_lang.setCurrentIndex(0 if self.settings.language == "id" else 1)
        gl.addWidget(self.settings_lang, 0, 1)

        gl.addWidget(QLabel(self.i18n.t("decompiler_setting")), 1, 0)
        self.settings_decompiler = QComboBox()
        self.settings_decompiler.addItems(DECOMPILER_OPTIONS)
        self.settings_decompiler.setCurrentText(self.settings.decompiler)
        gl.addWidget(self.settings_decompiler, 1, 1)

        gl.addWidget(QLabel(self.i18n.t("max_threads")), 2, 0)
        self.settings_threads = QSpinBox()
        self.settings_threads.setRange(1, 32)
        self.settings_threads.setValue(self.settings.max_threads)
        gl.addWidget(self.settings_threads, 2, 1)

        self.settings_auto_update = QCheckBox(self.i18n.t("auto_update"))
        self.settings_auto_update.setChecked(self.settings.auto_update_db)
        gl.addWidget(self.settings_auto_update, 3, 0, 1, 2)

        self.settings_cache = QCheckBox(self.i18n.t("cache_enabled"))
        self.settings_cache.setChecked(self.settings.cache_enabled)
        gl.addWidget(self.settings_cache, 4, 0, 1, 2)

        self.settings_deep = QCheckBox(self.i18n.t("deep_scan_default"))
        self.settings_deep.setChecked(self.settings.deep_scan_mode)
        gl.addWidget(self.settings_deep, 5, 0, 1, 2)

        layout.addWidget(general_group)

        # Scanner toggles
        scanner_group = QGroupBox("Scanners")
        sl = QVBoxLayout(scanner_group)

        self.settings_kernel = QCheckBox("Enable Kernel Check")
        self.settings_kernel.setChecked(self.settings.kernel_check_enabled)
        sl.addWidget(self.settings_kernel)

        self.settings_memory = QCheckBox("Enable Memory Scanner")
        self.settings_memory.setChecked(self.settings.memory_scan_enabled)
        sl.addWidget(self.settings_memory)

        self.settings_network = QCheckBox("Enable Network Scanner")
        self.settings_network.setChecked(self.settings.network_scan_enabled)
        sl.addWidget(self.settings_network)

        self.settings_browser = QCheckBox("Enable Browser Scanner")
        self.settings_browser.setChecked(self.settings.browser_scan_enabled)
        sl.addWidget(self.settings_browser)

        layout.addWidget(scanner_group)

        # Decompiler paths
        decompiler_group = QGroupBox("Decompiler Paths")
        dl = QGridLayout(decompiler_group)
        self.decompiler_inputs = {}
        for i, name in enumerate(DECOMPILER_OPTIONS):
            dl.addWidget(QLabel(f"{name} JAR:"), i, 0)
            inp = QLineEdit()
            inp.setPlaceholderText(f"Path to {name.lower()}.jar")
            current = getattr(self.settings, f"{name.lower()}_path", "")
            inp.setText(current)
            dl.addWidget(inp, i, 1)
            browse_btn = QPushButton(self.i18n.t("browse"))
            browse_btn.setObjectName("secondaryBtn")
            browse_btn.setFixedWidth(80)
            browse_btn.clicked.connect(lambda checked, n=name, w=inp: self._browse_decompiler(n, w))
            dl.addWidget(browse_btn, i, 2)
            self.decompiler_inputs[name] = inp
        layout.addWidget(decompiler_group)

        # Database section
        db_group = QGroupBox("Database")
        dbl = QHBoxLayout(db_group)
        dbl.addWidget(QLabel(f"{self.i18n.t('database_version')}: v{self.db.version}"))
        dbl.addStretch()
        update_btn = QPushButton(self.i18n.t("update_database"))
        update_btn.setObjectName("secondaryBtn")
        update_btn.clicked.connect(self._update_database)
        dbl.addWidget(update_btn)
        layout.addWidget(db_group)

        # Save/Reset buttons
        btn_row = QHBoxLayout()
        save_btn = QPushButton(self.i18n.t("save_settings"))
        save_btn.clicked.connect(self._save_settings)
        btn_row.addWidget(save_btn)

        reset_btn = QPushButton(self.i18n.t("reset_settings"))
        reset_btn.setObjectName("secondaryBtn")
        reset_btn.clicked.connect(self._reset_settings)
        btn_row.addWidget(reset_btn)
        btn_row.addStretch()

        layout.addLayout(btn_row)
        layout.addStretch()

        scroll.setWidget(content)
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.addWidget(scroll)
        return tab

    # ── Scan Control ──────────────────────────────────────────────────
    def _start_scan(self, scan_type: str):
        if self.worker and self.worker.isRunning():
            return

        self.scan_results = []
        if scan_type != "mods":
            self.findings_table.setRowCount(0)
        self.all_results_table.setRowCount(0)
        self.scan_start_time = time.time()

        deep = self.deep_scan_check.isChecked() if hasattr(self, 'deep_scan_check') else False

        self.worker = ScanWorker(
            scan_type=scan_type,
            settings=self.settings,
            deep_scan=deep,
        )
        self.worker.progress_update.connect(self._on_progress)
        self.worker.result_found.connect(self._on_result)
        self.worker.scan_finished.connect(self._on_scan_finished)
        self.worker.mod_result.connect(self._on_mod_result)
        self.worker.status_update.connect(self._on_status)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()

        self.full_scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.verdict_label.setText(self.i18n.t("scanning"))
        self.verdict_label.setStyleSheet("""
            QLabel { color: #58a6ff; background: #0d1f3c; border: 2px solid #1f6feb;
                     border-radius: 16px; padding: 24px; }
        """)
        self.status_label.setText(self.i18n.t("msg_scan_started"))
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Scanning...")

    def _stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.status_label.setText("Scan stopped by user")

    def _on_progress(self, module: str, current: int, total: int):
        if total > 0:
            pct = int((current / total) * 100)
            self.progress_bar.setValue(pct)
            self.progress_bar.setFormat(f"{module}: {current}/{total} ({pct}%)")
            if hasattr(self, 'mods_progress'):
                self.mods_progress.setValue(pct)
                self.mods_progress.setFormat(f"{current}/{total}")

    def _on_result(self, result_dict: dict):
        self.scan_results.append(
            ScanResult(**{k: v for k, v in result_dict.items()
                         if k in ['scanner', 'category', 'name', 'description',
                                  'severity', 'filepath', 'line_number', 'evidence',
                                  'details']})
        )
        self._add_finding_row(result_dict)
        self._add_all_results_row(result_dict)
        self._update_stats()

    def _on_mod_result(self, mod_result):
        self.mod_results.append(mod_result)
        self._add_mod_row(mod_result)

    def _on_scan_finished(self, results, duration):
        self.full_scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete!")

        self.status_label.setText(
            self.i18n.t("msg_scan_complete", time=format_duration(duration))
        )
        self.stat_duration.set_value(format_duration(duration))

        # Update verdict
        critical = len([r for r in self.scan_results if r.severity >= 90])
        high = len([r for r in self.scan_results if 70 <= r.severity < 90])

        if critical > 0 or high > 2:
            self.verdict_label.setText(self.i18n.t("cheater_detected"))
            self.verdict_label.setStyleSheet("""
                QLabel { color: #f85149; background: #2d0a0a; border: 3px solid #da3633;
                         border-radius: 16px; padding: 24px; }
            """)
        else:
            self.verdict_label.setText(self.i18n.t("player_clean"))
            self.verdict_label.setStyleSheet("""
                QLabel { color: #3fb950; background: #0a2d0a; border: 3px solid #238636;
                         border-radius: 16px; padding: 24px; }
            """)

        # Update kernel verdict too
        kernel_results = [r for r in self.scan_results
                          if r.scanner == "KernelCheck" and r.severity >= 80]
        if kernel_results:
            self.kernel_verdict.setText(self.i18n.t("kernel_cheat_detected"))
            self.kernel_verdict.setStyleSheet("""
                QLabel { color: #f85149; background: #2d0a0a; border: 2px solid #da3633;
                         border-radius: 12px; padding: 16px; font-weight: 800; }
            """)
        else:
            self.kernel_verdict.setText(self.i18n.t("kernel_clean"))
            self.kernel_verdict.setStyleSheet("""
                QLabel { color: #3fb950; background: #0a2d0a; border: 2px solid #238636;
                         border-radius: 12px; padding: 16px; }
            """)

        # Auto evidence collection
        if self.settings.evidence_auto_collect and self.scan_results:
            self.evidence_collector.save_scan_results(self.scan_results)
            self.evidence_collector.collect_process_list()

    def _on_status(self, status: str):
        self.status_label.setText(status)
        self.progress_label.setText(status)

    def _on_error(self, error: str):
        logger.error(error)
        self.status_label.setText(f"Error: {error}")

    # ── Table Helpers ─────────────────────────────────────────────────
    def _add_finding_row(self, r: dict):
        row = self.findings_table.rowCount()
        self.findings_table.insertRow(row)
        sev = r.get("severity", 0)
        color = QColor(severity_color(sev))

        items = [
            r.get("scanner", ""),
            r.get("category", ""),
            r.get("name", ""),
            f"{sev} ({severity_label(sev)})",
            r.get("description", ""),
        ]
        for col, text in enumerate(items):
            item = QTableWidgetItem(str(text))
            if col == 3:
                item.setForeground(QBrush(color))
                item.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            self.findings_table.setItem(row, col, item)

        # Keep table scrolled to bottom
        self.findings_table.scrollToBottom()

    def _add_all_results_row(self, r: dict):
        row = self.all_results_table.rowCount()
        self.all_results_table.insertRow(row)
        sev = r.get("severity", 0)
        color = QColor(severity_color(sev))

        items = [
            r.get("scanner", ""),
            r.get("category", ""),
            r.get("name", ""),
            f"{sev}",
            r.get("filepath", ""),
            r.get("description", ""),
        ]
        for col, text in enumerate(items):
            item = QTableWidgetItem(str(text))
            if col == 3:
                item.setForeground(QBrush(color))
                item.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            self.all_results_table.setItem(row, col, item)

    def _add_mod_row(self, mod: ModScanResult):
        row = self.mods_table.rowCount()
        self.mods_table.insertRow(row)

        status_colors = {
            "CLEAN": "#3fb950", "SUSPICIOUS": "#d29922",
            "CHEAT_DETECTED": "#f85149", "ERROR": "#8b949e"
        }
        color = QColor(status_colors.get(mod.status, "#8b949e"))

        items = [
            mod.filename,
            mod.status,
            str(mod.severity),
            str(mod.classes_scanned),
            str(len(mod.findings)),
            format_size(mod.file_size),
        ]
        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            if col == 1:
                item.setForeground(QBrush(color))
                item.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            elif col == 2:
                item.setForeground(QBrush(QColor(severity_color(mod.severity))))
                item.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            self.mods_table.setItem(row, col, item)

        # Add to kernel table if it's a kernel result
        if mod.status == "CHEAT_DETECTED":
            for f in mod.findings[:3]:
                kr = self.kernel_table.rowCount()

    def _on_mod_selected(self):
        """Show detailed findings for selected mod."""
        self.mod_detail_tree.clear()
        rows = self.mods_table.selectedIndexes()
        if not rows:
            return

        row = rows[0].row()
        if row < len(self.mod_results):
            mod = self.mod_results[row]
            self.mod_detail_title.setText(
                f"{mod.filename} — {mod.status} (Severity: {mod.severity})"
            )

            # Group findings by class
            by_class = {}
            for f in mod.findings:
                cn = f.get("class_name", "Unknown")
                if cn not in by_class:
                    by_class[cn] = []
                by_class[cn].append(f)

            for class_name, findings in by_class.items():
                class_item = QTreeWidgetItem([class_name, "", "", ""])
                class_item.setFont(0, QFont("Segoe UI", 11, QFont.Weight.Bold))
                for f in findings:
                    sev = f.get("severity", 0)
                    child = QTreeWidgetItem([
                        f.get("description", "")[:100],
                        f.get("type", ""),
                        f"{sev} ({severity_label(sev)})",
                        f.get("evidence", "")[:200],
                    ])
                    child.setForeground(2, QBrush(QColor(severity_color(sev))))
                    class_item.addChild(child)
                self.mod_detail_tree.addTopLevelItem(class_item)
                class_item.setExpanded(True)

    def _update_stats(self):
        critical = len([r for r in self.scan_results if r.severity >= 90])
        high = len([r for r in self.scan_results if 70 <= r.severity < 90])
        medium = len([r for r in self.scan_results if 50 <= r.severity < 70])
        low = len([r for r in self.scan_results if r.severity < 50])

        self.stat_critical.set_value(str(critical))
        self.stat_high.set_value(str(high))
        self.stat_medium.set_value(str(medium))
        self.stat_low.set_value(str(low))

        if self.scan_start_time > 0:
            elapsed = time.time() - self.scan_start_time
            self.stat_duration.set_value(format_duration(elapsed))

    # ── Actions ───────────────────────────────────────────────────────
    def _scan_mods_directory(self):
        directory = QFileDialog.getExistingDirectory(
            self, "Select Mods Directory"
        )
        if directory:
            self.worker = ScanWorker(
                scan_type="mods",
                settings=self.settings,
                mod_dir=directory,
                deep_scan=self.deep_scan_check.isChecked(),
            )
            self.worker.progress_update.connect(self._on_progress)
            self.worker.result_found.connect(self._on_result)
            self.worker.scan_finished.connect(self._on_scan_finished)
            self.worker.mod_result.connect(self._on_mod_result)
            self.worker.status_update.connect(self._on_status)
            self.worker.start()

    def _generate_report(self):
        if not self.scan_results:
            QMessageBox.information(self, "Info", "No scan results to report.")
            return

        duration = time.time() - self.scan_start_time if self.scan_start_time else 0
        path = self.report_generator.generate_html_report(
            self.scan_results,
            scan_duration=duration,
            player_name=self.player_input.text() or "Unknown",
            staff_name=self.staff_input.text() or "Staff",
            server_name=self.server_input.text() or "Server",
            mod_results=self.mod_results if self.mod_results else None,
        )
        QMessageBox.information(
            self, "Report Generated",
            self.i18n.t("msg_report_generated", path=path)
        )
        # Open in browser
        webbrowser.open(f"file:///{path}")

    def _collect_evidence(self):
        self.evidence_collector.collect_screenshot("dashboard")
        self.evidence_collector.collect_process_list()
        if self.scan_results:
            self.evidence_collector.save_scan_results(self.scan_results)
        QMessageBox.information(
            self, "Evidence",
            self.i18n.t("msg_evidence_collected")
        )

    def _export_results(self):
        if not self.scan_results:
            QMessageBox.information(self, "Info", "No results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", f"ss_results_{get_file_timestamp()}.json",
            "JSON Files (*.json)"
        )
        if path:
            data = [r.to_dict() for r in self.scan_results]
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.status_label.setText(f"Exported {len(data)} results to {path}")

    def _show_guide(self):
        dialog = GuideDialog(self.i18n, self)
        dialog.exec()

    def _show_about(self):
        QMessageBox.about(
            self, f"About {APP_NAME}",
            f"<h2>{APP_NAME} v{APP_VERSION}</h2>"
            f"<p>Anti-Cheat Screenshare Tool for Minecraft</p>"
            f"<p>Database: v{self.db.version}</p>"
            f"<p>&copy; 2026 SS-Tools Team</p>"
        )

    def _switch_language(self, index):
        lang = "id" if index == 0 else "en"
        self.settings.language = lang
        self.i18n.set_language(lang)
        self.settings.save()
        QMessageBox.information(
            self, "Language",
            "Language changed. Restart the application for full effect."
        )

    def _save_settings(self):
        self.settings.language = "id" if self.settings_lang.currentIndex() == 0 else "en"
        self.settings.decompiler = self.settings_decompiler.currentText()
        self.settings.max_threads = self.settings_threads.value()
        self.settings.auto_update_db = self.settings_auto_update.isChecked()
        self.settings.cache_enabled = self.settings_cache.isChecked()
        self.settings.deep_scan_mode = self.settings_deep.isChecked()
        self.settings.kernel_check_enabled = self.settings_kernel.isChecked()
        self.settings.memory_scan_enabled = self.settings_memory.isChecked()
        self.settings.network_scan_enabled = self.settings_network.isChecked()
        self.settings.browser_scan_enabled = self.settings_browser.isChecked()

        for name, inp in self.decompiler_inputs.items():
            setattr(self.settings, f"{name.lower()}_path", inp.text())

        self.settings.save()
        self.status_label.setText(self.i18n.t("msg_settings_saved"))
        QMessageBox.information(self, "Settings", self.i18n.t("msg_settings_saved"))

    def _reset_settings(self):
        self.settings = AppSettings()
        self.settings.save()
        QMessageBox.information(self, "Settings", "Settings reset to default.")

    def _update_database(self):
        self.status_label.setText("Updating database...")

        def callback(updated, msg):
            self.db_version_label.setText(f"DB: v{self.db.version}")
            self.status_label.setText(msg)

        self.db.auto_update_async(callback)

    def _browse_decompiler(self, name, widget):
        path, _ = QFileDialog.getOpenFileName(
            self, f"Select {name} JAR", "", "JAR Files (*.jar)"
        )
        if path:
            widget.setText(path)

    def _on_db_update(self, updated, msg):
        self.db_version_label.setText(f"DB: v{self.db.version}")

    def _check_first_run(self):
        first_run_file = Path.home() / ".ss_tools_welcomed"
        if not first_run_file.exists():
            dialog = WelcomeDialog(self.i18n, self)
            result = dialog.exec()
            if dialog.dont_show.isChecked():
                first_run_file.touch()
            if result == QDialog.DialogCode.Rejected:
                self._show_guide()


# ─── Entry Point ──────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
