"""
SS-Tools Ultimate - GUI Stylesheet
Professional dark theme with red-green accent colors.
"""

DARK_STYLESHEET = """
/* ── Global ── */
QWidget {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: 'Segoe UI', 'Noto Sans', system-ui, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #0d1117;
}

/* ── Tab Widget ── */
QTabWidget::pane {
    border: 1px solid #30363d;
    border-radius: 8px;
    background: #0d1117;
    margin-top: -1px;
}

QTabBar::tab {
    background: #161b22;
    color: #8b949e;
    padding: 10px 20px;
    margin-right: 2px;
    border: 1px solid #30363d;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-weight: 600;
    min-width: 100px;
}

QTabBar::tab:selected {
    background: #0d1117;
    color: #58a6ff;
    border-bottom: 3px solid #58a6ff;
}

QTabBar::tab:hover:!selected {
    background: #1c2128;
    color: #e6edf3;
}

/* ── Buttons ── */
QPushButton {
    background-color: #238636;
    color: #ffffff;
    border: 1px solid #2ea043;
    border-radius: 8px;
    padding: 10px 24px;
    font-weight: 700;
    font-size: 14px;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #2ea043;
    border-color: #3fb950;
}

QPushButton:pressed {
    background-color: #196c2e;
}

QPushButton:disabled {
    background-color: #21262d;
    color: #484f58;
    border-color: #30363d;
}

QPushButton#dangerBtn {
    background-color: #da3633;
    border-color: #f85149;
}

QPushButton#dangerBtn:hover {
    background-color: #f85149;
}

QPushButton#secondaryBtn {
    background-color: #21262d;
    border-color: #30363d;
    color: #c9d1d9;
}

QPushButton#secondaryBtn:hover {
    background-color: #30363d;
    border-color: #8b949e;
}

/* ── Input Fields ── */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 12px;
    color: #e6edf3;
    font-size: 13px;
    selection-background-color: #1f6feb;
}

QLineEdit:focus, QTextEdit:focus {
    border-color: #58a6ff;
    outline: none;
}

QComboBox {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 12px;
    color: #e6edf3;
    min-width: 120px;
}

QComboBox::drop-down {
    border: none;
    width: 30px;
}

QComboBox QAbstractItemView {
    background-color: #161b22;
    border: 1px solid #30363d;
    selection-background-color: #1f6feb;
    color: #e6edf3;
}

QSpinBox {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
    color: #e6edf3;
}

QCheckBox {
    spacing: 8px;
    color: #e6edf3;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 2px solid #30363d;
    background: #0d1117;
}

QCheckBox::indicator:checked {
    background-color: #238636;
    border-color: #2ea043;
}

/* ── Progress Bar ── */
QProgressBar {
    border: 1px solid #30363d;
    border-radius: 8px;
    text-align: center;
    background: #161b22;
    color: #e6edf3;
    font-weight: 700;
    min-height: 28px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #238636, stop:0.5 #2ea043, stop:1 #3fb950);
    border-radius: 7px;
}

/* ── Tables ── */
QTableWidget, QTreeWidget {
    background-color: #0d1117;
    alternate-background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    gridline-color: #21262d;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 10px 8px;
    border: none;
    border-bottom: 2px solid #30363d;
    font-weight: 700;
    font-size: 12px;
    text-transform: uppercase;
}

QTableWidget::item {
    padding: 6px 8px;
    border-bottom: 1px solid #21262d;
}

QTreeWidget::item {
    padding: 4px;
    border-bottom: 1px solid #21262d;
}

/* ── Scrollbars ── */
QScrollBar:vertical {
    background: #0d1117;
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: #30363d;
    border-radius: 5px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background: #484f58;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background: #0d1117;
    height: 10px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background: #30363d;
    border-radius: 5px;
    min-width: 30px;
}

/* ── Labels ── */
QLabel {
    color: #e6edf3;
}

QLabel#headerLabel {
    font-size: 24px;
    font-weight: 800;
    color: #58a6ff;
}

QLabel#subLabel {
    font-size: 12px;
    color: #8b949e;
}

QLabel#verdictClean {
    font-size: 36px;
    font-weight: 900;
    color: #3fb950;
    background: #0a2d0a;
    border: 3px solid #238636;
    border-radius: 16px;
    padding: 20px;
}

QLabel#verdictCheat {
    font-size: 36px;
    font-weight: 900;
    color: #f85149;
    background: #2d0a0a;
    border: 3px solid #da3633;
    border-radius: 16px;
    padding: 20px;
}

QLabel#statNumber {
    font-size: 32px;
    font-weight: 900;
}

QLabel#statLabel {
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
}

/* ── Group Box ── */
QGroupBox {
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-top: 16px;
    padding-top: 20px;
    font-weight: 700;
    color: #58a6ff;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 8px;
}

/* ── Splitter ── */
QSplitter::handle {
    background-color: #30363d;
    width: 2px;
}

/* ── Tool Tips ── */
QToolTip {
    background-color: #1c2128;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px;
    font-size: 12px;
}

/* ── Menu ── */
QMenuBar {
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 2px;
}

QMenuBar::item {
    padding: 6px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background: #1f6feb;
}

QMenu {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 4px;
}

QMenu::item {
    padding: 8px 24px;
    border-radius: 4px;
}

QMenu::item:selected {
    background: #1f6feb;
}

/* ── Status Bar ── */
QStatusBar {
    background: #161b22;
    border-top: 1px solid #30363d;
    color: #8b949e;
    font-size: 12px;
}

/* ── Dialog ── */
QDialog {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 12px;
}
"""
