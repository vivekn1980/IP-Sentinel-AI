# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

project_dir = Path(os.getcwd())

datas = [
    (str(project_dir / "resources"), "resources"),
]

hiddenimports = [
    "ip_sentinel",
    "ip_sentinel.core",
    "ip_sentinel.core.cache",
    "ip_sentinel.core.config",
    "ip_sentinel.core.exceptions",
    "ip_sentinel.core.ip_utils",
    "ip_sentinel.core.logger",
    "ip_sentinel.core.path_utils",
    "ip_sentinel.core.signals",
    "ip_sentinel.core.worker",
    "ip_sentinel.models",
    "ip_sentinel.models.threat_intel",
    "ip_sentinel.models.report_model",
    "ip_sentinel.providers",
    "ip_sentinel.providers.base",
    "ip_sentinel.providers.mock_provider",
    "ip_sentinel.providers.rdap_provider",
    "ip_sentinel.providers.geoip_provider",
    "ip_sentinel.reports",
    "ip_sentinel.reports.base",
    "ip_sentinel.reports.html_generator",
    "ip_sentinel.reports.pdf_generator",
    "ip_sentinel.services",
    "ip_sentinel.services.investigation_service",
    "ip_sentinel.services.dns_service",
    "ip_sentinel.ui",
    "ip_sentinel.ui.main_window",
    "ip_sentinel.ui.navigation",
    "ip_sentinel.ui.styles",
    "ip_sentinel.ui.views",
    "ip_sentinel.ui.views.dashboard_view",
    "ip_sentinel.ui.views.query_view",
    "ip_sentinel.ui.views.reports_view",
    "ip_sentinel.ui.views.logs_view",
    "ip_sentinel.ui.views.settings_view",
    "PySide6",
    "jinja2",
    "reportlab",
    "dns",
    "requests",
]

a = Analysis(
    [str(project_dir / "src" / "ip_sentinel" / "main.py")],
    pathex=[str(project_dir / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pdb"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="IP-Sentinel-AI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI mode (no black CLI window popup on launch)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
