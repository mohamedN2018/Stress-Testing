# -*- mode: python ; coding: utf-8 -*-
# PyInstaller build definition for Sentinel Test Lab (Windows, one-folder, no console).
#
#   .venv\Scripts\pyinstaller.exe sentinel.spec --noconfirm
#
# Output: dist\SentinelTestLab\SentinelTestLab.exe

from PyInstaller.utils.hooks import collect_submodules

PKG = "sentinel_test_lab"

datas = [
    (f"{PKG}/ui/themes/dark.qss", f"{PKG}/ui/themes"),
    (f"{PKG}/ui/themes/app.ico", f"{PKG}/ui/themes"),
    (f"{PKG}/ui/themes/app.png", f"{PKG}/ui/themes"),
    (f"{PKG}/reporting/templates/report.html.j2", f"{PKG}/reporting/templates"),
    (f"{PKG}/reporting/templates/report_pdf.html.j2", f"{PKG}/reporting/templates"),
    (f"{PKG}/database/migrations/0001_initial.sql", f"{PKG}/database/migrations"),
]

hiddenimports = [
    "keyring.backends.Windows",
    "win32timezone",
    *collect_submodules("dns"),
    *collect_submodules(f"{PKG}.engines"),
    *collect_submodules(f"{PKG}.integrations"),
]

a = Analysis(
    ["run_sentinel.py"],  # absolute-import launcher (a package module cannot be the frozen entry script)
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # Optional external tools and dev-only packages are never bundled.
    excludes=["locust", "gevent", "zmq", "flask", "aiohttp", "pytest", "pytestqt", "_pytest",
              "tkinter", "matplotlib", "IPython", "PyQt5", "PyQt6", "PySide2"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SentinelTestLab",
    icon=f"{PKG}/ui/themes/app.ico",
    console=False,
    disable_windowed_traceback=False,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="SentinelTestLab")
