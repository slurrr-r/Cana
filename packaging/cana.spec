# PyInstaller spec for CANA.
# Build on Windows: pyinstaller packaging/cana.spec

from pathlib import Path

root = Path(SPECPATH).parent

a = Analysis(
    [str(root / "main.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / "cana_ui/assets/cana.ico"), "cana_ui/assets"),
        (str(root / "cana_ui/assets/cana.png"), "cana_ui/assets"),
        (str(root / "packaging/install.ps1"), "packaging"),
        (str(root / "packaging/resolve-installer-sid.ps1"), "packaging"),
    ],
    hiddenimports=[
        "cana_engine",
        "cana_engine.ipc",
        "cana_engine.client",
        "cana_service",
        "cana_ui",
        "cana_ui.app",
        "cana_ui.controller",
        "cana_ui.window",
        "cana_ui.theme",
        "cana_ui.widgets",
        "cana_ui.icons",
        "cana_ui.brand",
        "cana_ui.traffic",
        "cana_ui.incidents",
        "cana_ui.correlated",
        "scapy.all",
        "win32serviceutil",
        "win32service",
        "win32event",
        "servicemanager",
        "win32pipe",
        "win32file",
        "win32security",
        "win32api",
        "win32con",
        "pywintypes",
        "ntsecuritycon",
        "pystray",
        "PIL",
        "PIL.Image",
        "PIL.ImageDraw",
        "PIL.ImageTk",
        "tkinter",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CANA",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon=str(root / "cana_ui/assets/cana.ico"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name="CANA",
)
