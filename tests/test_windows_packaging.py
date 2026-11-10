"""Linux-runnable checks that Windows packaging is wired correctly."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ISS = (ROOT / "packaging" / "CANA.iss").read_text(encoding="utf-8")
INSTALL_PS1 = (ROOT / "packaging" / "install.ps1").read_text(encoding="utf-8")
SPEC = (ROOT / "packaging" / "cana.spec").read_text(encoding="utf-8")
PRODUCTIZATION = (ROOT / "PRODUCTIZATION.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_inno_passes_unelevated_installer_sid() -> None:
    assert "-InstallerSid" in ISS
    assert "GetInstallerUserSid('')" in ISS
    assert "GetInstallerUserSid" in ISS
    assert "[Code]" in ISS


def test_inno_checks_service_install_exit_code() -> None:
    assert "CurStep = ssPostInstall" in ISS
    assert "if ResultCode <> 0 then" in ISS
    assert "CANA service setup failed" in ISS


def test_repair_does_not_delete_service() -> None:
    assert "sc.exe delete" not in INSTALL_PS1
    assert "WaitForStatus('Running'" in INSTALL_PS1


def test_inno_sid_validation_rejects_malformed_values() -> None:
    assert "IsValidInstallerSid" in ISS
    assert "S-1-5-21-" in ISS
    assert "RaiseException('Installer SID is not a valid unelevated user SID" in ISS
    assert "Copy(Value, 1, 9) <> 'S-1-5-21-'" in ISS
    assert "DashCount = 3" in ISS


def test_install_ps1_verifies_service_registration() -> None:
    assert "was not registered by sc.exe create" in INSTALL_PS1
    assert "not visible to the Service Control Manager" in INSTALL_PS1
    assert "Get-Service -Name $ServiceName" in INSTALL_PS1


def test_resolve_installer_sid_script_uses_explorer_owner() -> None:
    script = (ROOT / "packaging" / "resolve-installer-sid.ps1").read_text(
        encoding="utf-8"
    )
    assert "GetOwnerSid" in script
    assert "explorer.exe" in script
    assert "resolve-installer-sid.ps1" in ISS


def test_install_ps1_records_sid_and_acls() -> None:
    assert "installer-user.sid" in INSTALL_PS1
    assert "Get-CanaInstallerSid" in INSTALL_PS1 or "resolve_installer_sid" in INSTALL_PS1
    assert "Protect-CanaDataRoot" in INSTALL_PS1
    assert "*S-1-5-18" in INSTALL_PS1
    assert "*S-1-5-32-544" in INSTALL_PS1
    assert "config.json" in INSTALL_PS1
    assert "cana.db" in INSTALL_PS1
    assert "--service" not in INSTALL_PS1
    assert "Installation aborted" in INSTALL_PS1
    assert "S-1-5-21-" in INSTALL_PS1
    assert "LASTEXITCODE" in INSTALL_PS1
    assert "Invoke-CanaChecked" in INSTALL_PS1


def test_install_ps1_binpath_is_bare_exe() -> None:
    assert 'binPath= $BinPath' in INSTALL_PS1 or "binPath=" in INSTALL_PS1
    assert '`$BinPath = "`"$Exe`""' in INSTALL_PS1 or '$BinPath = "`"$Exe`""' in INSTALL_PS1


def test_install_ps1_honors_automatic_startup_and_1056() -> None:
    assert "demand" in INSTALL_PS1
    assert "automatic_startup" in INSTALL_PS1
    assert "1056" in INSTALL_PS1
    assert "Invoke-CanaChecked sc.exe start" not in INSTALL_PS1


def test_install_ps1_requires_frozen_exe_and_has_no_python_fallback() -> None:
    assert "CANA.exe" in INSTALL_PS1
    assert "Get-Command python" not in INSTALL_PS1
    assert "service.py" not in INSTALL_PS1
    assert "python.exe" not in INSTALL_PS1.lower()
    assert "Test-Path $Exe" in INSTALL_PS1
    assert "Installation aborted" in INSTALL_PS1


def test_pyinstaller_hiddenimports_include_pipe_and_security() -> None:
    for name in (
        "win32pipe",
        "win32file",
        "win32security",
        "win32api",
        "win32con",
        "ntsecuritycon",
        "pywintypes",
    ):
        assert name in SPEC


def test_docs_describe_named_pipe_not_http_token() -> None:
    assert r"\\.\pipe\CANAControl" in PRODUCTIZATION
    assert "X-CANA-Token" not in PRODUCTIZATION
    assert "X-CANA-Token" not in README
    assert "named pipe" in README.lower() or "named-pipe" in README.lower()


def test_inno_fails_closed_without_installer_sid() -> None:
    assert "RaiseException" in ISS
    assert "Installation aborted" in ISS


def test_docs_describe_native_ui_and_programdata_layout() -> None:
    assert "native" in README.lower()
    assert "cana-ui" in README
    assert r"%ProgramData%\CANA\config.json" in PRODUCTIZATION
    assert r"%ProgramData%\CANA\installer-user.sid" in PRODUCTIZATION
    assert "cana.db" in PRODUCTIZATION
    assert "S-1-5-32-544" in PRODUCTIZATION


def test_install_ps1_finds_built_exe_in_dist() -> None:
    assert "dist\\CANA\\CANA.exe" in INSTALL_PS1 or "dist/CANA/CANA.exe" in INSTALL_PS1


def test_pyinstaller_spec_is_onedir() -> None:
    assert "COLLECT(" in SPEC
    assert "exclude_binaries=True" in SPEC
    assert "Source: \"dist\\CANA\\*\"" in ISS or "dist\\CANA\\*" in ISS


def test_install_ps1_writes_config_without_bom() -> None:
    assert "UTF8Encoding($false)" in INSTALL_PS1
    assert "Set-Content -Path $ConfigPath" not in INSTALL_PS1


def test_service_name_is_consistent_everywhere() -> None:
    """Installer, service runtime, and UI must agree on the service name."""
    from cana_service.constants import SERVICE_NAME

    assert SERVICE_NAME == "CANA"
    assert f'$ServiceName = "{SERVICE_NAME}"' in INSTALL_PS1
    assert f"sc.exe create $ServiceName binPath=" in INSTALL_PS1
    controller = (ROOT / "cana_ui" / "controller.py").read_text(encoding="utf-8")
    assert "from cana_service.constants import SERVICE_NAME" in controller
    assert "SERVICE_NAME" in controller
    assert 'SERVICE_NAME = "CANA"' not in controller


def test_uninstall_stops_and_deletes_the_same_service_name() -> None:
    from cana_service.constants import SERVICE_NAME

    uninstall = (ROOT / "packaging" / "uninstall.ps1").read_text(encoding="utf-8")
    assert SERVICE_NAME in uninstall


def test_packaging_ships_cana_icon() -> None:
    assert "cana.ico" in SPEC
    assert "cana_ui.brand" in SPEC
    assert "icon=None" not in SPEC
    assert "SetupIconFile" in ISS
    assert "cana.ico" in ISS
    icon = ROOT / "cana_ui" / "assets" / "cana.ico"
    png = ROOT / "cana_ui" / "assets" / "cana.png"
    assert icon.is_file()
    assert png.is_file()


def test_packaging_does_not_reference_removed_dashboard_or_http() -> None:
    for text in (ISS, INSTALL_PS1, SPEC):
        lowered = text.lower()
        assert "streamlit" not in lowered
        assert "flask" not in lowered
        assert "http.server" not in lowered
        assert "control_token" not in lowered
        assert "x-cana-token" not in lowered
        assert "dashboard" not in lowered
