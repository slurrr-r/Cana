"""Mocked Windows service / install-path tests.

This environment is Linux. These tests simulate Windows SCM launch,
ProgramData config, and frozen-exe behavior without pywin32 or SCM.
"""

from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

from cana_engine.config import (
    CANAConfig,
    default_config_path,
    load_config,
    load_installer_user_sid,
    prepare_runtime_config,
    public_config_dict,
    save_installer_user_sid,
)
from cana_service.service import (
    launched_by_service_control_manager,
    run_service_entry,
)
from main import parse_args


def test_windows_default_config_uses_programdata(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "CANA"
    monkeypatch.setattr("cana_engine.config.uses_program_data", lambda: True)
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: root)
    expected = root / "config.json"
    assert default_config_path() == expected


def test_windows_prepare_runtime_config_writes_programdata(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "CANA"
    monkeypatch.setattr("cana_engine.config.uses_program_data", lambda: True)
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: root)
    monkeypatch.setattr(
        "cana_engine.config.default_config_path",
        lambda: root / "config.json",
    )
    config = prepare_runtime_config(CANAConfig())
    assert config.database_path == str(root / "cana.db")
    assert config.sessions_dir == str(root / "sessions")
    assert config.logs_dir == str(root / "logs")
    loaded = load_config(root / "config.json")
    assert loaded.database_path == config.database_path


def test_frozen_exe_config_still_uses_programdata_on_windows(
    monkeypatch, tmp_path: Path
) -> None:
    programdata = tmp_path / "ProgramData" / "CANA"
    monkeypatch.setattr("cana_engine.config.uses_program_data", lambda: True)
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: programdata)
    monkeypatch.setattr(
        "cana_engine.config.sys.executable",
        str(tmp_path / "Program Files" / "CANA" / "CANA.exe"),
    )
    path = default_config_path()
    assert path == programdata / "config.json"
    assert "Program Files" not in str(path)


def test_unelevated_sid_prefers_explorer_owner(monkeypatch) -> None:
    monkeypatch.setattr(
        "cana_service.install._explorer_owner_sid", lambda: "S-1-5-21-console"
    )
    monkeypatch.setattr(
        "cana_service.install._current_windows_sid", lambda: "S-1-5-21-elevated"
    )
    from cana_service.install import _unelevated_windows_sid

    assert _unelevated_windows_sid() == "S-1-5-21-console"


def test_unelevated_sid_does_not_fall_back_to_elevated(monkeypatch) -> None:
    monkeypatch.setattr("cana_service.install._explorer_owner_sid", lambda: "")
    monkeypatch.setattr(
        "cana_service.install._current_windows_sid", lambda: "S-1-5-21-elevated"
    )
    from cana_service.install import _unelevated_windows_sid

    assert _unelevated_windows_sid() == ""


def test_record_installer_user_sid_fails_closed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: tmp_path / "CANA")
    monkeypatch.setattr("cana_service.install._unelevated_windows_sid", lambda: "")
    from cana_service.install import record_installer_user_sid

    with pytest.raises(RuntimeError):
        record_installer_user_sid()


def test_installed_runtime_ignores_cana_config(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CANA_CONFIG", str(tmp_path / "hijack.json"))
    monkeypatch.setattr("cana_engine.config.is_installed_runtime", lambda: True)
    monkeypatch.setattr("cana_engine.config.uses_program_data", lambda: True)
    monkeypatch.setattr(
        "cana_engine.config.program_data_dir", lambda: tmp_path / "ProgramData" / "CANA"
    )
    assert default_config_path() == tmp_path / "ProgramData" / "CANA" / "config.json"


def test_record_installer_user_sid_uses_explicit_value(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "CANA"
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: root)
    from cana_service.install import record_installer_user_sid

    assert record_installer_user_sid("S-1-5-21-1-2-3-1001") == "S-1-5-21-1-2-3-1001"
    assert load_installer_user_sid() == "S-1-5-21-1-2-3-1001"


def test_installer_user_sid_roundtrip(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "CANA"
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: root)
    path = save_installer_user_sid("S-1-5-21-1-2-3-1001")
    assert path == root / "installer-user.sid"
    assert load_installer_user_sid() == "S-1-5-21-1-2-3-1001"


def test_record_installer_user_sid_rejects_system(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: tmp_path / "CANA")
    from cana_service.install import record_installer_user_sid

    with pytest.raises(RuntimeError):
        record_installer_user_sid("S-1-5-18")


def test_record_installer_user_sid_rejects_malformed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: tmp_path / "CANA")
    from cana_service.install import record_installer_user_sid

    with pytest.raises(RuntimeError):
        record_installer_user_sid("S-1-5-21-not-a-sid")


def test_load_installer_user_sid_ignores_invalid_file(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "CANA"
    root.mkdir()
    (root / "installer-user.sid").write_text("S-1-5-18\n", encoding="utf-8")
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: root)
    assert load_installer_user_sid() == ""


def test_load_installer_user_sid_tolerates_utf8_bom(
    monkeypatch, tmp_path: Path
) -> None:
    root = tmp_path / "CANA"
    root.mkdir()
    sid = "S-1-5-21-1-2-3-1001"
    (root / "installer-user.sid").write_bytes(b"\xef\xbb\xbf" + sid.encode("ascii"))
    monkeypatch.setattr("cana_engine.config.program_data_dir", lambda: root)
    assert load_installer_user_sid() == sid


def test_public_config_omits_token() -> None:
    payload = public_config_dict(CANAConfig())
    assert "control_token" not in payload


def test_scm_launch_detects_service_binpath(monkeypatch) -> None:
    monkeypatch.setattr("cana_service.service.sys.platform", "win32")
    assert launched_by_service_control_manager([]) is True
    assert launched_by_service_control_manager(["--service"]) is False
    assert launched_by_service_control_manager(["--ui"]) is False
    assert launched_by_service_control_manager(["install"]) is False


@pytest.mark.skipif(os.name == "nt", reason="Linux-only SCM detection check")
def test_scm_launch_never_true_on_linux(monkeypatch) -> None:
    monkeypatch.setattr("cana_service.service.sys.platform", "linux")
    assert launched_by_service_control_manager([]) is False
    assert launched_by_service_control_manager(["--service"]) is False


def test_run_service_entry_is_foreground_debug(monkeypatch) -> None:
    calls = []

    def fake_foreground(config=None):
        calls.append("foreground")
        return 0

    monkeypatch.setattr("cana_service.service.run_foreground", fake_foreground)
    assert run_service_entry() == 0
    assert calls == ["foreground"]


def test_handle_service_cli_empty_args_dispatches_scm(monkeypatch) -> None:
    calls = []

    def fake_scm():
        calls.append("scm")
        return 0

    monkeypatch.setattr("cana_service.service.os_is_windows", lambda: True)
    monkeypatch.setattr("cana_service.service._win32", {"servicemanager": object()})
    monkeypatch.setattr("cana_service.service.run_as_windows_service", fake_scm)
    from cana_service.service import handle_service_cli

    assert handle_service_cli([]) == 0
    assert calls == ["scm"]


def test_main_frozen_empty_argv_falls_back_to_ui(monkeypatch) -> None:
    calls = []

    def fake_scm():
        from cana_service.service import NotStartedBySCM

        calls.append("scm")
        raise NotStartedBySCM()

    def fake_ui():
        calls.append("ui")
        return 0

    monkeypatch.setattr("cana_service.service.run_as_windows_service", fake_scm)
    monkeypatch.setattr("cana_ui.app.run_ui", fake_ui)
    monkeypatch.setattr("main.sys.frozen", True, raising=False)
    monkeypatch.setattr("main.sys.argv", ["CANA.exe"])
    from main import main

    assert main(None) == 0
    assert calls == ["scm", "ui"]


def test_main_service_flag_uses_scm_entry(monkeypatch) -> None:
    args = parse_args(["--service"])
    assert args.service is True
    called = {}

    def fake_entry(config=None):
        called["config"] = config
        return 0

    monkeypatch.setattr("cana_service.service.run_service_entry", fake_entry)
    from main import main

    assert main(["--service"]) == 0
    assert "config" in called


def test_main_install_service_flag_runs_installer(monkeypatch) -> None:
    monkeypatch.setattr("cana_service.install.install_packaged_service", lambda: 0)
    from main import main

    assert main(["--install-service"]) == 0


def test_frozen_service_command_is_bare_cana_exe(monkeypatch) -> None:
    monkeypatch.setattr("cana_service.install.sys.frozen", True, raising=False)
    monkeypatch.setattr(
        "cana_service.install.sys.executable",
        "/opt/CANA/CANA.exe",
    )
    from cana_service.install import _service_command

    command = _service_command()
    assert "CANA.exe" in command
    assert "python" not in command.lower()
    assert "service.py" not in command
    assert "--service" not in command


def test_install_service_fails_when_sc_description_fails(monkeypatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    from cana_service.install import install_service

    _patch_install_happy_path(monkeypatch, tmp_path)

    def fake_sc(*args: str):
        if args and args[0] == "description":
            return SimpleNamespace(returncode=1, stdout="", stderr="sc description failed")
        return SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    monkeypatch.setattr("cana_service.install._sc", fake_sc)
    assert install_service() != 0


def test_install_service_fails_when_sc_config_fails(monkeypatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    from cana_service.install import install_service

    _patch_install_happy_path(monkeypatch, tmp_path)

    def fake_sc(*args: str):
        if args and args[0] == "config":
            return SimpleNamespace(returncode=5, stdout="", stderr="access denied")
        return SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    monkeypatch.setattr("cana_service.install._sc", fake_sc)
    assert install_service() != 0


def test_install_service_fails_when_sc_failure_fails(monkeypatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    from cana_service.install import install_service

    _patch_install_happy_path(monkeypatch, tmp_path)

    def fake_sc(*args: str):
        if args and args[0] == "failure":
            return SimpleNamespace(returncode=1, stdout="", stderr="sc failure failed")
        return SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    monkeypatch.setattr("cana_service.install._sc", fake_sc)
    assert install_service() != 0


def test_install_service_fails_when_sc_failureflag_fails(monkeypatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    from cana_service.install import install_service

    _patch_install_happy_path(monkeypatch, tmp_path)

    def fake_sc(*args: str):
        if args and args[0] == "failureflag":
            return SimpleNamespace(returncode=1, stdout="", stderr="sc failureflag failed")
        return SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    monkeypatch.setattr("cana_service.install._sc", fake_sc)
    assert install_service() != 0


def test_install_service_fails_when_sc_start_fails(monkeypatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    from cana_service.install import install_service

    _patch_install_happy_path(monkeypatch, tmp_path)

    def fake_sc(*args: str):
        if args and args[0] == "start":
            return SimpleNamespace(returncode=1053, stdout="", stderr="did not respond")
        return SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    monkeypatch.setattr("cana_service.install._sc", fake_sc)
    assert install_service() != 0


def test_install_service_succeeds_when_scm_operations_succeed(
    monkeypatch, tmp_path: Path
) -> None:
    from types import SimpleNamespace

    from cana_service.install import install_service

    _patch_install_happy_path(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "cana_service.install._sc",
        lambda *_args: SimpleNamespace(returncode=0, stdout="SUCCESS", stderr=""),
    )
    assert install_service() == 0


def test_install_service_uses_demand_when_automatic_startup_false(
    monkeypatch, tmp_path: Path
) -> None:
    from types import SimpleNamespace

    from cana_engine.config import CANAConfig
    from cana_service.install import install_service

    _patch_install_happy_path(monkeypatch, tmp_path)
    config = CANAConfig(
        database_path=str(tmp_path / "CANA" / "cana.db"),
        sessions_dir=str(tmp_path / "CANA" / "sessions"),
        logs_dir=str(tmp_path / "CANA" / "logs"),
        automatic_startup=False,
    )
    monkeypatch.setattr(
        "cana_service.install.prepare_runtime_config", lambda _config=None: config
    )
    calls = []

    def fake_sc(*args: str):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    monkeypatch.setattr("cana_service.install._sc", fake_sc)
    assert install_service() == 0
    create = [item for item in calls if item and item[0] == "create"][0]
    assert "demand" in create
    assert "auto" not in create[create.index("start=") + 1 :]
    configs = [item for item in calls if item and item[0] == "config"]
    assert configs
    assert "demand" in configs[0]


def test_install_service_treats_1056_as_already_running(
    monkeypatch, tmp_path: Path
) -> None:
    from types import SimpleNamespace

    from cana_service.install import install_service

    _patch_install_happy_path(monkeypatch, tmp_path)

    def fake_sc(*args: str):
        if args and args[0] == "start":
            return SimpleNamespace(
                returncode=1056,
                stdout="[SC] StartService FAILED 1056",
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="SUCCESS", stderr="")

    monkeypatch.setattr("cana_service.install._sc", fake_sc)
    assert install_service() == 0


def test_uninstall_service_fails_when_delete_fails(monkeypatch) -> None:
    from types import SimpleNamespace

    from cana_service.install import uninstall_service

    monkeypatch.setattr("cana_service.install._is_windows", lambda: True)
    monkeypatch.setattr("cana_service.install.log_lifecycle", lambda *_args, **_kwargs: None)

    def fake_sc(*args: str):
        if args and args[0] == "stop":
            return SimpleNamespace(returncode=1062, stdout="[SC] ControlService FAILED 1062", stderr="")
        if args and args[0] == "delete":
            return SimpleNamespace(returncode=5, stdout="", stderr="access denied")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("cana_service.install._sc", fake_sc)
    assert uninstall_service() != 0


def test_windows_module_log_roots_use_programdata() -> None:
    from packet_capture import config as packet_config
    from user_activity import config as activity_config
    from anomaly_detection import config as anomaly_config

    sources = [
        inspect.getsource(packet_config._runtime_root),
        inspect.getsource(activity_config._runtime_logs_dir),
        inspect.getsource(anomaly_config._runtime_logs_dir),
    ]
    for source in sources:
        assert "PROGRAMDATA" in source
        assert "CANA" in source
        assert "logs" in source or "CANA" in source
        assert "Program Files" not in source


def _patch_install_happy_path(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "CANA"
    config = CANAConfig(
        database_path=str(root / "cana.db"),
        sessions_dir=str(root / "sessions"),
        logs_dir=str(root / "logs"),
    )
    monkeypatch.setattr("cana_service.install._is_windows", lambda: True)
    monkeypatch.setattr(
        "cana_service.install.prepare_runtime_config", lambda _config=None: config
    )
    monkeypatch.setattr("cana_service.install._ensure_directories", lambda _config: None)
    monkeypatch.setattr(
        "cana_service.install.record_installer_user_sid", lambda: "S-1-5-21-1-2-3-1001"
    )
    monkeypatch.setattr("cana_service.install.save_config", lambda _config: root / "config.json")
    monkeypatch.setattr(
        "cana_service.install.configure_service_logging", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        "cana_service.install._service_command",
        lambda: r'"C:\Program Files\CANA\CANA.exe"',
    )
    monkeypatch.setattr("cana_service.install.log_lifecycle", lambda *_args, **_kwargs: None)


def test_run_as_windows_service_maps_error_1063(monkeypatch) -> None:
    class FakeError(Exception):
        winerror = 1063

    class FakeManager:
        def Initialize(self, *args, **kwargs):
            return None

        def PrepareToHostSingle(self, *args, **kwargs):
            return None

        def StartServiceCtrlDispatcher(self):
            raise FakeError("The service process could not connect to the service controller.")

    monkeypatch.setattr(
        "cana_service.service._win32",
        {"servicemanager": FakeManager()},
    )
    from cana_service.service import NotStartedBySCM, run_as_windows_service

    with pytest.raises(NotStartedBySCM):
        run_as_windows_service()


def test_main_exposes_build_packet_handler_without_loading_engine() -> None:
    import ast
    from pathlib import Path

    import main as main_mod

    assert callable(main_mod.build_packet_handler)
    tree = ast.parse((Path(__file__).resolve().parent.parent / "main.py").read_text(encoding="utf-8"))
    imports = [
        ast.unparse(node)
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    joined = "\n".join(imports)
    assert "cana_engine.engine" not in joined
    assert "cana_engine.handler" not in joined
    source = inspect.getsource(main_mod.build_packet_handler)
    assert "from cana_engine.handler import build_packet_handler" in source


def test_ui_frozen_path_does_not_import_service_at_module_load() -> None:
    import ast
    from pathlib import Path

    tree = ast.parse((Path(__file__).resolve().parent.parent / "main.py").read_text(encoding="utf-8"))
    top_imports = [
        ast.unparse(node)
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    joined = "\n".join(top_imports)
    assert "cana_service.service" not in joined
    assert "cana_engine.engine" not in joined
    assert "risk_scoring" not in joined


def test_svc_do_run_reports_running_before_engine_start() -> None:
    import inspect

    from cana_service import service as service_mod

    source = inspect.getsource(service_mod)
    running = source.index("SERVICE_RUNNING")
    start = source.index("self.runtime.start()")
    engine_import = source.index("from cana_engine.engine import CANAEngine")
    assert running < start
    assert engine_import > source.index("def start(self)")
    assert "CANAEngine(" not in inspect.getsource(service_mod.CANAServiceRuntime.__init__)
