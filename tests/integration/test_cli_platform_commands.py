"""CLI tests for the intelligence, operations, governance, integrations, and GitHub commands."""

import pytest

from python_hunter.interfaces.cli.main import run_cli


@pytest.mark.parametrize(
    "argv",
    [
        ["intelligence", "status"],
        ["posture"],
        ["remediation"],
        ["trends"],
        ["monitor", "status"],
        ["monitor", "start", "org/repo"],
        ["alerts"],
        ["incidents"],
        ["jobs"],
        ["health"],
        ["org", "list"],
        ["org", "users"],
        ["org", "teams"],
        ["org", "projects"],
        ["org", "approvals"],
        ["integrations", "list"],
        ["integrations", "status"],
        ["integrations", "test"],
        ["github", "status"],
        ["github", "prs"],
        ["github", "repositories"],
    ],
)
def test_platform_command_succeeds(argv: list[str]) -> None:
    assert run_cli(argv) == 0


def test_monitor_stop_unknown_repository_fails() -> None:
    assert run_cli(["monitor", "stop", "never/registered"]) == 1


def test_integrations_test_unknown_id_fails() -> None:
    assert run_cli(["integrations", "test", "int-missing"]) == 1


def test_verify_unknown_finding_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_cli(["verify", "no-such-finding"]) == 1
    assert "not found" in capsys.readouterr().err


@pytest.mark.parametrize("removed", ["project", "plugins"])
def test_placeholder_commands_are_gone(removed: str) -> None:
    assert run_cli([removed]) == 2
