"""Test CLI helper functions."""

import argparse
from pathlib import Path

import pytest

from password_manager import cli
from password_manager.errors import VaultNotFoundError
from password_manager.models import EntrySummary


def test_build_parser_exposes_all_commands():
    parser = cli.build_parser()
    command_action = next(action for action in parser._actions if action.dest == "command")
    commands = set(command_action.choices.keys())
    assert commands == {
        "init",
        "add",
        "list",
        "get",
        "delete",
        "generate",
        "check",
        "update",
        "search",
        "change-password",
        "lock",
    }


def test_clip_short_and_long():
    assert cli._clip("abc", 10) == "abc"
    assert cli._clip("abcdefghij", 5) == "abcd."
    assert cli._clip("ab", 1) == "a"


def test_print_summaries_empty(capsys):
    cli._print_summaries([])
    assert "No entries." in capsys.readouterr().out


def test_print_summaries_formats_row(capsys):
    from password_manager.models import utc_now

    now = utc_now()
    cli._print_summaries(
        [
            EntrySummary(
                id="12345678-1234-5678-1234-567812345678",
                service="very-long-service-name",
                username="user",
                url="https://example.com",
                created_at=now,
                updated_at=now,
            )
        ]
    )
    out = capsys.readouterr().out
    assert "very-long-service" in out
    assert "USER" in out.upper() or "user" in out


def test_generate_from_args_defaults():
    args = argparse.Namespace(
        length=12,
        no_uppercase=False,
        no_lowercase=False,
        no_digits=False,
        no_symbols=True,
    )
    password = cli._generate_from_args(args)
    assert len(password) == 12


def test_updates_from_args_conflicts():
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(
            ["--vault", "v.pwv", "update", "entry", "--password-prompt", "--generate"]
        )
    assert exc.value.code == 2


def test_updates_from_args_empty():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--vault", "v.pwv", "update", "entry"])
    assert exc.value.code == 2


def test_prompt_new_master_password_mismatch(monkeypatch):
    values = iter(["first-password1", "second-password2"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(values))
    with pytest.raises(ValueError, match="do not match"):
        cli._prompt_new_master_password()


def test_main_keyboard_interrupt(monkeypatch):
    def raise_interrupt(_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_dispatch", raise_interrupt)
    assert cli.main(["generate", "--length", "12"]) == 130


def test_main_vault_error(monkeypatch):
    def raise_not_found(_args):
        raise VaultNotFoundError("missing")

    monkeypatch.setattr(cli, "_dispatch", raise_not_found)
    assert cli.main(["--vault", "missing.pwv", "check"]) == 1


def test_get_with_details_and_empty_notes(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"

    def getpass_side_effect(prompt: str) -> str:
        if "New" in prompt or "Confirm" in prompt:
            return "master password 12"
        return "master password 12"

    monkeypatch.setattr(cli.getpass, "getpass", getpass_side_effect)
    assert cli.main(["--vault", str(path), "init"]) == 0

    monkeypatch.setattr(
        cli.getpass,
        "getpass",
        lambda prompt: "master password 12" if "Master" in prompt else "entry-pass",
    )
    assert cli.main(["--vault", str(path), "add", "svc", "--username", "u"]) == 0

    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "master password 12")
    assert cli.main(["--vault", str(path), "get", "svc", "--details"]) == 0
    out = capsys.readouterr().out
    assert "notes:" in out


def test_delete_cancelled(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"

    def getpass_values(prompt: str) -> str:
        if "New" in prompt or "Confirm" in prompt:
            return "master password 12"
        if "Master" in prompt:
            return "master password 12"
        return "entry-pass"

    monkeypatch.setattr(cli.getpass, "getpass", getpass_values)
    cli.main(["--vault", str(path), "init"])
    cli.main(["--vault", str(path), "add", "svc", "--username", "u"])

    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "master password 12")
    monkeypatch.setattr("builtins.input", lambda prompt: "no")
    assert cli.main(["--vault", str(path), "delete", "svc"]) == 0
    assert "cancelled" in capsys.readouterr().out.lower()


def test_update_with_notes_and_password_prompt(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"
    passwords = iter(
        [
            "master password 12",
            "master password 12",
            "master password 12",
            "entry-pass",
            "master password 12",
            "new-entry-pass",
            "updated note",
        ]
    )
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(passwords))
    cli.main(["--vault", str(path), "init"])
    cli.main(["--vault", str(path), "add", "svc", "--username", "u"])
    assert (
        cli.main(["--vault", str(path), "update", "svc", "--password-prompt", "--notes-prompt"])
        == 0
    )


def test_list_empty_vault(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"
    values = iter(["master password 12", "master password 12", "master password 12"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(values))
    cli.main(["--vault", str(path), "init"])
    assert cli.main(["--vault", str(path), "list"]) == 0
    assert "No entries." in capsys.readouterr().out


def test_check_missing_vault(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "master password 12")
    assert cli.main(["--vault", str(tmp_path / "missing.pwv"), "check"]) == 1


def test_main_value_error(monkeypatch):
    monkeypatch.setattr(cli, "_dispatch", lambda _args: (_ for _ in ()).throw(ValueError("bad")))
    assert cli.main(["generate", "--length", "12"]) == 1


def test_ambiguous_entry_without_summaries_prints_only_message(monkeypatch, capsys):
    from password_manager.errors import AmbiguousEntryError

    def boom(_args):
        raise AmbiguousEntryError("ambiguous", entries=[])

    monkeypatch.setattr(cli, "_dispatch", boom)
    assert cli.main(["--vault", "v.pwv", "get", "x"]) == 1
    assert "ambiguous" in capsys.readouterr().err
