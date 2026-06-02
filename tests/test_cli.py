"""Test CLI functionality."""

from pathlib import Path

import pytest

from password_manager import cli


def set_getpass(monkeypatch, values):
    iterator = iter(values)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(iterator))


def test_cli_init_add_list_get_update_search_delete(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["master password", "master password"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    set_getpass(monkeypatch, ["master password", "entry secret"])
    assert (
        cli.main(
            [
                "--vault",
                str(path),
                "add",
                "github",
                "--username",
                "user",
                "--url",
                "https://github.com",
            ]
        )
        == 0
    )

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "list"]) == 0
    list_output = capsys.readouterr().out
    assert "github" in list_output
    assert "entry secret" not in list_output

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "get", "github"]) == 0
    get_output = capsys.readouterr().out
    assert "********" in get_output
    assert "entry secret" not in get_output

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "get", "github", "--reveal"]) == 0
    reveal_output = capsys.readouterr().out
    assert "entry secret" in reveal_output

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "update", "github", "--username", "new-user"]) == 0

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "search", "git"]) == 0
    assert "new-user" in capsys.readouterr().out

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "delete", "github", "--yes"]) == 0

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "list"]) == 0
    assert "No entries." in capsys.readouterr().out


def test_cli_change_password_and_check(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["old password", "old password"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    set_getpass(monkeypatch, ["old password", "new password", "new password"])
    assert cli.main(["--vault", str(path), "change-password"]) == 0

    set_getpass(monkeypatch, ["old password"])
    assert cli.main(["--vault", str(path), "check"]) == 1

    set_getpass(monkeypatch, ["new password"])
    assert cli.main(["--vault", str(path), "check"]) == 0


def test_cli_does_not_accept_raw_password_argument(tmp_path: Path):
    path = tmp_path / "vault.pwv"

    with pytest.raises(SystemExit) as exc:
        cli.main(["--vault", str(path), "add", "github", "--username", "user", "raw-secret"])

    assert exc.value.code == 2


def test_cli_generate_rejects_short_length():
    with pytest.raises(SystemExit) as exc:
        cli.main(["generate", "--length", "11"])
    assert exc.value.code == 2


def test_cli_generate_rejects_all_character_classes_disabled():
    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "generate",
                "--no-uppercase",
                "--no-lowercase",
                "--no-digits",
                "--no-symbols",
            ]
        )
    assert exc.value.code == 2


def test_cli_generate_password(capsys):
    assert cli.main(["generate", "--length", "16", "--no-symbols"]) == 0
    password = capsys.readouterr().out.strip()

    assert len(password) == 16


def test_cli_init_refuses_existing_vault(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["master password", "master password"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    set_getpass(monkeypatch, ["another password", "another password"])
    assert cli.main(["--vault", str(path), "init"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_cli_add_with_generate(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["master password", "master password"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    set_getpass(monkeypatch, ["master password"])
    assert (
        cli.main(
            [
                "--vault",
                str(path),
                "add",
                "github",
                "--username",
                "user",
                "--generate",
                "--length",
                "16",
                "--no-symbols",
            ]
        )
        == 0
    )

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "get", "github", "--reveal"]) == 0
    output = capsys.readouterr().out
    password_line = [line for line in output.splitlines() if line.startswith("password:")][0]
    generated = password_line.split(": ", 1)[1]
    assert len(generated) == 16
    assert "entry secret" not in output


def test_cli_ambiguous_entry_prints_summaries(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["master password", "master password"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    set_getpass(monkeypatch, ["master password", "secret-one"])
    assert cli.main(["--vault", str(path), "add", "github", "--username", "one"]) == 0

    set_getpass(monkeypatch, ["master password", "secret-two"])
    assert cli.main(["--vault", str(path), "add", "github", "--username", "two"]) == 0

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "get", "github"]) == 1

    err = capsys.readouterr().err
    assert "ambiguous entry" in err
    assert "github" in err
    assert "one" in err or "two" in err


def test_cli_short_master_password_rejected(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["short", "short"])
    assert cli.main(["--vault", str(path), "init"]) == 1


def test_cli_delete_ambiguous_prints_summaries(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["master password", "master password"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    set_getpass(monkeypatch, ["master password", "secret-one"])
    assert cli.main(["--vault", str(path), "add", "github", "--username", "one"]) == 0

    set_getpass(monkeypatch, ["master password", "secret-two"])
    assert cli.main(["--vault", str(path), "add", "github", "--username", "two"]) == 0

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "delete", "github", "--yes"]) == 1

    err = capsys.readouterr().err
    assert "ambiguous entry" in err
    assert "github" in err


def test_cli_change_password_full_flow(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["old-password12", "old-password12"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    set_getpass(monkeypatch, ["old-password12", "new-password12", "new-password12"])
    assert cli.main(["--vault", str(path), "change-password"]) == 0

    set_getpass(monkeypatch, ["old-password12"])
    assert cli.main(["--vault", str(path), "check"]) == 1

    set_getpass(monkeypatch, ["new-password12"])
    assert cli.main(["--vault", str(path), "check"]) == 0


def test_cli_lock_command(tmp_path: Path, monkeypatch, capsys):
    path = tmp_path / "vault.pwv"

    set_getpass(monkeypatch, ["master password", "master password"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    set_getpass(monkeypatch, ["master password"])
    assert cli.main(["--vault", str(path), "lock"]) == 0
    assert "no session kept" in capsys.readouterr().out.lower()


def test_cli_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "0.1.2" in capsys.readouterr().out


def test_cli_mutate_fails_when_write_lock_held(tmp_path: Path, monkeypatch, capsys):
    from threading import Thread

    from password_manager.lockfile import WriteLock

    path = tmp_path / "vault.pwv"
    set_getpass(monkeypatch, ["master password", "master password"])
    assert cli.main(["--vault", str(path), "init"]) == 0

    results: list[int] = []

    def run_add_while_locked() -> None:
        set_getpass(monkeypatch, ["master password", "entry secret"])
        results.append(
            cli.main(["--vault", str(path), "add", "github", "--username", "user"])
        )

    with WriteLock(path):
        thread = Thread(target=run_add_while_locked)
        thread.start()
        thread.join()

    assert results == [1]
    assert "locked by another writer" in capsys.readouterr().err.lower()


def test_cli_search_empty_query_exits_two():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--vault", "vault.pwv", "search", ""])
    assert exc.value.code == 2


def test_cli_search_whitespace_query_exits_two():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--vault", "vault.pwv", "search", "   "])
    assert exc.value.code == 2
