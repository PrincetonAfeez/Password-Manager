"""argparse CLI for the local password vault."""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from . import __version__
from .errors import AmbiguousEntryError, VaultError
from .generator import generate_password
from .lockfile import WriteLock
from .models import EntryCreate, EntrySummary, EntryUpdate
from .vault import Vault

READ_ONLY_COMMANDS = frozenset({"list", "get", "search"})
MUTATING_COMMANDS = frozenset({"add", "update", "delete"})

EXIT_CODES_EPILOG = """\
Exit codes:
  0    Success (includes a cancelled delete)
  1    Vault error, validation error, or ambiguous entry
  2    Usage error (bad arguments; emitted by argparse)
  130  Interrupted (Ctrl-C)
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwvault",
        description="Local encrypted password vault",
        epilog=EXIT_CODES_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--vault", default="vault.pwv", help="path to the vault file")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="create a new encrypted vault")

    add_parser = subparsers.add_parser("add", help="add an entry")
    add_parser.add_argument("service")
    add_parser.add_argument("--username", required=True)
    add_parser.add_argument("--url", default="")
    add_parser.add_argument(
        "--notes-prompt",
        action="store_true",
        help="prompt for notes (input is hidden — notes may contain secrets)",
    )
    _add_generator_options(add_parser, for_entry_commands=True)

    subparsers.add_parser("list", help="list safe entry summaries")

    get_parser = subparsers.add_parser("get", help="get one entry")
    get_parser.add_argument("entry")
    get_parser.add_argument("--reveal", action="store_true")
    get_parser.add_argument("--details", action="store_true", help="show notes explicitly")

    delete_parser = subparsers.add_parser("delete", help="delete one entry")
    delete_parser.add_argument("entry")
    delete_parser.add_argument("--yes", action="store_true")

    generate_parser = subparsers.add_parser("generate", help="generate a standalone password")
    _add_generator_options(generate_parser, for_entry_commands=False)

    subparsers.add_parser("check", help="validate that a vault decrypts cleanly")

    update_parser = subparsers.add_parser("update", help="update one entry")
    update_parser.add_argument("entry")
    update_parser.add_argument("--service")
    update_parser.add_argument("--username")
    update_parser.add_argument("--url")
    update_parser.add_argument(
        "--notes-prompt",
        action="store_true",
        help="prompt for notes (input is hidden — notes may contain secrets)",
    )
    update_parser.add_argument("--password-prompt", action="store_true")
    _add_generator_options(update_parser, for_entry_commands=True)

    search_parser = subparsers.add_parser("search", help="search entries")
    search_parser.add_argument("query")

    subparsers.add_parser(
        "change-password",
        help="rotate the master password and salt (KDF upgrade: library API only)",
    )

    subparsers.add_parser("lock", help="verify the master password and exit (no session kept)")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return _dispatch(args)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except AmbiguousEntryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if exc.entries:
            _print_summaries(exc.entries)
        return 1
    except VaultError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def _dispatch(args: argparse.Namespace) -> int:
    vault_path = Path(args.vault)

    if args.command == "generate":
        print(_generate_from_args(args))
        return 0

    if args.command == "init":
        # Single source of truth for "vault exists?" is store.initialize, which
        # checks-and-creates atomically under the write lock. The CLI used to do
        # an early check here too, which was TOCTOU-racy on concurrent inits.
        password = _prompt_new_master_password()
        vault = Vault(vault_path)
        vault.initialize(password)
        print(f"Created vault: {args.vault}")
        return 0

    if args.command == "check":
        password = getpass.getpass("Master password: ")
        Vault(vault_path).verify_password(password)
        print("OK: vault decrypted and validated")
        return 0

    if args.command == "lock":
        password = getpass.getpass("Master password: ")
        Vault(vault_path).verify_password(password)
        print("OK: master password verified (no session kept).")
        return 0

    if args.command in READ_ONLY_COMMANDS:
        if args.command == "search" and (
            not isinstance(args.query, str) or not args.query.strip()
        ):
            raise ValueError("search query must not be empty")
        password = getpass.getpass("Master password: ")
        vault = Vault(vault_path)
        vault.unlock(password)
        return _run_readonly_command(vault, args)

    if args.command == "change-password":
        old_password = getpass.getpass("Current master password: ")
        new_password = _prompt_new_master_password()
        return _run_with_write_lock(
            vault_path,
            lambda vault: _change_password(vault, old_password, new_password),
        )

    if args.command in MUTATING_COMMANDS:
        # For destructive commands, confirm BEFORE prompting for the master
        # password so a cancelled action never captures a secret.
        if args.command == "delete" and not args.yes:
            confirmation = input("Delete this entry? Type yes to continue: ")
            if confirmation != "yes":
                print("Delete cancelled.")
                return 0
        master_password = getpass.getpass("Master password: ")
        return _run_mutation(vault_path, args, master_password)

    raise ValueError(f"unknown command: {args.command}")  # pragma: no cover


def _run_mutation(vault_path: Path, args: argparse.Namespace, master_password: str) -> int:
    """Collect all interactive input *before* acquiring the write lock."""
    if args.command == "add":
        entry_password = _entry_password_from_args(args)
        notes = getpass.getpass("Notes: ") if args.notes_prompt else ""
        return _run_with_write_lock(
            vault_path,
            lambda vault: _add_entry_action(
                vault, args, master_password, entry_password, notes
            ),
        )

    if args.command == "update":
        updates = _updates_from_args(args)
        return _run_with_write_lock(
            vault_path,
            lambda vault: _update_entry_action(vault, args, master_password, updates),
        )

    if args.command == "delete":
        return _run_with_write_lock(
            vault_path,
            lambda vault: _delete_entry_action(vault, args, master_password),
        )

    raise ValueError(f"unknown command: {args.command}")  # pragma: no cover


def _run_with_write_lock(vault_path: Path, action: Callable[[Vault], int]) -> int:
    with WriteLock(vault_path):
        return action(Vault(vault_path))


def _change_password(vault: Vault, old_password: str, new_password: str) -> int:
    vault.change_master_password(old_password, new_password)
    print("Master password changed.")
    return 0


def _add_entry_action(
    vault: Vault,
    args: argparse.Namespace,
    master_password: str,
    entry_password: str,
    notes: str,
) -> int:
    vault.unlock(master_password)
    entry = vault.add_entry(
        EntryCreate(
            service=args.service,
            username=args.username,
            password=entry_password,
            url=args.url,
            notes=notes,
        )
    )
    print(f"Added entry: {entry.id} {entry.service}/{entry.username}")
    return 0


def _update_entry_action(
    vault: Vault,
    args: argparse.Namespace,
    master_password: str,
    updates: EntryUpdate,
) -> int:
    vault.unlock(master_password)
    entry = vault.update_entry(args.entry, updates)
    print(f"Updated entry: {entry.id} {entry.service}/{entry.username}")
    return 0


def _delete_entry_action(vault: Vault, args: argparse.Namespace, master_password: str) -> int:
    vault.unlock(master_password)
    vault.delete_entry(args.entry)
    print("Entry deleted.")
    return 0


def _run_readonly_command(vault: Vault, args: argparse.Namespace) -> int:
    if args.command == "list":
        _print_summaries(vault.list_entries())
        return 0

    if args.command == "get":
        entry = vault.get_entry(args.entry)
        print(f"id: {entry.id}")
        print(f"service: {entry.service}")
        print(f"username: {entry.username}")
        print(f"url: {entry.url}")
        print(f"password: {entry.password if args.reveal else '********'}")
        if args.details:
            print(f"notes: {entry.notes}")
        else:
            print("notes: ********" if entry.notes else "notes:")
        print(f"created_at: {entry.created_at.isoformat()}")
        print(f"updated_at: {entry.updated_at.isoformat()}")
        return 0

    if args.command == "search":
        _print_summaries(vault.search(args.query))
        return 0

    raise ValueError(f"unknown command: {args.command}")  # pragma: no cover


def _prompt_new_master_password() -> str:
    password = getpass.getpass("New master password: ")
    confirmation = getpass.getpass("Confirm master password: ")
    if password != confirmation:
        raise ValueError("master passwords do not match")
    return password


def _entry_password_from_args(args: argparse.Namespace) -> str:
    if getattr(args, "generate", False):
        return _generate_from_args(args)
    return getpass.getpass("Entry password: ")


def _updates_from_args(args: argparse.Namespace) -> EntryUpdate:
    if args.password_prompt and args.generate:
        raise ValueError("choose either --password-prompt or --generate, not both")

    password: str | None = None
    if args.password_prompt:
        password = getpass.getpass("Entry password: ")
    elif args.generate:
        password = _generate_from_args(args)

    notes = getpass.getpass("Notes: ") if args.notes_prompt else None
    updates = EntryUpdate(
        service=args.service,
        username=args.username,
        password=password,
        url=args.url,
        notes=notes,
    )
    if not updates.has_changes():
        raise ValueError("no updates provided")
    return updates


def _add_generator_options(parser: argparse.ArgumentParser, *, for_entry_commands: bool) -> None:
    if for_entry_commands:
        group = parser.add_argument_group("password generation (requires --generate)")
        group.add_argument(
            "--generate",
            action="store_true",
            help="generate the entry password instead of prompting",
        )
        _add_generator_length_options(group)
    else:
        _add_generator_length_options(parser)


def _add_generator_length_options(parser: argparse._ActionsContainer) -> None:
    parser.add_argument("--length", type=int, default=20, help="generated password length")
    parser.add_argument("--no-uppercase", action="store_true", help="omit uppercase letters")
    parser.add_argument("--no-lowercase", action="store_true", help="omit lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="omit digits")
    parser.add_argument("--no-symbols", action="store_true", help="omit symbols")


def _generate_from_args(args: argparse.Namespace) -> str:
    return generate_password(
        length=args.length,
        uppercase=not args.no_uppercase,
        lowercase=not args.no_lowercase,
        digits=not args.no_digits,
        symbols=not args.no_symbols,
    )


def _print_summaries(entries: list[EntrySummary]) -> None:
    if not entries:
        print("No entries.")
        return

    print("ID                                   SERVICE              USERNAME             URL")
    for entry in entries:
        print(
            f"{entry.id:<36} "
            f"{_clip(entry.service, 20):<20} "
            f"{_clip(entry.username, 20):<20} "
            f"{entry.url}"
        )


def _clip(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return value[: width - 1] + "."
