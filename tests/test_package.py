"""Test package functionality."""

import importlib

import password_manager
from password_manager import Vault
from password_manager.cli import build_parser, main


def test_package_version_and_exports():
    assert password_manager.__version__ == "0.1.2"
    assert "Vault" in password_manager.__all__
    assert Vault is password_manager.Vault


def test_main_module_runnable():
    mod = importlib.import_module("password_manager.__main__")
    assert mod.main is main


def test_build_parser_prog():
    assert build_parser().prog == "pwvault"
