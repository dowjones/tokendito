# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Functional non-authenticated tests, and local fixtures."""
import os
from os import path
import re
import sys

import pytest
from tokendito import __version__
from utils import run_process

sys.path.insert(0, path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))


@pytest.fixture
def package_regex():
    """Get compiled package regex."""
    version_regex = re.compile(r"^\S+/(?P<version>\d.\d.\d)\D+")
    return version_regex


@pytest.fixture
def package_version():
    """Run test with access to the Tokendito package."""
    from tokendito import __version__ as tokendito_version

    return tokendito_version


@pytest.mark.run("first")
def test_package_uninstall():
    """Uninstall tokendito if it is already installed."""
    proc = run_process([sys.executable, "-m", "pip", "uninstall", "-q", "-q", "-y", "tokendito"])
    assert not proc["stderr"]
    assert proc["exit_status"] == 0


@pytest.mark.run("second")
def test_package_install():
    """Install tokendito as a python package."""
    repo_root = path.dirname(path.dirname(path.abspath(__file__))) + "/../"
    proc = run_process([sys.executable, "-m", "pip", "install", "-e", repo_root])
    assert not proc["stderr"]
    assert proc["exit_status"] == 0


def test_package_exists():
    """Check whether the package is installed."""
    proc = run_process([sys.executable, "-m", "pip", "show", "tokendito"])
    assert not proc["stderr"]
    assert proc["exit_status"] == 0


# Declare package_version and package_regex as an re.Pattern object
package_version = f"{__version__}"
package_regex = re.compile(r"^\S+/(?P<version>\d+\.\d+\.\d+(\.\w+)?)\D*")


# Helper function for assertions
def assert_process_successful(proc):
    """Assert that the process ran successfully.

    Args:
        proc (dict): The process dictionary.

    Raises:
        AssertionError: If the process had an error or did not exit with status code 0.

    """
    assert not proc["stderr"]
    assert proc["exit_status"] == 0


def assert_version_matches(expected_version, stdout, regex):
    """Assert that the version matches the expected version.

    Args:
        expected_version (str): The expected version.
        stdout (str): The output string to search for the version.
        regex (re.Pattern): The compiled regex pattern to match the version.

    Raises:
        AssertionError: If the expected version does not match the actual version.

    """
    match = re.match(regex, stdout)
    assert match is not None, f"No version found in {stdout}"

    local_version = match.group("version")
    assert expected_version == local_version, f"Expected {expected_version}, got {local_version}"


@pytest.mark.parametrize(
    "runnable",
    [
        [sys.executable, "-m", "tokendito", "--version"],
        [sys.executable, sys.path[0] + "/tokendito/tokendito.py", "--version"],
        ["tokendito", "--version"],
    ],
)
def test_version(runnable):
    """Check if the package version is the same when running in different ways."""
    proc = run_process(runnable)
    assert_process_successful(proc)
    assert_version_matches(package_version, proc["stdout"], package_regex)


def test_parameter_collection(monkeypatch, tmpdir):
    """Ensure that the order of arguments has the correct behavior."""
    from argparse import Namespace

    from tokendito import user
    from tokendito.config import Config

    config = Config()
    data = "[default]\n"
    data += "okta_username = pytest_ini\n"
    data += "aws_region = pytest_ini\n"
    data += "okta_org = pytest_ini\n"
    path = tmpdir.mkdir("pytest").join("pytest.ini")
    path.write(data)
    config_ini = user.process_ini_file(path, "default")

    env = {
        "TOKENDITO_OKTA_ORG": "pytest_env",
        "okta_tile": "https://acme.okta.org/_env",
    }
    monkeypatch.setattr(os, "environ", env)
    config_env = user.process_environment()

    args = {
        "okta_username": "pytest_arg",
        "okta_tile": "https://acme.okta.org/_arg",
    }
    config_arg = user.process_arguments(Namespace(**args))
    config.update(config_ini)
    config.update(config_env)
    config.update(config_arg)
    assert config.aws["region"] == "pytest_ini"
    assert config.okta["org"] == "pytest_env"
    assert config.okta["username"] == "pytest_arg"
    assert config.okta["tile"] == "https://acme.okta.org/_arg"


def test_quiet_failure():
    """Ensure we exit without all the necessary arguments."""
    args = ["--quiet"]
    executable = [sys.executable, "-m", "tokendito"]
    runnable = executable + args
    proc = run_process(runnable)
    assert proc["exit_status"] == 1
    assert "Could not validate configuration to run in quiet mode" in proc["stderr"]


def test_generate_config(custom_args, config_file):
    """Test writing to a config file."""
    from tokendito import user
    from tokendito.config import Config

    pytest_cfg = Config()
    tool_args = user.parse_cli_args(custom_args)
    config_arg = user.process_arguments(tool_args)
    pytest_cfg.update(config_arg)

    if (
        pytest_cfg.okta["tile"] is None
        or pytest_cfg.okta["mfa"] is None
        or not pytest_cfg.okta["username"]
    ):
        pytest_cfg.okta["tile"] = "https://pytest/home/amazon_aws/0123456789abcdef0123/456"
        pytest_cfg.okta["mfa"] = "push"
        pytest_cfg.okta["username"] = "pytest"

    # Rebuild argument list
    args = [
        "--configure",
        "--config-file",
        f"{config_file}",
        "--okta-tile",
        f"{pytest_cfg.okta['tile']}",
        "--okta-mfa",
        f"{pytest_cfg.okta['mfa']}",
        "--username",
        f"{pytest_cfg.okta['username']}",
    ]
    executable = [sys.executable, "-m", "tokendito"]
    runnable = executable + args
    proc = run_process(runnable)
    assert proc["exit_status"] == 0
