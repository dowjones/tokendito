# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Functional tests, and local fixtures."""
import datetime
import os
from os import environ, path
import re
import subprocess
import sys
import time


import pytest

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))


def string_decode(bytestring):
    """Convert a str into a Unicode object.

    The `decode()` method is only available in byte strings. Calling on
    other string objects generates a `NameError`, and the same string is
    returned unmodified.

    :param bytestring:
    :return: decoded string
    """
    decoded_string = bytestring
    try:
        decoded_string = bytestring.decode("utf-8")
    except (NameError, TypeError):
        # If a TypeError is raised, this is a no-op.
        pass

    return decoded_string


def run_process(proc):
    """Spawn a child process.

    Returns a dict with stdout, sdterr, exit status, and command executed.
    """
    process = subprocess.Popen(proc, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdoutdata, stderrdata) = process.communicate()

    proc_status = {
        "stdout": string_decode(stdoutdata),
        "stderr": string_decode(stderrdata),
        "name": " ".join(proc),
        "exit_status": process.returncode,
    }
    return proc_status


@pytest.fixture
def package_regex():
    """Get compiled package regex."""
    version_regex = re.compile(r"^\S+/(?P<version>.*?)\s+.*$")
    return version_regex


@pytest.fixture
def package_version():
    """Run test with access to the Tokendito package."""
    from tokendito import __version__ as tokendito_version

    return tokendito_version


@pytest.fixture
def custom_args(request):
    """Search the custom command-line options and return a list of keys and values."""
    options = [
        "--username",
        "--password",
        "--okta-app-url",
        "--okta-mfa-method",
        "--okta-mfa-response",
        "--aws-role-arn",
        "--config-file",
    ]
    arg_list = []
    # pytest does not have a method for listing options, so we have look them up.
    for item in options:
        if request.config.getoption(item):
            arg_list.extend([item, request.config.getoption(item)])
    return arg_list


@pytest.mark.run("first")
def test_package_uninstall():
    """Uninstall tokendito if it is already installed."""
    proc = run_process([sys.executable, "-m", "pip", "uninstall", "-q", "-q", "-y", "tokendito"])
    assert not proc["stderr"]
    assert proc["exit_status"] == 0


@pytest.mark.run("second")
def test_package_install():
    """Install tokendito as a python package."""
    repo_root = path.dirname(path.dirname(path.abspath(__file__)))
    proc = run_process([sys.executable, "-m", "pip", "install", "-e", repo_root])
    assert not proc["stderr"]
    assert proc["exit_status"] == 0


def test_package_exists():
    """Check whether the package is installed."""
    proc = run_process([sys.executable, "-m", "pip", "show", "tokendito"])
    assert not proc["stderr"]
    assert proc["exit_status"] == 0


@pytest.mark.parametrize(
    "runnable",
    [
        [sys.executable, "-m", "tokendito", "--version"],
        [sys.executable, sys.path[0] + "/tokendito/tokendito.py", "--version"],
        ["tokendito", "--version"],
    ],
)
def test_version(package_version, package_regex, runnable):
    """Check if the package version is the same when running in different ways."""
    local_version = None
    proc = run_process(runnable)
    assert not proc["stderr"]
    assert proc["exit_status"] == 0
    match = re.match(package_regex, proc["stdout"])
    if match:
        local_version = match.group("version")
    assert package_version == local_version


def test_parameter_collection(monkeypatch, tmpdir):
    """Ensure that the order of arguments has the correct behavior."""
    from argparse import Namespace
    from tokendito import user, config

    data = "[default]\n"
    data += "okta_username = pytest_ini\n"
    data += "aws_region = pytest_ini\n"
    data += "okta_org = pytest_ini\n"
    path = tmpdir.mkdir("pytest").join("pytest.ini")
    path.write(data)
    config_ini = user.process_ini_file(path, "default")

    env = {
        "TOKENDITO_OKTA_ORG": "pytest_env",
        "okta_app_url": "https://acme.okta.org/_env",
    }
    monkeypatch.setattr(os, "environ", env)
    config_env = user.process_environment()

    args = {
        "okta_username": "pytest_arg",
        "okta_app_url": "https://acme.okta.org/_arg",
    }
    config_arg = user.process_arguments(Namespace(**args))
    config.update(config_ini)
    config.update(config_env)
    config.update(config_arg)
    assert config.aws["region"] == "pytest_ini"
    assert config.okta["org"] == "pytest_env"
    assert config.okta["username"] == "pytest_arg"
    assert config.okta["app_url"] == "https://acme.okta.org/_arg"


@pytest.mark.run("second-to-last")
def test_generate_credentials(custom_args):
    """Run the tool and generate credentials."""
    from tokendito import user, config
    import pyotp

    # Emulate helpers.process_options() bypassing interactive portions.
    tool_args = user.parse_cli_args(custom_args)
    config_ini = user.process_ini_file(tool_args.user_config_file, "default")
    config_env = user.process_environment()
    config_arg = user.process_arguments(tool_args)

    config.update(config_ini)
    config.update(config_env)
    config.update(config_arg)

    if (
        config.aws["role_arn"] is None
        or config.okta["app_url"] is None
        or config.okta["mfa_method"] is None
        or not config.okta["username"]
        or not config.okta["password"]
    ):
        pytest.skip("Not enough arguments collected to execute non-interactively.")

    # If a token response is present and is not in the usual 6-digit format,
    # assume it is a MFA seed and create a valid response from it.
    if (
        config.okta["mfa_response"] is not None
        and re.match("[0-9]{6}", config.okta["mfa_response"]) is None
    ):
        totp = pyotp.TOTP(config.okta["mfa_response"], interval=30)
        # If there are a few seconds left on the TOTP timer, wait until the next round.
        time_remaining = totp.interval - datetime.datetime.now().timestamp() % totp.interval
        if time_remaining < 5:
            time.sleep(1 + time_remaining)
        config.okta["mfa_response"] = totp.now()
        # Update the environment variable that has been modified, if it exists
        # as this may be passed down to a subprocess.
        if "TOKENDITO_OKTA_MFA_RESPONSE" in environ:
            environ["TOKENDITO_OKTA_MFA_RESPONSE"] = config.okta["mfa_response"]

    # Rebuild argument list
    args = [
        "--aws-role-arn",
        f"{config.aws['role_arn']}",
        "--okta-app-url",
        f"{config.okta['app_url']}",
        "--okta-mfa-method",
        f"{config.okta['mfa_method']}",
        "--okta-mfa-response",
        f"{config.okta['mfa_response']}",
        "--username",
        f"{config.okta['username']}",
        "--password",
        f"{config.okta['password']}",
        "--loglevel",
        "DEBUG",
    ]
    # run as a local module, as we can't guarantee that the binary is installed.
    executable = [sys.executable, "-m", "tokendito"]
    runnable = executable + args

    proc = run_process(runnable)
    assert "'password': '*****'" in proc["stderr"]
    assert f"{config.okta['password']}" not in proc["stderr"]
    assert f"{config.okta['mfa_response']}" not in proc["stderr"]
    assert '"sessionToken": "*****"' in proc["stderr"]
    assert proc["exit_status"] == 0


@pytest.mark.run("last")
def test_aws_credentials(custom_args):
    """Run the AWS cli to verify whether credentials work."""
    from tokendito import user, config

    # Emulate helpers.process_options() bypassing interactive portions.
    tool_args = user.parse_cli_args(custom_args)
    config_ini = user.process_ini_file(tool_args.user_config_file, "default")
    config_env = user.process_environment()
    config_arg = user.process_arguments(tool_args)
    config.update(config_ini)
    config.update(config_env)
    config.update(config_arg)

    if not config.aws["role_arn"]:
        pytest.skip("No AWS profile defined, test will be skipped.")
    profile = config.aws["role_arn"].split("/")[-1]
    runnable = ["aws", "--profile", profile, "sts", "get-caller-identity"]
    proc = run_process(runnable)
    assert not proc["stderr"]
    assert proc["exit_status"] == 0
