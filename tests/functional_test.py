# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Functional tests, and local fixtures."""
import datetime
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
        # If a TypeError is raised, we are in Python 3, this is a no-op.
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
    from tokendito.__version__ import __version__ as tokendito_version

    return tokendito_version


@pytest.fixture
def custom_args(request):
    """Search the custom command-line options and return a list of keys and values."""
    options = [
        "--username",
        "--password",
        "--okta-aws-app-url",
        "--mfa-method",
        "--mfa-response",
        "--role-arn",
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
    proc = run_process(
        [sys.executable, "-m", "pip", "uninstall", "-q", "-q", "-y", "tokendito"]
    )
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
    proc = run_process(runnable)
    assert not proc["stderr"]
    assert proc["exit_status"] == 0
    match = re.match(package_regex, proc["stdout"])
    local_version = match.group("version")
    assert package_version == local_version


@pytest.mark.skipif(
    sys.version_info[:2] < (3, 5),
    reason="PyOTP Not supported in Python 2.x",
)
@pytest.mark.run("second-to-last")
def test_generate_credentials(custom_args):
    """Run the tool and generate credentials."""
    from tokendito import helpers, settings
    import pyotp

    # Emulate helpers.process_options() bypassing interactive portions.
    tool_args = helpers.setup(custom_args)
    helpers.process_ini_file(tool_args.config_file, "default")
    helpers.process_arguments(tool_args)
    helpers.process_environment()

    if (
        settings.role_arn is None
        or settings.okta_aws_app_url is None
        or settings.mfa_method is None
        or not settings.okta_username
        or not settings.okta_password
    ):
        pytest.skip("Not enough arguments collected to execute non-interactively.")

    # If a token response is present and is not in the usual 6-digit format,
    # assume it is a MFA seed and create a valid response from it.
    if (
        settings.mfa_response is not None
        and re.match("[0-9]{6}", settings.mfa_response) is None
    ):
        totp = pyotp.TOTP(settings.mfa_response, interval=30)
        # If there are a few seconds left on the TOTP timer, wait until the next round.
        time_remaining = (
            totp.interval - datetime.datetime.now().timestamp() % totp.interval
        )
        if time_remaining < 5:
            time.sleep(1 + time_remaining)
        settings.mfa_response = totp.now()
        # Update the environment variable that has been modified, if it exists
        # as this may be passed down to a subprocess.
        if "MFA_RESPONSE" in environ:
            environ["MFA_RESPONSE"] = settings.mfa_response

    # Rebuild argument list
    args = [
        "--role-arn",
        f"{settings.role_arn}",
        "--okta-aws-app-url",
        f"{settings.okta_aws_app_url}",
        "--mfa-method",
        f"{settings.mfa_method}",
        "--mfa-response",
        f"{settings.mfa_response}",
        "--username",
        f"{settings.okta_username}",
        "--password",
        f"{settings.okta_password}",
    ]
    # run as a local module, as we can't guarantee that the binary is installed.
    executable = [sys.executable, "-m", "tokendito"]
    runnable = executable + args

    proc = run_process(runnable)
    assert not proc["stderr"]
    assert proc["exit_status"] == 0


@pytest.mark.run("last")
def test_aws_credentials(custom_args):
    """Run the AWS cli to verify whether credentials work."""
    from tokendito import helpers, settings

    # Emulate helpers.process_options() bypassing interactive portions.
    tool_args = helpers.setup(custom_args)
    helpers.process_ini_file(tool_args.config_file, "default")
    helpers.process_arguments(tool_args)
    helpers.process_environment()

    if not settings.role_arn:
        pytest.skip("No AWS profile defined, test will be skipped.")
    profile = settings.role_arn.split("/")[-1]
    runnable = ["aws", "--profile", profile, "sts", "get-caller-identity"]
    proc = run_process(runnable)
    assert not proc["stderr"]
    assert proc["exit_status"] == 0
