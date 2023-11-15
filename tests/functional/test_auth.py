# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Functional, endt-to-end authenticated tests, and local fixtures."""
import datetime
from os import environ
from os import path
import re
import sys
import time

import pytest
from utils import run_process

sys.path.insert(0, path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))


@pytest.mark.run("first")
def test_generate_credentials(custom_args, config_file):
    """Run the tool and generate credentials."""
    import pyotp
    from tokendito import user
    from tokendito.config import config

    # Emulate helpers.process_options() bypassing interactive portions.
    tool_args = user.parse_cli_args(custom_args)
    config_ini = user.process_ini_file(config_file, "default")
    config_env = user.process_environment()
    config_arg = user.process_arguments(tool_args)

    config.update(config_ini)
    config.update(config_env)
    config.update(config_arg)

    if (
        config.aws["role_arn"] is None
        or config.okta["tile"] is None
        or config.okta["mfa"] is None
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
        "--aws-profile",
        f"{config.aws['profile']}",
        "--okta-tile",
        f"{config.okta['tile']}",
        "--okta-mfa",
        f"{config.okta['mfa']}",
        "--okta-mfa-response",
        f"{config.okta['mfa_response']}",
        "--username",
        f"{config.okta['username']}",
        "--password",
        f"{config.okta['password']}",
        "--config-file",
        f"{config.user['config_file']}",
        "--use-device-token",
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

    # Ensure the device token is written to the config file, and is correct.
    device_token = None
    match = re.search(r"(?<=okta_device_token': ')[^']+", proc["stderr"])
    if match:
        device_token = match.group(0)
    with open(config.user["config_file"]) as cfg:
        assert f"okta_device_token = {device_token}" in cfg.read()

    # print(f"stderr: {proc['stderr']}")


@pytest.mark.run("second")
def test_aws_credentials(custom_args):
    """Run the AWS cli to verify whether credentials work."""
    from tokendito import user
    from tokendito.config import config

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

    runnable = ["aws", "--profile", config.aws["profile"], "sts", "get-caller-identity"]
    proc = run_process(runnable)
    assert not proc["stderr"]
    assert proc["exit_status"] == 0
