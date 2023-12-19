# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures for the user module."""
from datetime import datetime, timedelta, timezone
import os
import sys

import pytest


@pytest.mark.xfail(
    sys.platform == "win32", reason="Windows does not always handle NULL stdin correctly."
)
def test_tty_assertion(monkeypatch):
    """Test the availability of stdin."""
    import os
    import sys

    from tokendito.user import tty_assertion

    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    # Save for reuse
    old_stdin = sys.stdin
    # Test for NoneType
    with pytest.raises(SystemExit) as err:
        sys.stdin = None
        tty_assertion()
    assert err.value.code == 1

    # Test for null descriptor
    with pytest.raises(SystemExit) as err:
        sys.stdin = open(os.devnull, "w")
        tty_assertion()
    assert err.value.code == 1

    sys.stdin = old_stdin
    # Test for closed descriptor
    with pytest.raises(SystemExit) as err:
        sys.stdin = old_stdin
        # This try/except block is needed for running pytest through en editor
        try:
            os.close(sys.stdin.fileno())
        except io.UnsupportedOperation:
            pass
        tty_assertion()
    assert err.value.code == 1


def test_get_username(mocker):
    """Test whether data sent is the same as data returned."""
    from tokendito import user

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.input", return_value="pytest_patched")
    val = user.get_username()

    assert val == "pytest_patched"


def test_get_secret_input(mocker):
    """Test whether data sent is the same as data returned."""
    from tokendito import user

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.getpass", return_value="pytest_patched")
    val = user.get_secret_input()

    assert val == "pytest_patched"


def test_setup_logging():
    """Test logging setup."""
    import logging

    from tokendito import user

    # test that a default level is set on a bad level
    ret = user.setup_logging({"loglevel": "pytest"})
    assert ret == logging.INFO

    # test that a correct level is set
    ret = user.setup_logging({"loglevel": "debug"})
    assert ret == logging.DEBUG


def test_setup_early_logging(monkeypatch, tmpdir):
    """Test early logging."""
    from argparse import Namespace

    from tokendito import user

    path = tmpdir.mkdir("pytest")
    logfile = f"{path}/pytest_log"
    # test that known values are set correctly
    args = {"user_loglevel": "debug", "user_log_output_file": logfile}
    ret = user.setup_early_logging(Namespace(**args))
    assert "loglevel" in ret
    assert "log_output_file" in ret

    # test that unknown bad values are ignored
    args = {"pytest_bad": "pytest"}
    ret = user.setup_early_logging(Namespace(**args))
    assert "pytest_bad" not in ret

    # test that known values are set correctly, and bad ones ignored
    valid_keys = dict(
        TOKENDITO_USER_LOGLEVEL="debug",
        TOKENDITO_USER_LOG_OUTPUT_FILE=logfile,
    )
    invalid_keys = dict(TOKENDITO_USER_PYTEST_EXPECTED_FAILURE="pytest_expected_failure")

    monkeypatch.setattr(os, "environ", {**valid_keys, **invalid_keys})
    ret = user.setup_early_logging([])
    assert "loglevel" in ret
    assert "log_output_file" in ret
    assert "TOKENDITO_USER_PYTEST_EXPECTED_FAILURE" not in ret


def test_get_interactive_config(mocker):
    """Test if interactive configuration is collected correctly."""
    from tokendito import user

    # test that all values return correctly
    ret = user.get_interactive_config(
        tile="https://pytest/pytest", org="https://pytest", username="pytest"
    )
    assert (
        ret["okta_username"] == "pytest"
        and ret["okta_org"] == "https://pytest"
        and ret["okta_tile"] == "https://pytest/pytest"
    )

    # test that interactive values are handled correctly
    mocker.patch("tokendito.user.get_org", return_value="https://pytest")
    mocker.patch("tokendito.user.get_tile", return_value="https://pytest")
    ret = user.get_interactive_config(tile=None, org=None, username="pytest")
    assert ret["okta_username"] == "pytest" and ret["okta_org"] == "https://pytest"

    # test that a username is collected
    mocker.patch("tokendito.user.get_username", return_value="pytests")
    ret = user.get_interactive_config(
        tile="https://pytest/pytest", org="https://pytest/", username=""
    )
    assert ret["okta_username"] == "pytests"


@pytest.mark.parametrize("value,expected", [("00", 0), ("01", 1), ("5", 5)])
def test_collect_integer(mocker, value, expected):
    """Test whether integers from the user are retrieved."""
    from tokendito import user

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.input", return_value=value)
    assert user.collect_integer(10) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("", ""),
        ("https://acme.okta.org", "https://acme.okta.org"),
        ("acme.okta.org", "https://acme.okta.org"),
    ],
)
def test_get_org(mocker, url, expected):
    """Test Org URL."""
    from tokendito import user

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.input", return_value=url)
    assert user.get_org() == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("", ""),
        (
            "https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456?fromHome=true",
            "https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456?fromHome=true",
        ),
        (
            "acme.okta.org/home/amazon_aws/0123456789abcdef0123/456?fromHome=true",
            "https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456?fromHome=true",
        ),
    ],
)
def test_get_tile(mocker, url, expected):
    """Test get tile URL."""
    from tokendito import user

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.input", return_value=url)
    assert user.get_tile() == expected


@pytest.mark.parametrize(
    "test,limit,expected",
    [(0, 10, True), (5, 10, True), (10, 10, False), (-1, 10, False), (1, 0, False)],
)
def test_check_within_range(test, limit, expected):
    """Test whether a given number is in the range 0 >= num < limit."""
    from tokendito import user

    assert user.check_within_range(test, limit) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("-1", False),
        ("0", True),
        ("1", True),
        (-1, False),
        (0, True),
        (1, True),
        (3.7, False),
        ("3.7", False),
        ("seven", False),
        ("0xff", False),
        (None, False),
    ],
)
def test_check_integer(value, expected):
    """Test whether the integer testing function works within boundaries."""
    from tokendito import user

    assert user.check_integer(value) is expected


@pytest.mark.parametrize(
    "test,limit,expected", [(1, 10, True), (-1, 10, False), ("pytest", 10, False)]
)
def test_validate_input(test, limit, expected):
    """Check if a given input is within the 0 >= num < limit range."""
    from tokendito import user

    assert user.validate_input(test, limit) is expected


def test_get_input(mocker):
    """Check if provided input is return unmodified."""
    from tokendito import user

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.input", return_value="pytest_patched")
    assert user.get_input() == "pytest_patched"


def test_update_ini(tmpdir):
    """Ensure ini files are updated correctly."""
    from tokendito import user

    path = tmpdir.mkdir("pytest")
    ini_file = f"{path}/update_ini"
    profile = "pytest"
    args = {"key_pytest_1": "val_pytest_1", "key_pytest_2": "val_pytest_2"}
    ret = user.update_ini(profile=profile, ini_file=ini_file, **args)
    assert ret.get(profile, "key_pytest_1") == "val_pytest_1"
    assert ret.get(profile, "key_pytest_2") == "val_pytest_2"


def test_set_local_credentials(tmpdir):
    """Test setting credentials."""
    from tokendito import user

    # evaluate that we exit on a bad role
    with pytest.raises(SystemExit) as err:
        user.set_local_credentials(response={}, role="pytest", region="pytest", output="pytest")
    assert err.value.code == 1

    # evaluate that we succeed on a working role
    response = {
        "Credentials": {
            "AccessKeyId": "pytest",
            "SecretAccessKey": "pytest",
            "SessionToken": "pytest",
        }
    }

    path = tmpdir.mkdir("pytest")
    user.config.aws["shared_credentials_file"] = f"{path}/pytest_credentials"
    user.config.aws["config_file"] = f"{path}/pytest_config"
    ret = user.set_local_credentials(response=response, role="default")
    assert ret == "default"


def test_add_sensitive_value_to_be_masked():
    """Test adding some values only adds what is expected."""
    from tokendito import user

    # Reset global mask_items
    user.mask_items = []
    user.add_sensitive_value_to_be_masked("should be added")
    user.add_sensitive_value_to_be_masked("should be added2")
    user.add_sensitive_value_to_be_masked("should be added3", "password")
    user.add_sensitive_value_to_be_masked("should not be added", "public")

    assert "should be added" in user.mask_items
    assert "should be added2" in user.mask_items
    assert "should be added3" in user.mask_items
    assert len(user.mask_items) == 3


def test_logger_mask(caplog):
    """Test that masking data in loggger works as expected."""
    import logging

    from tokendito import user

    secret_dict = {"secret_key": "secret_val"}
    logger = logging.getLogger(__name__)
    logger.addFilter(user.MaskLoggerSecret())
    user.add_sensitive_value_to_be_masked("supersecret")
    user.add_sensitive_value_to_be_masked("another secret", "sessionToken")
    user.add_sensitive_value_to_be_masked(secret_dict["secret_key"])
    with caplog.at_level(logging.DEBUG):
        logger.debug("This should be displayed, but not: supersecret")
        logger.debug("another secret")
        logger.debug(secret_dict)
    assert "supersecret" not in caplog.text
    assert "another secret" not in caplog.text
    assert "secret_val" not in caplog.text
    assert "This should be displayed" in caplog.text


def test_display_selected_role():
    """Test that role is printed correctly."""
    from datetime import timezone

    from tokendito import user

    now = datetime.now()
    utcnow = now.replace(tzinfo=timezone.utc)

    ret = user.display_selected_role("pytest", {"Credentials": {"Expiration": utcnow}})
    assert ret is not None and "pytest" in ret

    with pytest.raises(SystemExit) as err:
        ret = user.display_selected_role("pytest", {"pytest": {}})
    assert err.value.code == 1

    assert ret is not None and "pytest" in ret


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://acme.org/", False),
        ("https://acme.okta.org/app/UserHome", False),
        ("http://login.acme.org/home/amazon_aws/0123456789abcdef0123/456", False),
        ("https://login.acme.org/?abc=def", False),
        ("acme.okta.org", False),
        ("https://acme.okta.org/", True),
    ],
)
def test_validate_org(url, expected):
    """Test whether the Okta Org URL is parsed correctly."""
    from tokendito import user

    assert user.validate_okta_org(input_url=url) is expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("pytest_deadbeef", False),
        ("http://acme.org/", False),
        ("https://acme.okta.org/app/UserHome", False),
        ("http://login.acme.org/home/amazon_aws/0123456789abcdef0123/456", False),
        ("https://login.acme.org/home/amazon_aws/0123456789abcdef0123/456", True),
        (
            "https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456?fromHome=true",
            True,
        ),
    ],
)
def test_validate_tile(url, expected):
    """Test whether the Okta tile URL is parsed correctly."""
    from tokendito import user

    assert user.validate_okta_tile(input_url=url) is expected


def test_utc_to_local():
    """Check if passed utc datestamp becomes local one."""
    from datetime import timezone

    from tokendito import user

    utc = datetime.utcnow()
    local_time = utc.replace(tzinfo=timezone.utc).astimezone(tz=None)
    local_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z")

    assert user.utc_to_local(utc) == local_time

    with pytest.raises(SystemExit) as err:
        user.utc_to_local("pytest")
    assert err.value.code == 1


def test_process_environment(monkeypatch):
    """Test whether environment variables are interpreted correctly."""
    from tokendito import user

    valid_keys = dict(
        TOKENDITO_USER_CONFIG_PROFILE="pytest",
        TOKENDITO_OKTA_USERNAME="pytest",
        TOKENDITO_AWS_PROFILE="pytest",
    )
    invalid_keys = dict(TOKENDITO_USER_PYTEST_EXPECTED_FAILURE="pytest_expected_failure")

    monkeypatch.setattr(os, "environ", valid_keys)
    ret = user.process_environment()
    assert (ret.okta["username"] == "pytest") is True

    with pytest.raises(SystemExit) as err:
        monkeypatch.setattr(os, "environ", invalid_keys)
        ret = user.process_environment()
        assert err.value.code == 2


def test_process_arguments():
    """Test whether arguments are set correctly."""
    from argparse import Namespace

    from tokendito import user

    valid_settings = dict(okta_username="pytest", okta_password="%pytest_!&%password^")
    invalid_settings = dict(pytest_expected_failure="pytest_failure")
    args = {**valid_settings, **invalid_settings}
    ret = user.process_arguments(Namespace(**args))

    # Make sure that the arguments we passed are interpreted
    assert ret.okta["username"] == "pytest"
    assert ret.okta["password"] == "%pytest_!&%password^"
    # Make sure that incorrect arguments are not passed down to the Config object.
    assert "pytest" not in ret.__dict__


def test_update_configuration(tmpdir):
    """Test writing and reading to a configuration file."""
    from tokendito import user
    from tokendito.config import Config

    path = tmpdir.mkdir("pytest").join("pytest_tokendito.ini")
    pytest_config = Config(
        okta={
            "username": "pytest",
            "tile": "https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456",
            "org": "https://acme.okta.org/",
            "mfa": "pytest",
        },
        user={"config_file": path, "config_profile": "pytest"},
    )

    # Write out a config file via configure() and ensure it's functional
    user.update_configuration(pytest_config)
    ret = user.process_ini_file(path, "pytest")
    assert ret.okta["username"] == "pytest"
    assert ret.okta["tile"] == "https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456"
    assert ret.okta["org"] == "https://acme.okta.org/"
    assert ret.okta["mfa"] == "pytest"


def test_update_profile_device_token(tmpdir):
    """Test writing and reading device token to a configuration file."""
    from tokendito import user
    from tokendito.config import Config

    path = tmpdir.mkdir("pytest").join("pytest_tokendito.ini")

    device_token = "test-device-token"

    pytest_config = Config(
        okta={"device_token": device_token},
        user={"config_file": path, "config_profile": "pytest"},
    )

    # Write out a config file via configure() and ensure it's functional
    user.update_profile_device_token(pytest_config)
    ret = user.process_ini_file(path, "pytest")
    assert ret.okta["device_token"] == device_token


def test_check_profile_expiration():
    """Test checking profile expiration."""
    from tokendito import user
    from tokendito.config import Config

    now = datetime.now(timezone.utc)
    future = now + timedelta(days=1)
    past = now + timedelta(days=-1)

    pytest_config = Config(
        aws={"profile": "test-profile"},
        okta={"profile_expiration": str(future)},
        user={"use_profile_expiration": True},
    )

    # Expiration in the future should exit
    with pytest.raises(SystemExit):
        user.check_profile_expiration(pytest_config)

    # Expiration in the past should not exit
    pytest_config.okta["profile_expiration"] = str(past)
    try:
        user.check_profile_expiration(pytest_config)
    except SystemExit:
        pytest.fail("Profile expiration was invalid and should not have exited")


def test_update_profile_expiration(tmpdir):
    """Test writing and reading profile expiration to a configuration file."""
    from tokendito import user
    from tokendito.config import Config

    path = tmpdir.mkdir("pytest").join("pytest_tokendito.ini")

    expiration = datetime.now(timezone.utc)

    pytest_config = Config(
        okta={"profile_expiration": expiration},
        user={"config_file": path, "config_profile": "pytest"},
    )

    # Write out a config file via configure() and ensure it's functional
    user.update_profile_expiration(pytest_config)
    ret = user.process_ini_file(path, "pytest")
    assert datetime.fromisoformat(ret.okta["profile_expiration"]) == expiration


def test_process_ini_file(tmpdir):
    """Test whether ini config elements are set correctly.

    All this testing is in the same function as they share an ini file.
    """
    from tokendito import user

    valid_settings = dict(
        okta_password="%pytest_!&%password^",
        okta_username="pytest",
    )
    invalid_settings = dict(user_pytest_expected_failure="pytest")

    # Write out a config file and esure it's functional
    path = tmpdir.mkdir("pytest").join("pytest_tokendito.ini")
    user.update_ini("pytest", path, **valid_settings)
    ret = user.process_ini_file(path, "pytest")
    assert ret.okta["username"] == "pytest"
    assert ret.okta["password"] == "%pytest_!&%password^"

    # Ensure we fail if the section is not found
    user.update_ini("pytest", path, **valid_settings)
    with pytest.raises(SystemExit) as err:
        user.process_ini_file(path, "pytest_expected_failure")
    assert err.value.code == 2

    # Ensure we fail if there's a bad element
    user.update_ini("pytest", path, **invalid_settings)
    with pytest.raises(SystemExit) as err:
        user.process_ini_file(path, "pytest")
    assert err.value.code == 1


@pytest.mark.parametrize(
    "factor_type, output",
    [
        ("token", "x"),
        ("token:software:totp", "x"),
        ("push", "y"),
        ("sms", "12345"),
        ("call", "12345"),
        ("webauthn", "test"),
        ("web", "okta"),
        ("u2f", "okta"),
        ("", "Not Presented"),
        ("token:hotp", "okta"),
        ("token:hardware", "x"),
        ("question", "xyz"),
        ("email", "Firstname.Lastname@acme.org"),
        ("bad_data", "Not Presented"),
        (None, "Not Presented"),
    ],
)
def test_mfa_option_info(factor_type, output):
    """Test whether the function returns the correct answer to a specific input."""
    from tokendito.user import mfa_option_info

    mfa_option = {
        "factorType": factor_type,
        "vendorName": "okta",
        "profile": {
            "credentialId": "x",
            "name": "y",
            "phoneNumber": "12345",
            "authenticatorName": "test",
            "question": "xyz",
            "email": "Firstname.Lastname@acme.org",
        },
    }
    assert mfa_option_info(mfa_option) == output


def test_select_preferred_mfa_index(mocker, sample_json_response):
    """Test whether the function returns index entered by user."""
    from tokendito.user import select_preferred_mfa_index

    primary_auth = sample_json_response
    mfa_options = primary_auth["okta_response_mfa"]["_embedded"]["factors"]
    for output in mfa_options:
        mocker.patch("tokendito.user.collect_integer", return_value=output)
        assert select_preferred_mfa_index(mfa_options) == output


@pytest.mark.parametrize(
    "email",
    [
        ("First.Last@acme.org"),
    ],
)
def test_select_preferred_mfa_index_output(email, capsys, mocker, sample_json_response):
    """Test whether the function gives correct output."""
    from tokendito.config import config
    from tokendito.user import select_preferred_mfa_index

    # For this test, ensure that quiet is never true
    config.user["quiet"] = False
    primary_auth = sample_json_response
    mfa_options = primary_auth["okta_response_mfa"]["_embedded"]["factors"]

    correct_output = (
        "\nSelect your preferred MFA method and press Enter:\n"
        "[0]  OKTA    push                Redmi 6 Pro         Id: opfrar9yi4bKJNH2WEW\n"
        f"[1]  GOOGLE  token:software:totp {email} Id: FfdskljfdsS1ljUT0r8\n"
        f"[2]  OKTA    token:software:totp {email} Id: fdsfsd6ewREr8\n"
        f"[3]  GOOGLE  pytest_dupe         Not Presented       Id: fdsfsd6ewREr0\n"
        f"[4]  OKTA    pytest_dupe         Not Presented       Id: fdsfsd6ewREr1\n"
    )

    mocker.patch("tokendito.user.collect_integer", return_value=1)
    select_preferred_mfa_index(mfa_options)
    captured = capsys.readouterr()
    assert captured.out == correct_output


@pytest.mark.parametrize(
    "selected_role",
    [
        "arn:aws:iam::123456789012:role/pytest_role_1",
        "arn:aws:iam::124356789012:role/pytest_role_2",
    ],
)
def test_correct_role_selection(mocker, selected_role):
    """Test which role does the user has chosen."""
    from tokendito.user import select_role_arn

    role_arns = [
        "arn:aws:iam::123456789012:role/pytest",
        "arn:aws:iam::124356789012:role/pytest",
    ]

    authenticated_tiles = {"url": {"roles": role_arns}}

    mocker.patch("tokendito.user.prompt_role_choices", return_value=selected_role)
    assert select_role_arn(authenticated_tiles) == selected_role


def test_repeated_line_select_role_arn():
    """Ensure that duplicate roles trigger an error."""
    from tokendito.config import config
    from tokendito.user import select_role_arn

    config.aws["profile"] = "pytest"

    role_arns = [
        "arn:aws:iam::123456789012:role/pytest",
        "arn:aws:iam::123456789012:role/pytest",
    ]

    authenticated_tiles = {"url": {"roles": role_arns}}

    with pytest.raises(SystemExit) as error:
        assert select_role_arn(authenticated_tiles) == error


def test_incorrect_role_arn():
    """Ensure that incorrectly selected options trigger an error."""
    from tokendito.config import config
    from tokendito.user import select_role_arn

    config.aws["profile"] = "pytest_failure"
    config.aws["role_arn"] = "pytest_failure"

    role_arns = [
        "arn:aws:iam::123456789012:role/pytest",
        "arn:aws:iam::124356789012:role/pytest",
    ]

    authenticated_tiles = {"url": {"roles": role_arns}}

    with pytest.raises(SystemExit) as error:
        assert select_role_arn(authenticated_tiles) == error


def test_loglevel_collected_from_env(monkeypatch):
    """Ensure that the loglevel collected from env vars."""
    from argparse import Namespace
    import logging

    from tokendito import user

    args = {
        "okta_username": "pytest_arg",
        "okta_tile": "https://acme.okta.org/_arg",
        "version": None,
        "configure": False,
        "user_config_file": None,
        "user_config_profile": None,
    }

    monkeypatch.setenv("TOKENDITO_USER_LOGLEVEL", "DEBUG")
    monkeypatch.setattr(user, "parse_cli_args", lambda *x: Namespace(**args))
    ret = user.setup_early_logging(args)["loglevel"]
    val = logging.getLevelName(ret)

    assert val == logging.DEBUG


def test_create_directory(tmpdir):
    """Test dir creation."""
    from tokendito import user

    path = tmpdir.mkdir("pytest")
    testdir = f"{path}/pytest/deepdir"

    ret = user.create_directory(testdir)
    assert ret is None

    with pytest.raises(SystemExit) as err:
        user.create_directory(__file__)
        assert err.value.code == 1


def test_get_submodules_names(mocker):
    """Test whether submodules are retrieves correctly."""
    from tokendito import user

    ret = user.get_submodule_names()
    assert "__main__" in ret


def test_process_interactive_input(mocker):
    """Test interactive input processor."""
    from tokendito import user
    from tokendito.config import Config

    # Check that a good object retrieves an interactive password
    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.getpass", return_value="%pytest_!&%password^")

    pytest_config = Config()
    pytest_config.okta["tile"] = "https://pytest/tile"
    pytest_config.okta["org"] = "https://pytest/"
    pytest_config.okta["username"] = "pytest"
    ret = user.process_interactive_input(pytest_config)
    pytest_config.update(ret)
    assert pytest_config.okta["password"] == "%pytest_!&%password^"

    # Check that quiet mode does not retrieve a username
    pytest_config.user["quiet"] = True
    pytest_config.okta["username"] = ""
    ret = user.process_interactive_input(pytest_config)
    pytest_config.update(ret)
    assert pytest_config.okta["username"] == ""

    # Check that a bad object raises an exception
    with pytest.raises(AttributeError) as error:
        assert user.process_interactive_input({"pytest": "pytest"}) == error


@pytest.mark.parametrize(
    "default,submit,expected",
    [
        ("", "", ""),
        ("", "different_name", "different_name"),
        ("role_name", "", "role_name"),
        ("role_name", "different_name", "different_name"),
        ("role_name", "role_name", "role_name"),
    ],
)
def test_get_interactive_profile_name(mocker, default, submit, expected):
    """Test getting the AWS profile name form user input."""
    from tokendito import user

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.input", return_value=submit)
    assert user.get_interactive_profile_name(default) == expected


def test_get_interactive_profile_name_invalid_input(mocker, monkeypatch):
    """Test reprompting the AWS profile name form user on invalid input."""
    from tokendito import user

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    # provided inputs
    inputs = iter(["_this_is_invalid", "str with space", "1StartsWithNum", "valid"])

    # using lambda statement for mocking
    monkeypatch.setattr("builtins.input", lambda name: next(inputs))

    assert user.get_interactive_profile_name("role_name") == "valid"


@pytest.mark.parametrize(
    "value,submit,expected",
    [
        ("pytest", None, "pytest"),
        ("pytest", "deadbeef", "pytest"),
        ("pytest", 0xDEADBEEF, "pytest"),
        (None, "user_input", "user_input"),
    ],
)
def test_set_role_name(value, submit, mocker, expected):
    """Test setting the AWS Role (profile) name."""
    from tokendito import user
    from tokendito.config import Config

    pytest_config = Config(aws=dict(profile=value))

    mocker.patch("tokendito.user.get_interactive_profile_name", return_value=submit)

    ret = user.set_profile_name(pytest_config, "role_name")
    assert ret.aws["profile"] == expected


@pytest.mark.parametrize(
    "config,expected",
    [
        (
            {"okta": {"username": "", "password": "", "org": None, "tile": None}},
            [
                "Username not set",
                "Password not set",
                "Either Okta Org or tile URL must be defined",
            ],
        ),
        (
            {
                "okta": {
                    "username": "pytest",
                    "password": "pytest",
                    "org": "https://acme.okta.org",
                    "tile": None,
                }
            },
            [],
        ),
        (
            {
                "okta": {
                    "username": "pytest",
                    "password": "pytest",
                    "org": "https://acme.okta.org",
                    "tile": "https://badurl_pytest.org",
                }
            },
            [
                "Tile URL https://badurl_pytest.org is not valid",
                "Org URL https://acme.okta.org and Tile URL "
                "https://badurl_pytest.org must be in the same domain",
            ],
        ),
        (
            {
                "okta": {
                    "username": "pytest",
                    "password": "pytest",
                    "org": "https://acme.okta.org",
                    "tile": "https://acme.okta.org/home/amazon_aws/"
                    "0123456789abcdef0123/456?fromHome=true",
                }
            },
            [],
        ),
        (
            {
                "okta": {
                    "username": "pytest",
                    "password": "pytest",
                    "org": "https://acme.okta.com/",
                    "tile": "https://acme.okta.org/home/amazon_aws/"
                    "0123456789abcdef0123/456?fromHome=true",
                }
            },
            [
                "Org URL https://acme.okta.com/ and Tile URL "
                "https://acme.okta.org/home/amazon_aws/"
                "0123456789abcdef0123/456?fromHome=true must be in the same domain"
            ],
        ),
        (
            {
                "okta": {
                    "username": "pytest",
                    "password": "pytest",
                    "org": "pytest_deadbeef",
                    "tile": None,
                }
            },
            ["Org URL pytest_deadbeef is not valid"],
        ),
        (
            {
                "okta": {
                    "username": "pytest",
                    "password": "pytest",
                    "org": "https://acme.okta.org",
                    "tile": None,
                },
                "user": {"quiet": False},
            },
            [],
        ),
        (
            {
                "user": {"quiet": True},
                "okta": {
                    "username": "pytest",
                    "password": "pytest",
                    "org": "https://acme.okta.org",
                    "tile": None,
                    "mfa": "push",
                    "mfa_response": None,
                },
                "aws": {
                    "role_arn": None,
                },
            },
            ["AWS role ARN not set"],
        ),
        (
            {
                "user": {"quiet": True},
                "okta": {
                    "username": "pytest",
                    "password": "pytest",
                    "org": "https://acme.okta.org",
                    "tile": None,
                    "mfa": None,
                    "mfa_response": None,
                },
                "aws": {
                    "role_arn": "arn:aws:iam::123456789000:role/test-role",
                },
            },
            ["MFA Method not set", "MFA Response not set"],
        ),
    ],
)
def test_validate_configuration(config, expected):
    """Test configuration validator."""
    from tokendito import user
    from tokendito.config import Config

    pytest_config = Config(**config)
    assert user.validate_configuration(pytest_config) == expected


def test_sanitize_config_values():
    """Test configuration sanitizer method."""
    from tokendito import user
    from tokendito.config import Config

    pytest_config = Config(
        aws=dict(output="pytest", region="pytest"),
        okta=dict(tile="https://pytest_org", org="https://pytest_bar/"),
    )
    ret = user.sanitize_config_values(pytest_config)
    assert ret.aws["region"] == pytest_config.get_defaults()["aws"]["region"]
    assert ret.aws["output"] == pytest_config.get_defaults()["aws"]["output"]
    assert ret.okta["tile"].startswith(ret.okta["org"])


@pytest.mark.parametrize(
    "saml, expected",
    [
        ("pytest", {}),
        ("pytest,pytest", {}),
        (
            'xsi:type="xs:string">arn:aws:iam::000000000000:saml/name,'
            "arn:aws:iam::000000000000:role/name</saml2:AttributeValue>",
            {"arn:aws:iam::000000000000:role/name": "arn:aws:iam::000000000000:saml/name"},
        ),
    ],
)
def test_extract_arns(saml, expected):
    """Test extracting Provider/Role ARN pairs from a SAML document."""
    from tokendito import user

    assert user.extract_arns(saml) == expected
