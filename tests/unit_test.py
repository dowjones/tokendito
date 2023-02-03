# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures."""
from datetime import datetime
import os
import sys
from unittest.mock import Mock

import pytest
import requests_mock
import semver


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def sample_json_response():
    """Return a response from okta server."""
    from okta_response_simulation import no_mfa_no_session_token
    from okta_response_simulation import no_mfa
    from okta_response_simulation import error_dict
    from okta_response_simulation import empty_dict
    from okta_response_simulation import no_auth_methods
    from okta_response_simulation import with_mfa

    okta_fixture_data = {
        "okta_response_no_auth_methods": no_auth_methods,
        "okta_response_empty": empty_dict,
        "okta_response_error": error_dict,
        "okta_response_no_mfa": no_mfa,
        "okta_response_no_mfa_no_session_token": no_mfa_no_session_token,
        "okta_response_mfa": with_mfa,
    }
    return okta_fixture_data


@pytest.fixture
def sample_headers():
    """Return a headers."""
    headers = {"content-type": "application/json", "accept": "application/json"}
    return headers


def test_import_location():
    """Ensure module imported is the local one."""
    import tokendito

    local_path = os.path.realpath(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/tokendito/__init__.py"
    )
    imported_path = os.path.realpath(tokendito.__file__)
    assert imported_path.startswith(local_path)


def test_semver_version():
    """Ensure the package version is semver compliant."""
    from tokendito import __version__ as version

    assert semver.VersionInfo.parse(version)


def test_get_username(mocker):
    """Test whether data sent is the same as data returned."""
    from tokendito import user

    mocker.patch("tokendito.user.input", return_value="pytest_patched")
    val = user.get_username()

    assert val == "pytest_patched"


def test_get_password(mocker):
    """Test whether data sent is the same as data returned."""
    from tokendito import user

    mocker.patch("getpass.getpass", return_value="pytest_patched")
    val = user.get_password()

    assert val == "pytest_patched"


def test_setup_logging():
    """Test logging setup."""
    from tokendito import user
    import logging

    # test that a default level is set on a bad level
    ret = user.setup_logging({"loglevel": "pytest"})
    assert ret == logging.INFO

    # test that a correct level is set
    ret = user.setup_logging({"loglevel": "debug"})
    assert ret == logging.DEBUG


def test_setup_early_logging(monkeypatch, tmpdir):
    """Test early logging."""
    from tokendito import user
    from argparse import Namespace

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


def test_validate_saml_response():
    """Test for failures on SAML response."""
    from tokendito import user

    with pytest.raises(SystemExit) as err:
        user.validate_saml_response("")
    assert err.value.code == 1


def test_assert_credentials():
    """Test whether getting credentials works as expeted."""
    from moto import mock_sts
    from tokendito import aws

    with pytest.raises(SystemExit) as err:
        aws.assert_credentials({})
    assert err.value.code == 1

    saml_response = {
        "Credentials": {
            "AccessKeyId": "pytest",
            "SecretAccessKey": "pytest",
            "SessionToken": "pytest",
        }
    }
    with mock_sts():
        ret = aws.assert_credentials(role_response=saml_response)
        assert "Arn" in ret and "UserId" in ret


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
    """Test adding some values only adds whatas expected."""
    from tokendito import user

    user.add_sensitive_value_to_be_masked("should be added")
    user.add_sensitive_value_to_be_masked("should be added2")
    user.add_sensitive_value_to_be_masked("should be added3", "password")
    user.add_sensitive_value_to_be_masked("should not be added", "public")
    assert (
        "should be added" in user.mask_items
        and "should be added2" in user.mask_items
        and "should be added3" in user.mask_items
        and len(user.mask_items) == 3
    )


def test_logger_mask(caplog):
    """Test that masking data in loggger works as expected."""
    from tokendito import user
    import logging

    logger = logging.getLogger(__name__)
    logger.addFilter(user.MaskLoggerSecret())
    user.add_sensitive_value_to_be_masked("supersecret")
    user.add_sensitive_value_to_be_masked("another secret", "sessionToken")
    with caplog.at_level(logging.DEBUG):
        logger.debug("This should be displayed, but not: supersecret")
        logger.debug("another secret")
    assert (
        "supersecret" not in caplog.text
        and "another secret" not in caplog.text
        and "This should be displayed" in caplog.text
    )


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
    from tokendito import user
    from datetime import timezone

    utc = datetime.utcnow()
    local_time = utc.replace(tzinfo=timezone.utc).astimezone(tz=None)
    local_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z")

    assert user.utc_to_local(utc) == local_time

    with pytest.raises(SystemExit) as err:
        user.utc_to_local("pytest")
    assert err.value.code == 1


def test_set_passcode(mocker):
    """Check if numerical passcode can handle leading zero values."""
    from tokendito import duo

    mocker.patch("tokendito.user.input", return_value="0123456")
    assert duo.set_passcode({"factor": "passcode"}) == "0123456"


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
    from tokendito import user
    from argparse import Namespace

    valid_settings = dict(okta_username="pytest", okta_password="pytest_password")
    invalid_settings = dict(pytest_expected_failure="pytest_failure")
    args = {**valid_settings, **invalid_settings}
    ret = user.process_arguments(Namespace(**args))

    # Make sure that the arguments we passed are interpreted
    assert ret.okta["username"] == "pytest"
    assert ret.okta["password"] == "pytest_password"
    # Make sure that incorrect arguments are not passed down to the Config object.
    assert "pytest" not in ret.__dict__


def test_update_configuration(tmpdir):
    """Test writing and reading to a configuration file."""
    from tokendito import user, Config

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


def test_process_ini_file(tmpdir):
    """Test whether ini config elements are set correctly.

    All this testing is in the same function as they share an ini file.
    """
    from tokendito import user

    valid_settings = dict(
        okta_password="pytest_password",
        okta_username="pytest",
    )
    invalid_settings = dict(user_pytest_expected_failure="pytest")

    # Write out a config file and esure it's functional
    path = tmpdir.mkdir("pytest").join("pytest_tokendito.ini")
    user.update_ini("pytest", path, **valid_settings)
    ret = user.process_ini_file(path, "pytest")
    assert ret.okta["username"] == "pytest"
    assert ret.okta["password"] == "pytest_password"

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
    "session_token, expected, mfa_availability",
    [
        (345, 345, "okta_response_no_auth_methods"),
        (345, 345, "okta_response_mfa"),
        (345, 345, "okta_response_no_auth_methods"),
        (None, None, "okta_response_no_mfa_no_session_token"),
    ],
)
def test_user_session_token(
    sample_json_response,
    session_token,
    expected,
    mocker,
    sample_headers,
    mfa_availability,
):
    """Test whether function return key on specific status."""
    from tokendito.okta import user_session_token

    primary_auth = sample_json_response[mfa_availability]

    mocker.patch("tokendito.okta.user_mfa_challenge", return_value=session_token)
    assert user_session_token(primary_auth, sample_headers) == expected
    with pytest.raises(SystemExit) as err:
        assert user_session_token(None, sample_headers) == err


def test_bad_user_session_token(mocker, sample_json_response, sample_headers):
    """Test whether function behave accordingly."""
    from tokendito.okta import user_session_token

    mocker.patch("tokendito.okta.api_error_code_parser", return_value=None)
    okta_response_statuses = ["okta_response_error", "okta_response_empty"]

    for response in okta_response_statuses:
        primary_auth = sample_json_response[response]

        with pytest.raises(SystemExit) as error:
            assert user_session_token(primary_auth, sample_headers) == error


@pytest.mark.parametrize(
    "mfa_provider, session_token, expected",
    [("duo", 123, 123), ("okta", 345, 345), ("google", 456, 456)],
)
def test_mfa_provider_type(
    mfa_provider,
    session_token,
    expected,
    mocker,
    sample_headers,
):
    """Test whether function return key on specific MFA provider."""
    from tokendito.okta import mfa_provider_type

    payload = {"x": "y", "t": "z"}
    callback_url = "https://www.acme.org"
    selected_mfa_option = 1
    mfa_challenge_url = 1
    primary_auth = 1
    selected_factor = 1

    mfa_verify = {"sessionToken": session_token}
    mocker.patch(
        "tokendito.duo.authenticate_duo",
        return_value=(payload, sample_headers, callback_url),
    )
    mocker.patch("tokendito.okta.api_wrapper", return_value=mfa_verify)
    mocker.patch("tokendito.okta.user_mfa_options", return_value=mfa_verify)
    mocker.patch("tokendito.duo.duo_api_post")
    assert (
        mfa_provider_type(
            mfa_provider,
            selected_factor,
            mfa_challenge_url,
            primary_auth,
            selected_mfa_option,
            sample_headers,
            payload,
        )
        == expected
    )


def test_bad_mfa_provider_type(mocker, sample_headers):
    """Test whether function return key on specific MFA provider."""
    from tokendito.okta import mfa_provider_type

    payload = {"x": "y", "t": "z"}
    callback_url = "https://www.acme.org"
    selected_mfa_option = 1
    mfa_challenge_url = 1
    primary_auth = 1
    selected_factor = 1

    mfa_verify = {"sessionToken": "pytest_session_token"}
    mfa_bad_provider = "bad_provider"
    mocker.patch(
        "tokendito.duo.authenticate_duo",
        return_value=(payload, sample_headers, callback_url),
    )
    mocker.patch("tokendito.okta.api_wrapper", return_value=mfa_verify)
    mocker.patch("tokendito.okta.user_mfa_options", return_value=mfa_verify)

    with pytest.raises(SystemExit) as error:
        assert (
            mfa_provider_type(
                mfa_bad_provider,
                selected_factor,
                mfa_challenge_url,
                primary_auth,
                selected_mfa_option,
                sample_headers,
                payload,
            )
            == error
        )


def test_api_wrapper():
    """Test whether verify_api_method returns the correct data."""
    from tokendito.okta import api_wrapper

    url = "https://acme.org"
    with requests_mock.Mocker() as m:
        data = {"response": "ok"}
        m.post(url, json=data, status_code=200)
        assert api_wrapper(url, data) == data

    with pytest.raises(SystemExit) as error, requests_mock.Mocker() as m:
        data = None
        m.post(url, json=data, status_code=200)
        assert api_wrapper(url, data) == error

    with pytest.raises(SystemExit) as error, requests_mock.Mocker() as m:
        data = {"response": "ok", "errorCode": "0xdeadbeef"}
        m.post(url, json=data, status_code=200)
        assert api_wrapper(url, data) == error

    with pytest.raises(SystemExit) as error, requests_mock.Mocker() as m:
        data = "pytest_bad_datatype"
        m.post(url, text=data, status_code=403)
        assert api_wrapper(url, data) == error

    with pytest.raises(SystemExit) as error, requests_mock.Mocker() as m:
        data = {"response": "incorrect", "errorCode": "0xdeadbeef"}
        m.post(url, json=data, status_code=403)
        assert api_wrapper("http://acme.org", data) == error


def test_api_error_code_parser():
    """Test whether message on specific status equal."""
    from tokendito.okta import api_error_code_parser, _status_dict

    okta_status_dict = _status_dict

    for key, value in okta_status_dict.items():
        assert api_error_code_parser(key) == "Okta auth failed: " + value
    unexpected_key = "UNEXPECTED_KEY"
    value = f"Okta auth failed: {unexpected_key}. Please verify your settings and try again."
    assert api_error_code_parser(unexpected_key) == value


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


@pytest.mark.parametrize(
    "preset_mfa, output",
    [("push", 0), (None, 1), ("0xdeadbeef", 1), ("opfrar9yi4bKJNH2WEW", 0), ("pytest_dupe", 1)],
)
def test_user_mfa_index(preset_mfa, output, mocker, sample_json_response):
    """Test whether the function returns correct mfa index."""
    from tokendito.okta import user_mfa_index

    primary_auth = sample_json_response["okta_response_mfa"]

    mfa_options = primary_auth["_embedded"]["factors"]
    available_mfas = [f"{d['provider']}_{d['factorType']}_{d['id']}" for d in mfa_options]
    mocker.patch("tokendito.user.select_preferred_mfa_index", return_value=1)

    if preset_mfa == "pytest_dupe":
        with pytest.raises(SystemExit) as err:
            user_mfa_index(preset_mfa, available_mfas, mfa_options)
        assert err.value.code == output
    else:
        assert user_mfa_index(preset_mfa, available_mfas, mfa_options) == output


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
    from tokendito.user import select_preferred_mfa_index
    from tokendito import config

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


def test_user_mfa_options(sample_headers, sample_json_response, mocker):
    """Test handling of mfa options."""
    from tokendito.okta import user_mfa_options

    selected_mfa_option = {"factorType": "push"}
    primary_auth = sample_json_response["okta_response_no_mfa"]
    payload = {"x": "y", "t": "z"}
    mfa_challenge_url = "https://pytest"

    # Test for push_approval returning the correct value
    mocker.patch("tokendito.okta.push_approval", return_value=primary_auth)
    ret = user_mfa_options(
        selected_mfa_option, sample_headers, mfa_challenge_url, payload, primary_auth
    )
    assert ret == primary_auth

    # Test that selecting software token returns a session token
    selected_mfa_option = {"factorType": "token:software:totp"}
    primary_auth["stateToken"] = "pytest"
    mfa_verify = {"sessionToken": "pytest"}
    mocker.patch("tokendito.user.get_input", return_value="012345")
    mocker.patch("tokendito.okta.api_wrapper", return_value=mfa_verify)
    ret = user_mfa_options(
        selected_mfa_option, sample_headers, mfa_challenge_url, payload, primary_auth
    )
    assert ret == mfa_verify


def test_user_mfa_challenge_with_no_mfas(sample_headers, sample_json_response):
    """Test whether okta response has mfas."""
    from tokendito.okta import user_mfa_challenge

    primary_auth = sample_json_response["okta_response_no_auth_methods"]

    with pytest.raises(SystemExit) as error:
        assert user_mfa_challenge(sample_headers, primary_auth) == error


@pytest.mark.parametrize(
    "return_value,side_effect,expected",
    [
        ({"status": "SUCCESS", "sessionToken": "pytest"}, None, 0),
        ({"status": "SUCCESS", "sessionToken": "pytest", "factorResult": "SUCCESS"}, None, 0),
        ({"status": "MFA_CHALLENGE", "factorResult": "REJECTED"}, None, 2),
        ({"status": "MFA_CHALLENGE", "factorResult": "TIMEOUT"}, None, 2),
        ({"status": "UNKNOWN", "factorResult": "UNKNOWN"}, None, 2),
        (
            {
                "status": "MFA_CHALLENGE",
                "factorResult": "WAITING",
                "_links": {"next": {"href": None}},
            },
            [
                {
                    "status": "MFA_CHALLENGE",
                    "factorResult": "WAITING",
                    "_links": {"next": {"href": None}},
                },
                {"status": "SUCCESS", "sessionToken": "pytest", "factorResult": "SUCCESS"},
            ],
            0,
        ),
        (
            {
                "status": "MFA_CHALLENGE",
                "factorResult": "WAITING",
                "_embedded": {"factor": {"_embedded": {"challenge": {"correctAnswer": 100}}}},
                "_links": {"next": {"href": None}},
            },
            [
                {
                    "status": "MFA_CHALLENGE",
                    "factorResult": "WAITING",
                    "_embedded": {"factor": {"_embedded": {"challenge": {"correctAnswer": 100}}}},
                    "_links": {"next": {"href": None}},
                },
                {"status": "SUCCESS", "sessionToken": "pytest", "factorResult": "SUCCESS"},
            ],
            0,
        ),
    ],
)
def test_push_approval(mocker, sample_headers, return_value, side_effect, expected):
    """Test push approval."""
    from tokendito import okta

    challenge_url = "https://pytest/api/v1/authn/factors/factorid/verify"

    mocker.patch("tokendito.okta.api_wrapper", return_value=return_value, side_effect=side_effect)
    mocker.patch("time.sleep", return_value=0)

    if "status" in return_value and return_value["status"] == "SUCCESS":
        ret = okta.push_approval(sample_headers, challenge_url, None)
        assert ret["status"] == "SUCCESS"
    elif "factorResult" in return_value and return_value["factorResult"] == "WAITING":
        ret = okta.push_approval(sample_headers, challenge_url, None)
        assert ret["status"] == "SUCCESS"
    else:
        with pytest.raises(SystemExit) as err:
            okta.push_approval(sample_headers, challenge_url, None)
        assert err.value.code == expected


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
    import tokendito
    from tokendito.user import select_role_arn

    tokendito.config.aws["profile"] = "pytest"

    role_arns = [
        "arn:aws:iam::123456789012:role/pytest",
        "arn:aws:iam::123456789012:role/pytest",
    ]

    authenticated_tiles = {"url": {"roles": role_arns}}

    with pytest.raises(SystemExit) as error:
        assert select_role_arn(authenticated_tiles) == error


def test_incorrect_role_arn():
    """Ensure that incorrectly selected options trigger an error."""
    import tokendito
    from tokendito.user import select_role_arn

    tokendito.config.aws["profile"] = "pytest_failure"
    tokendito.config.aws["role_arn"] = "pytest_failure"

    role_arns = [
        "arn:aws:iam::123456789012:role/pytest",
        "arn:aws:iam::124356789012:role/pytest",
    ]

    authenticated_tiles = {"url": {"roles": role_arns}}

    with pytest.raises(SystemExit) as error:
        assert select_role_arn(authenticated_tiles) == error


def test_prepare_duo_info():
    """Test behaviour empty return duo info."""
    from tokendito.duo import prepare_duo_info
    from tokendito import config

    selected_okta_factor = {
        "_embedded": {
            "factor": {
                "_embedded": {
                    "verification": {
                        "_links": {
                            "complete": {"href": "http://test.okta.href"},
                            "script": {"href": "python-v3.7"},
                        },
                        "signature": "fdsafdsa:fdsfdfds:fdsfdsfds",
                        "host": "test_host",
                    }
                },
                "id": 1234,
            }
        },
        "stateToken": 12345,
    }
    okta_factor = selected_okta_factor["_embedded"]["factor"]["_embedded"]["verification"]
    expected_duo_info = {
        "okta_factor": okta_factor,
        "factor_id": 1234,
        "state_token": 12345,
        "okta_callback_url": "http://test.okta.href",
        "tx": "fdsafdsa",
        "tile_sig": "fdsfdfds",
        "parent": f"{config.okta['org']}/signin/verify/duo/web",
        "host": "test_host",
        "sid": "",
        "version": "3.7",
    }
    assert prepare_duo_info(selected_okta_factor) == expected_duo_info


def test_get_duo_sid(mocker):
    """Check if got sid correct."""
    from tokendito import config
    from tokendito.duo import get_duo_sid

    test_duo_info = {
        "okta_factor": "okta_factor",
        "factor_id": 1234,
        "state_token": 12345,
        "okta_callback_url": "http://test.okta.href",
        "tx": "fdsafdsa",
        "tile_sig": "fdsfdfds",
        "parent": f"{config.okta['org']}/signin/verify/duo/web",
        "host": "test_host",
        "sid": "",
        "version": "3.7",
    }

    test_url = "http://test.token.dito?sid=testval"
    duo_api_response = Mock()
    duo_api_response.url = test_url

    mocker.patch("tokendito.duo.duo_api_post", return_value=duo_api_response)

    duo_sid_info, duo_auth_response = get_duo_sid(test_duo_info)

    assert duo_sid_info["sid"] == "testval"
    assert duo_auth_response.url == test_url


@pytest.mark.parametrize("status_code", [(400), (401), (404), (500), (503)])
def test_authenticate_to_roles(status_code, monkeypatch):
    """Test if function return correct response."""
    from tokendito.aws import authenticate_to_roles
    import requests

    mock_get = {"status_code": status_code, "text": "response"}
    monkeypatch.setattr(requests, "get", mock_get)
    with pytest.raises(SystemExit) as error:
        assert authenticate_to_roles("secret_session_token", [("http://test.url.com", "")]) == error


def test_get_mfa_response():
    """Test if mfa verify correctly."""
    from tokendito.duo import get_mfa_response

    mfa_result = Mock()
    mfa_result.json = Mock(return_value={"response": "test_response"})

    assert get_mfa_response(mfa_result) == "test_response"


def test_config_object():
    """Test proper initialization of the Config object."""
    import json
    from tokendito import Config

    # Test for invalid assignments to the object
    with pytest.raises(AttributeError):
        pytest_config = Config(pytest_attribute={})

    with pytest.raises(KeyError):
        pytest_config = Config(aws="pytest")

    with pytest.raises(ValueError):
        pytest_config = Config(aws={"pytest": "pytest"})

    # Test whether repr can be reused to create an object
    pytest_config = Config()
    args = json.loads(repr(pytest_config))
    pytest_config_2 = Config(**args)
    assert (pytest_config == pytest_config_2) is True

    # Test if passing arguments results in an object with new values
    pytest_config_aws = Config(aws={"profile": "pytest_aws"})
    pytest_config_okta = Config(okta={"username": "pytest_username"})
    pytest_config_mixed = Config(
        user={"config_profile": "pytest_user"}, okta={"password": "pytest_password"}
    )
    assert (pytest_config == pytest_config_aws) is False

    # Check that an update copies the values correctly
    pytest_config.update(pytest_config_aws)
    assert pytest_config.aws["profile"] == "pytest_aws"

    # Check that an update does not overwrite all values
    pytest_config.update(pytest_config_okta)
    assert pytest_config.aws["profile"] == "pytest_aws"

    # Check that an update overwrites matching values only
    pytest_config.update(pytest_config_mixed)
    assert pytest_config.okta["username"] == "pytest_username"
    assert pytest_config.okta["password"] == "pytest_password"
    assert pytest_config.user["config_profile"] == "pytest_user"

    # Check that default values from the original object are kept
    assert pytest_config.get_defaults()["aws"]["region"] == pytest_config.aws["region"]


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
    testdir = f"{path}/pytest"

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
    from tokendito import user, Config

    # Check that a good object retrieves an interactive password
    mocker.patch("getpass.getpass", return_value="pytest_password")

    pytest_config = Config()
    pytest_config.okta["tile"] = "https://pytest/tile"
    pytest_config.okta["org"] = "https://pytest/"
    pytest_config.okta["username"] = "pytest"
    ret = user.process_interactive_input(pytest_config)
    pytest_config.update(ret)
    assert pytest_config.okta["password"] == "pytest_password"

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
    "role_name,user_input,expected",
    [
        ("role_name", "", "role_name"),
        ("role_name", "different_name", "different_name"),
        ("role_name", "role_name", "different_name"),
    ],
)
def test_get_profile_name(mocker, role_name, user_input, expected):
    """Test get tile URL."""
    from tokendito import user

    mocker.patch("tokendito.user.input", return_value=user_input)
    assert user.get_profile_name(role_name) == expected


@pytest.mark.parametrize(
    "value,submit,expected",
    [
        ("pytest", None, "pytest"),
        ("pytest", "deadbeef", "pytest"),
        ("pytest", 0xDEADBEEF, "pytest"),
        (None, None, "default"),
        (None, "", "default"),
        (None, 0xDEADBEEF, str(0xDEADBEEF)),
    ],
)
def test_set_profile_name(value, submit, expected):
    """Test setting the AWS Profile name."""
    from tokendito import user, Config

    pytest_config = Config(aws=dict(profile=value))

    ret = user.set_profile_name(pytest_config, submit)
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
    from tokendito import user, Config

    pytest_config = Config(**config)
    assert user.validate_configuration(pytest_config) == expected


def test_sanitize_config_values():
    """Test configuration sanitizer method."""
    from tokendito import user, Config

    pytest_config = Config(
        aws=dict(output="pytest", region="pytest"),
        okta=dict(tile="https://pytest_org", org="https://pytest_bar/"),
    )
    ret = user.sanitize_config_values(pytest_config)
    assert ret.aws["region"] == pytest_config.get_defaults()["aws"]["region"]
    assert ret.aws["output"] == pytest_config.get_defaults()["aws"]["output"]
    assert ret.okta["tile"].startswith(ret.okta["org"])


def test_get_regions():
    """Test retrieval of available AWS regions."""
    from tokendito import aws

    ret = aws.get_regions(profile="pytest")
    assert ret == []
    ret = aws.get_regions()
    assert "us-east-1" in ret


def test_get_output_types():
    """Test getting AWS output types."""
    from tokendito import aws

    ret = aws.get_output_types()
    assert "json" in ret
