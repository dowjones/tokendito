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


def test_set_okta_username(mocker):
    """Test whether data sent is the same as data returned."""
    from tokendito import user, config

    mocker.patch("tokendito.user.input", return_value="pytest_patched")
    val = user.set_okta_username()

    assert val == "pytest_patched"
    assert config.okta["username"] == "pytest_patched"


def test_set_okta_password(mocker):
    """Test whether data sent is the same as data returned."""
    from tokendito import user, config

    mocker.patch("getpass.getpass", return_value="pytest_patched")
    val = user.set_okta_password()

    assert val == "pytest_patched"
    assert config.okta["password"] == "pytest_patched"


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
def test_validate_app_url(url, expected):
    """Test whether the Okta URL is parsed correctly."""
    from tokendito import user

    assert user.validate_okta_app_url(input_url=url) is expected


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


@pytest.mark.parametrize("value,expected", [("00", 0), ("01", 1), ("5", 5)])
def test_collect_integer(mocker, value, expected):
    """Check if a given digit or series of digits are properly casted to int."""
    from tokendito import user

    mocker.patch("tokendito.user.input", return_value=value)
    assert user.collect_integer(10) == expected


def test_utc_to_local():
    """Check if passed utc datestamp becomes local one."""
    from tokendito import user
    from datetime import timezone

    utc = datetime.utcnow()
    local_time = utc.replace(tzinfo=timezone.utc).astimezone(tz=None)
    local_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z")

    assert user.utc_to_local(utc) == local_time


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

    valid_settings = dict(okta_username="pytest", okta_password="pytest")
    invalid_settings = dict(pytest_expected_failure="pytest_failure")
    args = {**valid_settings, **invalid_settings}
    ret = user.process_arguments(Namespace(**args))

    # Make sure that the arguments we passed are interpreted
    assert ret.okta["username"] == "pytest"
    assert ret.okta["password"] == "pytest"
    # Make sure that incorrect arguments are not passed down to the Config object.
    assert "pytest" not in ret.__dict__


def test_process_ini_file(tmpdir):
    """Test whether ini config elements are set correctly."""
    from tokendito import user

    valid_settings = dict(
        okta_password="pytest",
        okta_username="pytest",
    )
    invalid_settings = dict(user_pytest_expected_failure="pytest")

    # Create a mock config file
    data = "[default]\nokta_username = pytest\n\n[pytest]\n"
    data += "".join(f"{key} = {val}\n" for key, val in valid_settings.items())
    data += "\n[pytest_expected_element_failure]\n"
    data += "".join(f"{key} = {val}\n" for key, val in invalid_settings.items())

    # Python 3.7 supports patching builtins.open(), which gives us the ability
    # to bypass file creation with:
    # mocker.patch('builtins.open', mocker.mock_open(read_data=data), create=True)
    # There is no (easy) way to achieve the same on earlier versions, so we create
    # an actual file instead. tmpdir keeps the last 3 files/dirs behind for inspection
    path = tmpdir.mkdir("pytest").join("pytest_tokendito.ini")
    path.write(data)

    # Ensure we fail if the section is not found
    with pytest.raises(SystemExit) as err:
        user.process_ini_file(path, "pytest_expected_failure")
        assert err.value.code == 2

    ret = user.process_ini_file(path, "pytest")
    assert ret.okta["username"] == "pytest"
    assert ret.okta["password"] == "pytest"

    with pytest.raises(SystemExit) as err:
        user.process_ini_file(path, "pytest_expected_element_failure")
        assert err.value.code == 2


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


def test_bad_user_session_token(mocker, sample_json_response, sample_headers):
    """Test whether function behave accordingly."""
    from tokendito.okta import user_session_token

    mocker.patch("tokendito.okta.login_error_code_parser", return_value=None)
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
    mocker.patch("tokendito.okta.okta_verify_api_method", return_value=mfa_verify)
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

    mfa_verify = {"sessionToken": "123"}
    mfa_bad_provider = "bad_provider"
    mocker.patch(
        "tokendito.duo.authenticate_duo",
        return_value=(payload, sample_headers, callback_url),
    )
    mocker.patch("tokendito.okta.okta_verify_api_method", return_value=mfa_verify)
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


def test_okta_verify_api_method():
    """Test whether verify_api_method returns the correct data."""
    from tokendito.okta import okta_verify_api_method

    url = "https://acme.org"
    with requests_mock.Mocker() as m:
        data = {"response": "ok"}
        m.post(url, json=data, status_code=200)
        assert okta_verify_api_method(url, data) == data

    with pytest.raises(SystemExit) as error, requests_mock.Mocker() as m:
        data = "pytest_bad_datatype"
        m.post(url, text=data, status_code=403)
        assert okta_verify_api_method(url, data) == error

    with pytest.raises(SystemExit) as error, requests_mock.Mocker() as m:
        data = {"response": "incorrect", "errorCode": "0xdeadbeef"}
        m.post(url, json=data, status_code=403)
        assert okta_verify_api_method("http://acme.org", data) == error


def test_login_error_code_parser():
    """Test whether message on specific status equal."""
    from tokendito.okta import login_error_code_parser, _status_dict

    okta_status_dict = _status_dict

    for (key, value) in okta_status_dict.items():
        assert login_error_code_parser(key) == "Okta auth failed: " + value
    unexpected_key = "UNEXPECTED_KEY"
    value = f"Okta auth failed: {unexpected_key}. Please verify your settings and try again."
    assert login_error_code_parser(unexpected_key) == value


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


@pytest.mark.parametrize("preset_mfa, output", [("push", 0), (None, 1)])
def test_user_mfa_index(preset_mfa, output, mocker, sample_json_response):
    """Test whether the function returns correct mfa method index."""
    from tokendito.okta import user_mfa_index

    primary_auth = sample_json_response["okta_response_mfa"]

    mfa_options = primary_auth["_embedded"]["factors"]
    available_mfas = [d["factorType"] for d in mfa_options]
    mocker.patch("tokendito.user.select_preferred_mfa_index", return_value=1)

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

    primary_auth = sample_json_response
    mfa_options = primary_auth["okta_response_mfa"]["_embedded"]["factors"]

    correct_output = (
        "\nSelect your preferred MFA method and press Enter:\n"
        "[0]  OKTA    push                Redmi 6 Pro         Id: opfrar9yi4bKJNH2WEWQ0x8\n"
        f"[1]  GOOGLE  token:software:totp {email} Id: FfdskljfdsS1ljUT0r8\n"
        f"[2]  OKTA    token:software:totp {email} Id: fdsfsd6ewREr8\n"
    )

    mocker.patch("tokendito.user.collect_integer", return_value=1)
    select_preferred_mfa_index(mfa_options)
    captured = capsys.readouterr()
    assert captured.out == correct_output


def test_user_mfa_challenge_with_no_mfa_methods(sample_headers, sample_json_response):
    """Test whether okta response has mfa methods."""
    from tokendito.okta import user_mfa_challenge

    primary_auth = sample_json_response["okta_response_no_auth_methods"]

    with pytest.raises(SystemExit) as error:
        assert user_mfa_challenge(sample_headers, primary_auth) == error


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

    saml_xml = "x"
    saml_response_string = "y"

    role_arns = [
        "arn:aws:iam::123456789012:role/pytest",
        "arn:aws:iam::124356789012:role/pytest",
    ]
    mocker.patch("tokendito.user.prompt_role_choices", return_value=selected_role)
    assert select_role_arn(role_arns, saml_xml, saml_response_string) == selected_role


def test_repeated_line_select_role_arn():
    """Ensure that duplicate roles trigger an error."""
    import tokendito
    from tokendito.user import select_role_arn

    saml_xml = "x"
    saml_response_string = "y"
    tokendito.config.aws["profile"] = "pytest"

    role_arns = [
        "arn:aws:iam::123456789012:role/pytest",
        "arn:aws:iam::123456789012:role/pytest",
    ]

    with pytest.raises(SystemExit) as error:
        assert select_role_arn(role_arns, saml_xml, saml_response_string) == error


def test_incorrect_role_arn():
    """Ensure that incorrectly selected options trigger an error."""
    import tokendito
    from tokendito.user import select_role_arn

    saml_xml = "x"
    saml_response_string = "y"
    tokendito.config.aws["profile"] = "pytest_failure"
    tokendito.config.aws["role_arn"] = "pytest_failure"

    role_arns = [
        "arn:aws:iam::123456789012:role/pytest",
        "arn:aws:iam::124356789012:role/pytest",
    ]

    with pytest.raises(SystemExit) as error:
        assert select_role_arn(role_arns, saml_xml, saml_response_string) == error


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
                            "script": {"href": "python-v3.6"},
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
        "app_sig": "fdsfdfds",
        "parent": f"{config.okta['org']}/signin/verify/duo/web",
        "host": "test_host",
        "sid": "",
        "version": "3.6",
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
        "app_sig": "fdsfdfds",
        "parent": f"{config.okta['org']}/signin/verify/duo/web",
        "host": "test_host",
        "sid": "",
        "version": "3.6",
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
        assert authenticate_to_roles("secret_session_token", "http://test.url.com") == error


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
    assert pytest_config.aws["region"] == "us-east-1"


def test_default_loglevel():
    """Check default loglevel."""
    import tokendito

    default_loglevel = "WARNING"

    assert tokendito.Config().user["loglevel"] == default_loglevel


def test_loglevel_collected_from_env(monkeypatch, tmpdir):
    """Ensure that the loglevel collected from env vars."""
    from argparse import Namespace
    from tokendito import user, config, Config

    args = {
        "okta_username": "pytest_arg",
        "okta_app_url": "https://acme.okta.org/_arg",
        "version": None,
        "configure": False,
        "user_config_file": None,
        "user_config_profile": None,
    }

    monkeypatch.setenv("TOKENDITO_USER_LOGLEVEL", "DEBUG")
    monkeypatch.setattr(user, "parse_cli_args", lambda *x: Namespace(**args))
    monkeypatch.setattr(user, "process_ini_file", lambda *x: Config())

    user.process_options(None)

    assert config.user["loglevel"] == "DEBUG"
