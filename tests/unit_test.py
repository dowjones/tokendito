# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures."""
from datetime import datetime
import os
import sys

import pytest
import semver
from tokendito.settings import okta_status_dict


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def valid_settings():
    """Return a dict with valid settings for the tokendito.settings module."""
    from tokendito import settings

    builtins_and_methods = [
        "__builtins__",
        "__cached__",
        "__doc__",
        "__file__",
        "__loader__",
        "__name__",
        "__package__",
        "__spec__",
        "ascii",
        "bytes",
        "chr",
        "dict",
        "division",
        "encoding",
        "filter",
        "hex",
        "input",
        "int",
        "list",
        "map",
        "next",
        "object",
        "oct",
        "open",
        "pow",
        "print_function",
        "range",
        "role_arn",
        "round",
        "str",
        "super",
        "sys",
        "unicode_literals",
        "zip",
    ]

    settings_keys = dir(settings)
    unmatched_keys = list(set(settings_keys) - set(builtins_and_methods))

    valid_keys = {str(key): key + "_pytest_patched" for key in unmatched_keys}
    return valid_keys


@pytest.fixture
def invalid_settings():
    """Return a dict with invalid settings for the tokendito.settings module."""
    invalid_keys = {
        "okta": "okta_pytest_patched",
        "okta_deadbeef": "okta_deadbeef_pytest_patched",
        "aws_deadbeef": "aws_deadbeef_pytest_patched",
        "pytest_bad_value": "pytest_bad_value_pytest_patched",
    }
    return invalid_keys


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
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        + "/tokendito/__init__.py"
    )
    imported_path = os.path.realpath(tokendito.__file__)
    assert imported_path.startswith(local_path)


def test_semver_version():
    """Ensure the package version is semver compliant."""
    from tokendito.__version__ import __version__ as version

    assert semver.VersionInfo.parse(version)


def test__version__var_names():
    """Ensure variables follow the __varname__ convention."""
    from tokendito import __version__

    for item in vars(__version__):
        assert item.startswith("__")
        assert item.endswith("__")


def test_set_okta_username(mocker):
    """Test whether data sent is the same as data returned."""
    from tokendito import helpers, settings

    mocker.patch("tokendito.helpers.input", return_value="pytest_patched")
    val = helpers.set_okta_username()

    assert val == "pytest_patched"
    assert settings.okta_username == "pytest_patched"


def test_set_okta_password(monkeypatch):
    """Test whether data sent is the same as data returned."""
    from tokendito import helpers, settings
    import getpass

    monkeypatch.setattr(getpass, "getpass", lambda: "pytest_patched")
    val = helpers.set_okta_password()

    assert val == "pytest_patched"
    assert settings.okta_password == "pytest_patched"


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
def test_validate_okta_aws_app_url(url, expected):
    """Test whether the Okta URL is parsed correctly."""
    from tokendito import helpers

    assert helpers.validate_okta_aws_app_url(input_url=url) is expected


@pytest.mark.parametrize(
    "test,limit,expected",
    [(0, 10, True), (5, 10, True), (10, 10, False), (-1, 10, False), (1, 0, False)],
)
def test_check_within_range(mocker, test, limit, expected):
    """Test whether a given number is in the range 0 >= num < limit."""
    from tokendito import helpers

    mocker.patch("logging.error")
    assert helpers.check_within_range(test, limit) is expected


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
def test_check_integer(value, expected, mocker):
    """Test whether the integer testing function works within boundaries."""
    from tokendito import helpers

    mocker.patch("logging.error")
    assert helpers.check_integer(value) is expected


@pytest.mark.parametrize(
    "test,limit,expected", [(1, 10, True), (-1, 10, False), ("pytest", 10, False)]
)
def test_validate_input(mocker, test, limit, expected):
    """Check if a given input is within the 0 >= num < limit range."""
    from tokendito import helpers

    mocker.patch("logging.error")
    assert helpers.validate_input(test, limit) is expected


def test_get_input(mocker):
    """Check if provided input is return unmodified."""
    from tokendito import helpers

    mocker.patch("tokendito.helpers.input", return_value="pytest_patched")
    assert helpers.get_input() == "pytest_patched"


@pytest.mark.parametrize("value,expected", [("00", 0), ("01", 1), ("5", 5)])
def test_collect_integer(mocker, value, expected):
    """Check if a given digit or series of digits are properly casted to int."""
    from tokendito import helpers

    mocker.patch("tokendito.helpers.input", return_value=value)
    assert helpers.collect_integer(10) == expected


def test_utc_to_local():
    """Check if passed utc datestamp becomes local one."""
    import pytz
    from tokendito import helpers
    from tzlocal import get_localzone

    utc = datetime.now(pytz.utc)
    local_time = utc.replace(tzinfo=pytz.utc).astimezone(tz=get_localzone())
    local_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z")

    assert helpers.utc_to_local(utc) == local_time


def test_prepare_payload():
    """Check if values passed return in a dictionary."""
    from tokendito import helpers

    assert helpers.prepare_payload(pytest_key="pytest_val") == {
        "pytest_key": "pytest_val"
    }
    assert helpers.prepare_payload(pytest_key=None) == {"pytest_key": None}
    assert helpers.prepare_payload(
        pytest_key1="pytest_val1", pytest_key2="pytest_val2"
    ) == {"pytest_key1": "pytest_val1", "pytest_key2": "pytest_val2"}


def test_set_passcode(mocker):
    """Check if numerical passcode can handle leading zero values."""
    from tokendito import duo_helpers

    mocker.patch("tokendito.helpers.input", return_value="0123456")
    assert duo_helpers.set_passcode({"factor": "passcode"}) == "0123456"


def test_process_environment(monkeypatch, valid_settings, invalid_settings):
    """Test whether environment variables are set in settings.*."""
    from tokendito import helpers, settings

    # ENV standard is uppercase
    valid_keys = {key.upper(): val for (key, val) in valid_settings.items()}
    invalid_keys = {key.upper(): val for (key, val) in invalid_settings.items()}

    env_keys = {**valid_keys.copy(), **invalid_keys}

    monkeypatch.setattr(os, "environ", env_keys)
    helpers.process_environment()

    for key in valid_settings:
        assert getattr(settings, key) == valid_settings[key]

    for key in invalid_settings:
        assert getattr(settings, key, "not_found") == "not_found"


def test_process_arguments(valid_settings, invalid_settings):
    """Test whether arguments are correctly set in settings.*."""
    from tokendito import helpers, settings
    from argparse import Namespace

    args = {**valid_settings.copy(), **invalid_settings}
    args.update()

    helpers.process_arguments(Namespace(**args))

    for key_name in valid_settings:
        assert getattr(settings, key_name) == valid_settings[key_name]

    for key_name in invalid_settings:
        assert getattr(settings, key_name, "not_found") == "not_found"


@pytest.mark.skipif(
    sys.version_info[:2] == (3, 5),
    reason="ConfigParser bug, see https://bugs.python.org/issue29623",
)
def test_process_ini_file(tmpdir, valid_settings, invalid_settings, mocker):
    """Test whether ini config elements are correctly set in settings.*."""
    from tokendito import helpers, settings

    # Create a mock config file
    data = "[default]\nokta_username = pytest\n\n[pytest]\n"
    data += "".join(f"{key} = {val}\n" for key, val in valid_settings.items())
    data += "".join(f"{key} = {val}\n" for key, val in invalid_settings.items())
    data += "\n[pytest_end]\n"
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
        mocker.patch("logging.error")
        helpers.process_ini_file(path, "pytest_expected_failure")
        # assert err.type == SystemExit
        assert err.value.code == 2

    helpers.process_ini_file(path, "pytest")
    # Test that correct options are set
    for key_name in valid_settings:
        assert getattr(settings, key_name) == valid_settings[key_name]
    # Test that incorrect options aren't set
    for key_name in invalid_settings:
        assert getattr(settings, key_name, "not_found") == "not_found"


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
    from tokendito.okta_helpers import user_session_token

    primary_auth = sample_json_response[mfa_availability]

    mocker.patch(
        "tokendito.okta_helpers.user_mfa_challenge", return_value=session_token
    )
    assert user_session_token(primary_auth, sample_headers) == expected


def test_bad_user_session_token(sample_json_response, sample_headers, mocker):
    """Test whether function behave accordingly."""
    from tokendito.okta_helpers import user_session_token

    mocker.patch("tokendito.okta_helpers.login_error_code_parser", return_value=None)
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
    from tokendito.okta_helpers import mfa_provider_type

    payload = {"x": "y", "t": "z"}
    callback_url = "https://www.acme.org"
    selected_mfa_option = 1
    mfa_challenge_url = 1
    primary_auth = 1
    selected_factor = 1

    mfa_verify = {"sessionToken": session_token}
    mocker.patch(
        "tokendito.duo_helpers.authenticate_duo",
        return_value=(payload, sample_headers, callback_url),
    )
    mocker.patch(
        "tokendito.okta_helpers.okta_verify_api_method", return_value=mfa_verify
    )
    mocker.patch("tokendito.okta_helpers.user_mfa_options", return_value=mfa_verify)
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
        == session_token
    )


def test_bad_mfa_provider_type(mocker, sample_headers):
    """Test whether function return key on specific MFA provider."""
    from tokendito.okta_helpers import mfa_provider_type

    payload = {"x": "y", "t": "z"}
    callback_url = "https://www.acme.org"
    selected_mfa_option = 1
    mfa_challenge_url = 1
    primary_auth = 1
    selected_factor = 1

    mfa_verify = {"sessionToken": "123"}
    mfa_bad_provider = "bad_provider"
    mocker.patch(
        "tokendito.duo_helpers.authenticate_duo",
        return_value=(payload, sample_headers, callback_url),
    )
    mocker.patch(
        "tokendito.okta_helpers.okta_verify_api_method", return_value=mfa_verify
    )
    mocker.patch("tokendito.okta_helpers.user_mfa_options", return_value=mfa_verify)

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


def test_login_error_code_parser(mocker):
    """Test whether message on specific status equal."""
    from tokendito.okta_helpers import login_error_code_parser

    mocker.patch("logging.error")
    for key, value in okta_status_dict.items():
        assert (
            login_error_code_parser(key, okta_status_dict)
            == "Okta auth failed: " + value
        )
    unexpected_key = "UNEXPECTED_KEY"
    value = f"Okta auth failed: {unexpected_key}. Please verify your settings and try again."
    assert login_error_code_parser(unexpected_key, okta_status_dict) == value


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
    from tokendito.helpers import mfa_option_info

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
    from tokendito.okta_helpers import user_mfa_index

    primary_auth = sample_json_response["okta_response_mfa"]

    mfa_options = primary_auth["_embedded"]["factors"]
    available_mfas = [d["factorType"] for d in mfa_options]
    mocker.patch("tokendito.helpers.select_preferred_mfa_index", return_value=1)

    assert user_mfa_index(preset_mfa, available_mfas, mfa_options) == output


def test_select_preferred_mfa_index(mocker, sample_json_response):
    """Test whether the function returns index entered by user."""
    from tokendito.helpers import select_preferred_mfa_index

    primary_auth = sample_json_response
    mfa_options = primary_auth["okta_response_mfa"]["_embedded"]["factors"]
    for output in mfa_options:
        mocker.patch("tokendito.helpers.collect_integer", return_value=output)
        assert select_preferred_mfa_index(mfa_options) == output


@pytest.mark.parametrize(
    "email",
    [
        ("Token.Dito@acme.org"),
    ],
)
def test_select_preferred_mfa_index_output(email, capsys, mocker, sample_json_response):
    """Test whether the function gives correct output."""
    from tokendito.helpers import select_preferred_mfa_index

    primary_auth = sample_json_response
    mfa_options = primary_auth["okta_response_mfa"]["_embedded"]["factors"]

    correct_output = (
        "\nSelect your preferred MFA method and press Enter:\n"
        "[0]  OKTA    push                Redmi 6 Pro         Id: opfrar9yi4bKJNH2WEWQ0x8\n"
        f"[1]  GOOGLE  token:software:totp {email} Id: FfdskljfdsS1ljUT0r8\n"
        f"[2]  OKTA    token:software:totp {email} Id: fdsfsd6ewREr8\n"
    )

    mocker.patch("tokendito.helpers.collect_integer", return_value=1)
    select_preferred_mfa_index(mfa_options)
    captured = capsys.readouterr()
    assert captured.out == correct_output


def test_bad_with_no_mfa_methods_user_mfa_challenge(
    sample_headers, sample_json_response
):
    """Test whether okta response has mfa methods."""
    from tokendito.okta_helpers import user_mfa_challenge

    primary_auth = sample_json_response["okta_response_no_auth_methods"]

    with pytest.raises(SystemExit) as error:
        assert user_mfa_challenge(sample_headers, primary_auth) == error


@pytest.mark.parametrize(
    "aws_profile, role_arn, selected_role",
    [
        ("token", None, "arn:aws:iam::123456789012:role/token"),
        (
            "dito",
            None,
            "arn:aws:iam::124356789012:role/dito",
        ),
        (
            None,
            "arn:aws:iam::124356789012:role/dito",
            "arn:aws:iam::124356789012:role/dito",
        ),
        (
            None,
            "arn:aws:iam::123456789012:role/token",
            "arn:aws:iam::123456789012:role/token",
        ),
    ],
)
def test_good_select_role_arn(
    mocker, monkeypatch, aws_profile, role_arn, selected_role
):
    """Test which role does the user has chosen."""
    from tokendito.helpers import select_role_arn

    saml_xml = "x"
    saml_response_string = "y"

    role_arns = [
        "arn:aws:iam::123456789012:role/token",
        "arn:aws:iam::124356789012:role/dito",
    ]
    monkeypatch.setattr("tokendito.settings.aws_profile", aws_profile)
    mocker.patch("tokendito.helpers.prompt_role_choices", return_value=selected_role)
    assert select_role_arn(role_arns, saml_xml, saml_response_string) == selected_role


def test_repeated_line_select_role_arn(monkeypatch):
    """Test behaviour repeated role."""
    from tokendito.helpers import select_role_arn

    saml_xml = "x"
    saml_response_string = "y"

    role_arns = [
        "arn:aws:iam::123456789012:role/token",
        "arn:aws:iam::123456789012:role/token",
    ]
    monkeypatch.setattr("tokendito.settings.aws_profile", "token")

    with pytest.raises(SystemExit) as error:
        assert select_role_arn(role_arns, saml_xml, saml_response_string) == error


def test_bad_select_role_arn(monkeypatch):
    """Test behaviour wrong aws_profile and role_arn."""
    from tokendito.helpers import select_role_arn

    saml_xml = "x"
    saml_response_string = "y"

    role_arns = [
        "arn:aws:iam::123456789012:role/token",
        "arn:aws:iam::124356789012:role/dito",
    ]
    monkeypatch.setattr("tokendito.settings.aws_profile", "wrong_response")
    monkeypatch.setattr(
        "tokendito.settings.role_arn",
        "arn:aws:iam::123456789012:role/wrong_response",
    )
    with pytest.raises(SystemExit) as error:
        assert select_role_arn(role_arns, saml_xml, saml_response_string) == error
