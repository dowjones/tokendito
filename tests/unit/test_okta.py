# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures for the Okta module."""
from unittest.mock import Mock

import pytest
from tokendito.config import Config
from tokendito.http_client import HTTP_client


@pytest.fixture
def sample_headers():
    """Return a headers."""
    headers = {"content-type": "application/json", "accept": "application/json"}
    return headers


@pytest.mark.parametrize(
    "session_token, expected, mfa_availability",
    [
        (345, 345, "okta_response_no_auth_methods"),
        (345, 345, "okta_response_mfa"),
        (345, 345, "okta_response_no_auth_methods"),
        (None, None, "okta_response_no_mfa_no_session_token"),
    ],
)
def test_get_session_token(
    sample_json_response,
    session_token,
    expected,
    mocker,
    sample_headers,
    mfa_availability,
):
    """Test whether function return key on specific status."""
    from tokendito.config import Config
    from tokendito.okta import get_session_token

    pytest_config = Config()
    primary_auth = sample_json_response[mfa_availability]

    mocker.patch("tokendito.okta.mfa_challenge", return_value=session_token)
    assert get_session_token(pytest_config, primary_auth, sample_headers) == expected
    with pytest.raises(SystemExit) as err:
        assert get_session_token(pytest_config, None, sample_headers) == err


def test_bad_session_token(mocker, sample_json_response, sample_headers):
    """Test whether function behave accordingly."""
    from tokendito.config import Config
    from tokendito.okta import get_session_token

    pytest_config = Config()
    mocker.patch("tokendito.okta.api_error_code_parser", return_value=None)
    okta_response_statuses = ["okta_response_error", "okta_response_empty"]

    for response in okta_response_statuses:
        primary_auth = sample_json_response[response]

        with pytest.raises(SystemExit) as error:
            assert get_session_token(pytest_config, primary_auth, sample_headers) == error


@pytest.mark.parametrize(
    "mfa_provider, session_token, selected_factor, expected",
    [
        ("DUO", 123, {"_embedded": {}}, 123),
        (
            "OKTA",
            345,
            {"_embedded": {"factor": {"factorType": "push"}}},
            345,
        ),  # Changed expected value to 2
        ("GOOGLE", 456, {"_embedded": {"factor": {"factorType": "sms"}}}, 456),
    ],
)
def test_mfa_provider_type(
    mfa_provider,
    session_token,
    selected_factor,
    expected,
    mocker,
    sample_headers,
):
    """Test whether function return key on specific MFA provider."""
    from tokendito.http_client import HTTP_client
    from tokendito.okta import mfa_provider_type

    mock_response = {"sessionToken": session_token}
    mocker.patch.object(HTTP_client, "post", return_value=mock_response)

    mocker.patch("tokendito.duo.api_post", return_value=None)

    payload = {"x": "y", "t": "z"}
    selected_mfa_option = 1
    mfa_challenge_url = 1
    primary_auth = 1
    pytest_config = Config()

    mocker.patch("tokendito.duo.authenticate", return_value=payload)
    mocker.patch("tokendito.okta.push_approval", return_value={"sessionToken": session_token})
    mocker.patch("tokendito.okta.totp_approval", return_value={"sessionToken": session_token})

    assert (
        mfa_provider_type(
            pytest_config,
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
    from tokendito.config import Config
    from tokendito.http_client import HTTP_client
    from tokendito.okta import mfa_provider_type

    pytest_config = Config()
    payload = {"x": "y", "t": "z"}
    selected_mfa_option = 1
    mfa_challenge_url = 1
    primary_auth = 1
    selected_factor = {}

    mfa_verify = {"sessionToken": "pytest_session_token"}
    mfa_bad_provider = "bad_provider"

    mock_response = Mock()
    mock_response.json.return_value = mfa_verify

    mocker.patch("tokendito.duo.authenticate", return_value=payload)
    mocker.patch.object(HTTP_client, "post", return_value=mock_response)
    mocker.patch("tokendito.okta.totp_approval", return_value=mfa_verify)

    with pytest.raises(SystemExit) as error:
        assert (
            mfa_provider_type(
                pytest_config,
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


def test_api_error_code_parser():
    """Test whether message on specific status equal."""
    from tokendito.okta import _status_dict
    from tokendito.okta import api_error_code_parser

    okta_status_dict = _status_dict

    for key, value in okta_status_dict.items():
        assert api_error_code_parser(key) == "Okta auth failed: " + value
    unexpected_key = "UNEXPECTED_KEY"
    value = f"Okta auth failed: {unexpected_key}. Please verify your settings and try again."
    assert api_error_code_parser(unexpected_key) == value


@pytest.mark.parametrize(
    "preset_mfa, output",
    [("push", 0), (None, 1), ("0xdeadbeef", 1), ("opfrar9yi4bKJNH2WEW", 0), ("pytest_dupe", 1)],
)
def test_mfa_index(preset_mfa, output, mocker, sample_json_response):
    """Test whether the function returns correct mfa index."""
    from tokendito.okta import mfa_index

    primary_auth = sample_json_response["okta_response_mfa"]

    mfa_options = primary_auth["_embedded"]["factors"]
    available_mfas = [f"{d['provider']}_{d['factorType']}_{d['id']}" for d in mfa_options]
    mocker.patch("tokendito.user.select_preferred_mfa_index", return_value=1)

    if preset_mfa == "pytest_dupe":
        with pytest.raises(SystemExit) as err:
            mfa_index(preset_mfa, available_mfas, mfa_options)
        assert err.value.code == output
    else:
        assert mfa_index(preset_mfa, available_mfas, mfa_options) == output


def test_mfa_options(sample_headers, sample_json_response, mocker):
    """Test handling of MFA approval."""
    from tokendito.config import Config
    from tokendito.http_client import HTTP_client
    from tokendito.okta import totp_approval

    selected_mfa_option = {"factorType": "push"}
    primary_auth = sample_json_response["okta_response_no_mfa"]
    payload = {"x": "y", "t": "z"}
    mfa_challenge_url = "https://pytest"
    pytest_config = Config(okta={"mfa_response": None})

    mocker.patch("tokendito.user.get_input", return_value="012345")

    mocker.patch.object(HTTP_client, "post", return_value={"sessionToken": "pytest"})
    selected_mfa_option = {"factorType": "token:software:totp"}
    primary_auth["stateToken"] = "pytest"
    mfa_verify = {"sessionToken": "pytest"}

    ret = totp_approval(
        pytest_config, selected_mfa_option, sample_headers, mfa_challenge_url, payload, primary_auth
    )

    assert ret == mfa_verify


def test_mfa_challenge_with_no_mfas(sample_headers, sample_json_response):
    """Test whether okta response has mfas."""
    from tokendito.config import Config
    from tokendito.okta import mfa_challenge

    primary_auth = sample_json_response["okta_response_no_auth_methods"]
    pytest_config = Config()

    with pytest.raises(SystemExit) as error:
        assert mfa_challenge(pytest_config, sample_headers, primary_auth) == error


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
def test_push_approval(mocker, return_value, side_effect, expected):
    """Test push approval."""
    from tokendito import okta

    challenge_url = "https://pytest/api/v1/authn/factors/factorid/verify"
    payload = {"some_key": "some_value"}

    mocker.patch.object(HTTP_client, "post", return_value=return_value, side_effect=side_effect)
    mocker.patch("time.sleep", return_value=None)

    if "status" in return_value and return_value["status"] == "SUCCESS":
        ret = okta.push_approval(challenge_url, payload)
        assert ret["status"] == "SUCCESS"
    elif "factorResult" in return_value and return_value["factorResult"] == "WAITING":
        ret = okta.push_approval(challenge_url, payload)
        assert ret["status"] == "SUCCESS"
    else:
        with pytest.raises(SystemExit) as err:
            okta.push_approval(challenge_url, payload)
        assert err.value.code == expected


@pytest.mark.parametrize(
    "auth_properties,expected",
    [
        ({}, False),
        (None, False),
        ({"type": "OKTA"}, True),
        ({"type": "SAML2"}, False),
    ],
)
def test_is_local_auth(auth_properties, expected):
    """Test local auth method."""
    from tokendito import okta

    assert okta.is_local_auth(auth_properties) == expected


@pytest.mark.parametrize(
    "auth_properties,expected",
    [
        ({}, False),
        (None, False),
        ({"type": "OKTA"}, False),
        ({"type": "SAML2"}, True),
    ],
)
def test_is_saml2_auth(auth_properties, expected):
    """Test saml2 auth method."""
    from tokendito import okta

    assert okta.is_saml2_auth(auth_properties) == expected


@pytest.mark.parametrize(
    "html, raw, expected",
    [
        (
            '<html><body><input name="SAMLResponse" type="hidden" '
            'value="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4="></body></html>',
            False,
            '<?xml version="1.0" encoding="UTF-8"?>',
        ),
        (
            '<html><body><input name="SAMLResponse" type="hidden" '
            'value="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4="></body></html>',
            True,
            "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4=",
        ),
        (
            "",
            False,
            None,
        ),
        (
            "invalid html",
            False,
            None,
        ),
    ],
)
def test_extract_saml_response(html, raw, expected):
    """Test extracting SAML response."""
    from tokendito import okta

    assert okta.extract_saml_response(html, raw) == expected


@pytest.mark.parametrize(
    "html, raw, expected",
    [
        (
            '<html><body><input name="SAMLRequest" type="hidden" '
            'value="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4="></body></html>',
            False,
            '<?xml version="1.0" encoding="UTF-8"?>',
        ),
        (
            '<html><body><input name="SAMLRequest" type="hidden" '
            'value="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4="></body></html>',
            True,
            "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4=",
        ),
        (
            "",
            False,
            None,
        ),
        (
            "invalid html",
            False,
            None,
        ),
    ],
)
def test_extract_saml_request(html, raw, expected):
    """Test extracting SAML response."""
    from tokendito import okta

    assert okta.extract_saml_request(html, raw) == expected


@pytest.mark.parametrize(
    "html,expected",
    [
        (
            "<html><body><form action='https://acme.okta.com/app/okta_org2org/"
            "akjlkjlksjx0xmdd/sso/saml' id='appForm' method='POST'</form></body></html>",
            "https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/saml",
        ),
        ("<html><body><form action='' id='appForm' method='POST'</form></body></html>", ""),
        ("invalid html", None),
    ],
)
def test_extract_form_post_url(html, expected):
    """Test extracting form post URL."""
    from tokendito import okta

    assert okta.extract_form_post_url(html) == expected


@pytest.mark.parametrize(
    "html,expected",
    [
        (
            "<html><body><input name='RelayState' type='hidden' value='foobar'></body></html>",
            "foobar",
        ),
        ("<html><body><input name='RelayState' type='hidden' value=''></body></html>", ""),
        ("invalid html", None),
    ],
)
def test_extract_saml_relaystate(html, expected):
    """Test extracting SAML relay state."""
    from tokendito import okta

    assert okta.extract_saml_relaystate(html) == expected


def test_get_saml_request(mocker):
    """Test getting SAML request."""
    from tokendito import okta
    from tokendito.http_client import HTTP_client

    mock_response = Mock()
    mock_response.text = (
        "<html><body><form action='https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/"
        "saml' id='appForm' method='POST'</form><input name='SAMLRequest' type='hidden' "
        "value='PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4='>"
        "<input name='RelayState' type='hidden' value='foobar'></body></html>"
    )

    mocker.patch.object(HTTP_client, "get", return_value=mock_response)

    auth_properties = {"id": "id", "metadata": "metadata"}

    assert okta.get_saml_request(auth_properties) == {
        "base_url": "https://acme.okta.com",
        "post_url": "https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/saml",
        "relay_state": "foobar",
        "request": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4=",
    }


def test_send_saml_request(mocker):
    """Test sending SAML request."""
    from tokendito import okta

    mock_response = Mock()
    mock_response.text = (
        "<html><body><form action='https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/"
        "saml' id='appForm' method='POST'</form><input name='SAMLResponse' type='hidden' "
        "value='PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4='>"
        "<input name='RelayState' type='hidden' value='foobar'></body></html>"
    )

    saml_request = {"relay_state": "relay_state", "request": "request", "post_url": "post_url"}
    cookie = {"sid": "pytestcookie"}

    mocker.patch("tokendito.http_client.HTTP_client.get", return_value=mock_response)

    assert okta.send_saml_request(saml_request, cookie) == {
        "response": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4=",
        "relay_state": "foobar",
        "post_url": "https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/saml",
    }


def test_send_saml_response(mocker):
    """Test sending SAML response."""
    from tokendito import okta
    from tokendito.http_client import HTTP_client

    mock_response = Mock()
    mock_response.cookies = {"sid": "pytestcookie"}

    saml_response = {
        "response": "pytestresponse",
        "relay_state": "foobar",
        "post_url": "https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/saml",
    }

    mocker.patch.object(HTTP_client, "post", return_value=mock_response)

    assert okta.send_saml_response(saml_response) == mock_response.cookies


def test_authenticate(mocker):
    """Test authentication."""
    from tokendito import okta
    from tokendito.config import Config

    pytest_config = Config(
        okta={
            "username": "pytest",
            "password": "pytest",
            "org": "https://acme.okta.org/",
        }
    )
    sid = {"sid": "pytestsid"}
    mocker.patch("tokendito.user.request_cookies", return_value=sid)
    mocker.patch("tokendito.okta.local_auth", return_value="foobar")
    mocker.patch("tokendito.okta.saml2_auth", return_value=sid)

    mocker.patch("tokendito.okta.get_auth_properties", return_value={"type": "OKTA"})
    assert okta.authenticate(pytest_config) == sid

    mocker.patch("tokendito.okta.get_auth_properties", return_value={"type": "SAML2"})
    assert okta.authenticate(pytest_config) == sid

    mocker.patch("tokendito.okta.get_auth_properties", return_value={"type": "UNKNOWN"})
    with pytest.raises(SystemExit) as error:
        assert okta.authenticate(pytest_config) == error

    mocker.patch("tokendito.okta.get_auth_properties", return_value={})
    with pytest.raises(SystemExit) as error:
        assert okta.authenticate(pytest_config) == error


def test_step_up_authenticate(mocker):
    """Test set up authenticate method."""
    from tokendito import okta
    from tokendito.config import Config
    from tokendito.http_client import HTTP_client

    pytest_config = Config(
        okta={
            "username": "pytest",
            "org": "https://acme.okta.org/",
        }
    )

    state_token = "test-state-token"

    # Test missing auth type
    mocker.patch("tokendito.okta.get_auth_properties", return_value={})
    assert okta.step_up_authenticate(pytest_config, state_token) is False

    # Test unsupported auth type
    mocker.patch("tokendito.okta.get_auth_properties", return_value={"type": "SAML2"})
    assert okta.step_up_authenticate(pytest_config, state_token) is False

    # Test supported auth type...
    mocker.patch("tokendito.okta.get_auth_properties", return_value={"type": "OKTA"})

    # ...with SUCCESS status
    mock_response_data = {"status": "SUCCESS"}
    mocker.patch.object(HTTP_client, "post", return_value=mock_response_data)

    assert okta.step_up_authenticate(pytest_config, state_token) is True

    # ...with MFA_REQUIRED status
    mock_response_data = {"status": "MFA_REQUIRED"}
    mocker.patch.object(HTTP_client, "post", return_value=mock_response_data)
    patched_mfa_challenge = mocker.patch.object(
        okta, "mfa_challenge", return_value="test-session-token"
    )

    assert okta.step_up_authenticate(pytest_config, state_token) is True
    assert patched_mfa_challenge.call_count == 1

    # ...with unknown status
    mock_response_data = {"status": "unknown"}
    mocker.patch.object(HTTP_client, "post", return_value=mock_response_data)

    assert okta.step_up_authenticate(pytest_config, state_token) is False


def test_local_auth(mocker):
    """Test local auth method."""
    from tokendito import okta
    from tokendito.config import Config
    from tokendito.http_client import HTTP_client

    # Create a fake HTTP response using Mock
    mock_response_data = {"status": "SUCCESS", "sessionToken": "pytesttoken"}

    # Patch HTTP_client.post to return the mock response
    mocker.patch.object(HTTP_client, "post", return_value=mock_response_data)

    # Initialize the configuration
    pytest_config = Config(
        okta={
            "username": "pytest",
            "password": "pytest",
            "org": "https://acme.okta.org/",
        }
    )

    assert okta.local_auth(pytest_config) == "pytesttoken"


def test_saml2_auth(mocker):
    """Test saml2 authentication."""
    from tokendito import okta
    from tokendito.config import Config

    auth_properties = {"id": "id", "metadata": "metadata"}

    pytest_config = Config(
        okta={
            "username": "pytest",
            "password": "pytest",
            "org": "https://acme.okta.org/",
        }
    )
    saml_request = {
        "base_url": "https://acme.okta.com",
    }
    mocker.patch("tokendito.okta.get_saml_request", return_value=saml_request)
    mocker.patch("tokendito.okta.authenticate", return_value="pytestsessioncookie")

    saml_response = {
        "response": "pytestresponse",
    }

    mocker.patch("tokendito.okta.send_saml_request", return_value=saml_response)
    mocker.patch("tokendito.okta.send_saml_response", return_value="pytestsessionid")
    assert okta.saml2_auth(pytest_config, auth_properties) == "pytestsessionid"
