# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures for the Okta module."""
from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests.cookies
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
        ({"type": "IWA"}, True),
        ({"type": "SAML2"}, False),
    ],
)
def test_local_authentication_enabled(auth_properties, expected):
    """Test local auth method."""
    from tokendito import okta

    assert okta.local_authentication_enabled(auth_properties) == expected


@pytest.mark.parametrize(
    "auth_properties,expected",
    [
        ({}, False),
        (None, False),
        ({"type": "OKTA"}, False),
        ({"type": "SAML2"}, True),
    ],
)
def test_is_saml2_authentication(auth_properties, expected):
    """Test saml2 auth method."""
    from tokendito import okta

    assert okta.is_saml2_authentication(auth_properties) == expected


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
    import base64

    mock_response = Mock()
    mock_response.text = (
        "<html><body><form action='https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/"
        "saml' id='appForm' method='POST'</form><input name='SAMLResponse' type='hidden' "
        "value='PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4='>"
        "<input name='RelayState' type='hidden' value='foobar'></body></html>"
    )

    saml_request = {"relay_state": "relay_state", "request": "request", "post_url": "post_url"}

    mocker.patch.object(base64, "b64decode", return_value="foo")
    mocker.patch("tokendito.http_client.HTTP_client.get", return_value=mock_response)

    assert okta.send_saml_request(saml_request) == {
        "response": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4=",
        "relay_state": "foobar",
        "post_url": "https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/saml",
    }


def test_send_saml_response(mocker):
    """Test sending SAML response."""
    from tokendito import okta
    from tokendito.config import Config
    from tokendito.http_client import HTTP_client
    import base64

    cookies = requests.cookies.RequestsCookieJar()
    cookies.set("sid", "pytestcookie")
    mock_response = Mock()
    mock_response.status_code = 201
    mock_response.session = Mock()
    mock_response.session.cookies = cookies

    saml_response = {
        "response": "pytestresponse",
        "relay_state": "foobar",
        "post_url": "https://acme.okta.com/app/okta_org2org/akjlkjlksjx0xmdd/sso/saml",
    }

    mocker.patch("tokendito.okta.extract_state_token", return_value=None)

    mocker.patch.object(base64, "b64decode", return_value="foo")

    mocker.patch.object(HTTP_client, "post", return_value=mock_response)

    pytest_config = Config()

    assert okta.send_saml_response(pytest_config, saml_response) is None


def test_get_auth_pipeline(mocker):
    """Test get_auth_pipeline."""
    from tokendito import okta

    mock_response = Mock()
    mock_response.json.return_value = {"pipeline": "idx"}
    mocker.patch.object(HTTP_client, "get", return_value=mock_response)
    assert okta.get_auth_pipeline() == "idx"

    mock_response.json.return_value = {"pipeline": "v1"}
    mocker.patch.object(HTTP_client, "get", return_value=mock_response)
    assert okta.get_auth_pipeline() == "v1"

    mocker.patch.object(HTTP_client, "get", return_value="invalid format")
    with pytest.raises(SystemExit) as error:
        assert okta.get_auth_pipeline() == error

    mock_response.json.return_value = {"pipeline": "future_version"}
    mocker.patch.object(HTTP_client, "get", return_value=mock_response)
    with pytest.raises(SystemExit) as error:
        assert okta.get_auth_pipeline() == error


def test_create_authz_cookies():
    """Test create_authz_cookies."""
    from tokendito import okta

    pytest_oauth2_session_data = {"state": "pyteststate", "nonce": "pytestnonce"}

    pytest_oauth2_config = {
        "client_id": "123",
        "org": "acme",
        "authorization_endpoint": "pytesturl",
        "token_endpoint": "tokeneurl",
    }
    assert okta.create_authz_cookies(pytest_oauth2_config, pytest_oauth2_session_data) is None
    from tokendito import okta

    pytest_oauth2_config = {}
    pytest_oauth2_session_data = {"state": "pyteststate"}
    with pytest.raises(SystemExit) as error:
        assert okta.create_authz_cookies(pytest_oauth2_config, pytest_oauth2_session_data) == error


def test_get_access_token(mocker):
    """Test get_access_token."""
    from tokendito import okta

    pytest_oauth2_config = {"client_id": "123", "token_endpoint": "pytesttokenendpoint"}
    pytest_oauth2_session_data = {
        "state": "pyteststate",
        "grant_type": "pytestgrandtype",
        "redirect_uri": "pytestredirecturi",
        "code_verifier": "pytestcodeverifier",
    }

    mock_response_data = {"access_token": "pytesttoken"}
    mocker.patch.object(HTTP_client, "post", return_value=mock_response_data)
    assert (
        okta.get_access_token(pytest_oauth2_config, pytest_oauth2_session_data, "pytestcode")
        == "pytesttoken"
    )

    mock_response_data = {}
    mocker.patch.object(HTTP_client, "post", return_value=mock_response_data)
    assert (
        okta.get_access_token(pytest_oauth2_config, pytest_oauth2_session_data, "pytestcode")
        is None
    )


def test_get_pkce_code_challenge_method():
    """Test get_pkce_code_challenge_method."""
    from tokendito import okta

    assert okta.get_pkce_code_challenge_method() == "S256"


def test_get_pkce_code_challenge():
    """Test get_pkce_code_challenge."""
    from tokendito import okta

    assert (
        okta.get_pkce_code_challenge("pytestverifier")
        == "gcJ7mE9WW6euOYlu2Wx45XTPumBk5-8eoU4AF_BBbP4"
    )


@patch("hashlib.sha256")
def test_get_oauth2_state(mocker):
    """Test getting OAuth2 state."""
    from tokendito import okta

    mocker.return_value.hexdigest.return_value = "random_digested"
    assert okta.get_oauth2_state() == "random_digested"


@patch("base64.urlsafe_b64encode")
def test_get_pkce_code_verifier(mocker):
    """Test get_pkce_code_verifier."""
    from tokendito import okta

    mocker.return_value.decode.return_value = "@#!decoded_value%%"
    assert okta.get_pkce_code_verifier() == "decodedvalue"


def test_pkce_enabled():
    """Test pkce_enabled."""
    from tokendito import okta

    assert okta.pkce_enabled() is True


def test_get_authorize_code():
    """Test get authorize code."""
    from tokendito import okta

    response = Mock()
    response.url = "https://example.com?code=pytest"
    assert okta.get_authorize_code(response, "sessionToken") == "pytest"

    response.url = "https//example.com?error=login_required"
    assert okta.get_authorize_code(response, None) is None


def test_authorization_code_enabled():
    """Test authorization_code_enabled."""
    from tokendito import okta

    pytest_oauth2_config = {}
    with pytest.raises(SystemExit) as error:
        assert okta.authorization_code_enabled(pytest_oauth2_config) == error

    pytest_oauth2_config = {"grant_types_supported": "authorization_code"}
    with pytest.raises(SystemExit) as error:
        assert okta.authorization_code_enabled(pytest_oauth2_config) == error

    pytest_oauth2_config = {"grant_types_supported": "authorization_code", "org": "acme"}
    assert okta.authorization_code_enabled(pytest_oauth2_config) is True


def test_authorize_request(mocker):
    """Test authorize_request."""
    from tokendito import okta

    pytest_oauth2_config = {
        "client_id": "123",
        "token_endpoint": "pytesttokenendpoint",
    }
    pytest_oauth2_session_data = {
        "state": "pyteststate",
        "scope": "pytestscope",
        "code_challenge": "pytestchallenge",
        "code_challenge_method": "pytest",
        "grant_type": "pytestgrandtype",
        "redirect_uri": "pytestredirecturi",
        "code_verifier": "pytestcodeverifier",
        "response_type": "code",
    }

    response = Mock()
    response.url = "https://example.com?code=pytest"
    mocker.patch.object(HTTP_client, "get", return_value=response)
    with pytest.raises(SystemExit) as error:
        assert okta.authorization_code_enabled(pytest_oauth2_config) == error

    pytest_oauth2_config = {
        "client_id": "123",
        "token_endpoint": "pytesttokenendpoint",
        "authorization_endpoint": "pytestauthurl",
    }
    assert okta.authorize_request(pytest_oauth2_config, pytest_oauth2_session_data) == "pytest"


def test_get_nonce(mocker):
    """Test get_nonce."""
    from tokendito import okta

    response = Mock()
    response.text = """
    <html>
    <script nonce="PYTEST_NONCE" type="text/javascript">'
    </html>
    """
    mocker.patch.object(HTTP_client, "get", return_value=response)

    assert okta.get_nonce("https://acme.com") == "PYTEST_NONCE"

    response.text = "nonce-non-present"
    mocker.patch.object(HTTP_client, "get", return_value=response)
    assert okta.get_nonce("https://acme.com") is None


def test_get_oauth2_session_data(mocker):
    """Test get_oauth2_session_data."""
    from tokendito import okta

    mocker.patch("tokendito.okta.get_nonce", return_value="ABC")
    assert (
        okta.get_oauth2_session_data("https://acme.com")["redirect_uri"]
        == "https://acme.com/enduser/callback"
    )


def test_get_oauth2_configuration(mocker):
    """Test get_oauth2_configuration."""
    from tokendito import okta

    response = Mock()
    response.json.return_value = {
        "authorization_endpoint": "pytest",
        "token_endpoint": "pytest",
        "scopes_supported": "pytest",
        "response_types_supported": "code",
        "grant_types_supported": "authorization_code",
        "request_parameter_supported": "pytest",
    }
    pytest_config = Config(okta={"client_id": "test_client_id", "org": "acme"})
    mocker.patch.object(HTTP_client, "get", return_value=response)
    assert okta.get_oauth2_configuration(pytest_config)["org"] == "acme"


def test_validate_oauth2_configuration():
    """Test validate_oauth2_configuration."""
    from tokendito import okta

    pytest_oauth2_config = {
        "client_id": "123",
        "org": "acme",
        "token_endpoint": "pytesttokenendpoint",
        "grant_types_supported": "authorization_code",
        "scopes_supported": "pytest",
        "response_types_supported": "code",
        "request_parameter_supported": "pytest",
    }

    with pytest.raises(SystemExit) as error:
        assert okta.validate_oauth2_configuration(pytest_oauth2_config) == error

    pytest_oauth2_config = {
        "client_id": "123",
        "org": "acme",
        "token_endpoint": "pytesttokenendpoint",
        "authorization_endpoint": "pytestauthurl",
        "grant_types_supported": "authorization_code",
        "scopes_supported": "pytest",
        "response_types_supported": "code",
        "request_parameter_supported": "pytest",
    }
    assert okta.validate_oauth2_configuration(pytest_oauth2_config) is None


def test_idp_authorize(mocker):
    """Test idp_authorize."""
    from tokendito import okta

    oauth2_config = {"client_id": "test_client_id"}
    oauth2_session_data = {}
    mocker.patch("tokendito.okta.authorization_code_enabled", return_value=True)
    mocker.patch("tokendito.okta.authorize_request", return_value="pytest")
    mocker.patch("tokendito.okta.get_access_token", return_value="token")
    assert okta.idp_authorize(oauth2_config, oauth2_session_data) is None

    oauth2_config = {}
    with pytest.raises(SystemExit) as error:
        assert okta.idp_authorize(oauth2_config, oauth2_session_data) == error


@pytest.mark.parametrize(
    "url, response, expected",
    [
        (
            "https://login.okta.com",
            "pytest",
            None,
        ),
        (
            "https://login.okta.com",
            '<html><head><script src="https://login.okta.com/enduser-v1.0.0.0/enduser.min.js">'
            "</script></head></html>",
            "https://login.okta.com/enduser-v1.0.0.0/enduser.min.js",
        ),
    ],
)
def test_get_enduser_url(mocker, url, response, expected):
    """Test get_enduser_url."""
    from tokendito import okta

    mock_response = Mock()
    mock_response.text = response
    mock_response.status_code = 201
    mocker.patch.object(HTTP_client, "get", return_value=mock_response)
    assert okta.get_enduser_url(url) == expected


@pytest.mark.parametrize(
    "url, response, expected",
    [
        (
            "https://login.okta.com/enduser-v1.0.0.0/enduser.min.js",
            "pytest",
            None,
        ),
        (
            "https://login.okta.com/enduser-v1.0.0.0/enduser.min.js",
            'redirectUri:"".concat(Cn,"/enduser/callback")'
            ',clientId:"okta.00000000-0000-0000-0000-000000000000",scopes:yn,',
            "okta.00000000-0000-0000-0000-000000000000",
        ),
    ],
)
def test_get_client_id_by_url(mocker, url, response, expected):
    """Test get_client_id_by_url."""
    from tokendito import okta

    mock_response = Mock()
    mock_response.text = response
    mock_response.status_code = 201
    mocker.patch("tokendito.okta.get_enduser_url", return_value="acme")
    mocker.patch.object(HTTP_client, "get", return_value=mock_response)
    assert okta.get_client_id_by_url(url) == expected


def test_get_client_id(mocker):
    """Test getting client ID."""
    from tokendito import okta

    pytest_config = Config(okta={"client_id": "test_client_id", "org": "acme"})

    assert okta.get_client_id(pytest_config) == "test_client_id"

    pytest_config = Config(okta={"org": "acme"})
    mocker.patch("tokendito.okta.get_client_id_by_url", return_value=None)
    assert okta.get_client_id(pytest_config) is None

    mocker.patch("tokendito.okta.get_client_id_by_url", return_value="test_client_id")
    assert okta.get_client_id(pytest_config) == "test_client_id"


def test_oie_enabled(mocker):
    """Test oie_enabled."""
    from tokendito import okta

    mocker.patch("tokendito.okta.get_auth_pipeline", return_value="idx")

    assert okta.oie_enabled("pytesturl") is True

    mocker.patch("tokendito.okta.get_auth_pipeline", return_value="foobar")
    assert okta.oie_enabled("pytesturl") is False


def test_get_redirect_uri():
    """Test getting redirect URI."""
    from tokendito import okta

    assert okta.get_redirect_uri("testurl") == "testurl/enduser/callback"


def test_get_response_type():
    """Test getting response code."""
    from tokendito import okta

    assert okta.get_response_type() == "code"


def test_get_authorize_scope():
    """Test getting authorize scope."""
    from tokendito import okta

    assert okta.get_authorize_scope() == "openid"


def test_access_control(mocker):
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
    mocker.patch("tokendito.okta.oie_enabled", return_value=False)
    mocker.patch("tokendito.okta.idp_authenticate", return_value=None)
    mocker.patch("tokendito.okta.idp_authorize", return_value=None)
    assert okta.access_control(pytest_config) is None

    mocker.patch("tokendito.okta.oie_enabled", return_value=True)
    mocker.patch("tokendito.okta.get_oauth2_configuration", return_value=None)
    mocker.patch("tokendito.okta.get_oauth2_session_data", return_value=None)
    mocker.patch("tokendito.okta.create_authz_cookies", return_value=None)
    mocker.patch("tokendito.okta.idp_authenticate", return_value=None)
    mocker.patch("tokendito.okta.idp_authorize", return_value=None)
    assert okta.access_control(pytest_config) is None


def test_idp_authenticate(mocker):
    """Test IDP authenticate."""
    from tokendito import okta
    from tokendito.config import Config

    pytest_config = Config(
        okta={
            "username": "XXXXXX",
            "password": "XXXXXX",
            "org": "XXXXXXXXXXXXXXXXXXXXXX",
        }
    )
    mocker.patch("tokendito.okta.create_authn_cookies", return_value=None)
    mocker.patch("tokendito.okta.local_authenticate", return_value=None)
    mocker.patch("tokendito.okta.oie_enabled", return_value=False)
    mocker.patch("tokendito.okta.saml2_authenticate", return_value=None)
    mocker.patch("tokendito.okta.get_auth_properties", return_value={"type": "OKTA"})

    assert okta.idp_authenticate(pytest_config) is None

    mocker.patch("tokendito.okta.get_auth_properties", return_value={"type": "SAML2"})
    assert okta.idp_authenticate(pytest_config) is None

    mocker.patch("tokendito.okta.get_auth_properties", return_value={"type": "UNKNOWN"})
    with pytest.raises(SystemExit) as error:
        assert okta.idp_authenticate(pytest_config) == error

    mocker.patch("tokendito.okta.get_auth_properties", return_value={})
    with pytest.raises(SystemExit) as error:
        assert okta.idp_authenticate(pytest_config) == error


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


def test_local_authenticate(mocker):
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

    assert okta.local_authenticate(pytest_config) == "pytesttoken"


def test_saml2_authenticate(mocker):
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
    mocker.patch("tokendito.okta.access_control", return_value="pytestsessioncookie")

    saml_response = {
        "response": "pytestresponse",
    }

    mocker.patch("tokendito.okta.send_saml_request", return_value=saml_response)
    mocker.patch("tokendito.okta.send_saml_response", return_value=None)
    mocker.patch("tokendito.okta.idp_authenticate", return_value=None)
    assert okta.saml2_authenticate(pytest_config, auth_properties) is None
