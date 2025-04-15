# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures for DUO module."""
from unittest.mock import Mock

import pytest
from tokendito.http_client import HTTP_client


def test_get_passcode(mocker):
    """Check if numerical passcode can handle leading zero values."""
    from tokendito import duo

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.input", return_value="0123456")
    assert duo.get_passcode({"factor": "passcode"}) == "0123456"
    assert duo.get_passcode({"factor": "PassCode"}) == "0123456"
    assert duo.get_passcode({"factor": "push"}) is None
    assert duo.get_passcode("pytest") is None


def test_prepare_info():
    """Test behaviour empty return duo info."""
    from tokendito.config import config
    from tokendito.duo import prepare_info

    selected_okta_factor = {
        "_embedded": {
            "factor": {
                "_embedded": {
                    "verification": {
                        "_links": {
                            "complete": {"href": "http://test.okta.href"},
                            "script": {"href": "python-v3.11"},
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
        "version": "3.11",
    }
    assert prepare_info(selected_okta_factor) == expected_duo_info

    with pytest.raises(SystemExit) as err:
        prepare_info({"badresponse": "FAIL"})
    assert err.value.code == 1


def test_get_sid(mocker):
    """Check if got sid correct."""
    from tokendito.config import config
    from tokendito.duo import get_sid

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
        "version": "3.11",
    }

    test_url = "http://test.token.dito?sid=testval"
    duo_api_response = Mock()
    duo_api_response.url = test_url

    mocker.patch("tokendito.duo.api_post", return_value=duo_api_response)

    duo_sid_info, duo_auth_response = get_sid(test_duo_info)

    assert duo_sid_info["sid"] == "testval"
    assert duo_auth_response.url == test_url

    mocker.patch("tokendito.duo.api_post", return_value="FAIL")
    with pytest.raises(SystemExit) as err:
        get_sid(test_duo_info)
    assert err.value.code == 2


def test_get_mfa_response():
    """Test if mfa verify correctly."""
    from tokendito.duo import get_mfa_response

    mfa_result = Mock()

    # Test if response is correct
    assert get_mfa_response({"response": "test_value"}) == "test_value"

    # Test if response is incorrect
    mfa_result = Mock(return_value={"badresponse": "FAIL"})
    with pytest.raises(SystemExit) as err:
        get_mfa_response(mfa_result)
    assert err.value.code == 1

    # Test no key available
    with pytest.raises(SystemExit) as err:
        get_mfa_response({"pytest": "FAIL"})
    assert err.value.code == 1

    # Test generic failure
    with pytest.raises(SystemExit) as err:
        get_mfa_response(Mock(return_value="FAIL"))
    assert err.value.code == 1


def test_api_post(mocker):
    """Test if duo api post correctly."""
    from tokendito.duo import api_post

    mock_post = mocker.patch("requests.Session.post")
    mock_resp = mocker.Mock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"status": "pytest"}
    mock_post.return_value = mock_resp

    response = api_post("https://pytest/")
    assert response == {"status": "pytest"}


def test_get_devices(mocker):
    """Test that we can get a list of devices."""
    from tokendito.duo import get_devices

    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.content = "<html></html>"

    # Test generic failure or empty response
    with pytest.raises(SystemExit) as err:
        get_devices(mock_resp)
    assert err.value.code == 2

    # Test no devices in list
    mock_resp.content = """
        <select name='device'>
                <option value='pytest_val'>pytest_text</option>
        </select>
        """
    assert get_devices(mock_resp) == []

    # Test devices in list
    mock_resp.content = """
        <select name='device'>
            <option value='pytest_device'>pytest_device_name</option>
        </select>
        <fieldset data-device-index='pytest_device'>
            <input name='factor' value='factor_type'>
        </fieldset>
        """
    assert get_devices(mock_resp) == [
        {"device": "pytest_device - pytest_device_name", "factor": "factor_type"}
    ]


def test_parse_mfa_challenge():
    """Test parsing the response to the challenge."""
    from tokendito.duo import parse_mfa_challenge

    mfa_challenge = Mock()

    # Test successful challenge
    assert parse_mfa_challenge({"stat": "OK", "response": {"txid": "pytest"}}) == "pytest"

    # Test error
    mfa_challenge.json = Mock(return_value={"stat": "OK", "response": "error"})
    with pytest.raises(SystemExit) as err:
        parse_mfa_challenge(mfa_challenge)
    assert err.value.code == 1

    # Test no key in returned content
    with pytest.raises(SystemExit) as err:
        parse_mfa_challenge({"pyest": "OK", "badresponse": "error"})
    assert err.value.code == 1

    # Test no response in returned content
    mfa_challenge.json = Mock(return_value={"stat": "OK", "badresponse": "error"})
    with pytest.raises(SystemExit) as err:
        parse_mfa_challenge(mfa_challenge)
    assert err.value.code == 1

    # Test failure
    with pytest.raises(SystemExit) as err:
        parse_mfa_challenge({"stat": "fail", "response": {"txid": "pytest_error"}})
    assert err.value.code == 1

    # Test API failure
    mfa_challenge.json = Mock(return_value={"stat": "fail", "response": {"txid": "error"}})
    with pytest.raises(SystemExit) as err:
        parse_mfa_challenge(mfa_challenge)
    assert err.value.code == 1


def test_mfa_challenge(mocker):
    """TODO: Test MFA challenge."""
    from tokendito.duo import mfa_challenge

    with pytest.raises(SystemExit) as err:
        mfa_challenge(None, None, None)
    assert err.value.code == 2

    duo_info = {
        "okta_factor": "okta_factor",
        "factor_id": 1234,
        "state_token": 12345,
        "okta_callback_url": "http://test.okta.href",
        "tx": "pytest_tx",
        "tile_sig": "pytest_tile_sig",
        "parent": "pytest_parent",
        "host": "pytest_host",
        "sid": "pytest_sid",
        "version": "3.11",
    }
    passcode = "pytest_passcode"
    mfa_option = {"factor": "pytest_factor", "device": "pytest_device - pytest_device_name"}

    mocker.patch(
        "tokendito.duo.api_post", return_value={"stat": "OK", "response": {"txid": "pytest_txid"}}
    )

    txid = mfa_challenge(duo_info, mfa_option, passcode)
    assert txid == "pytest_txid"


def test_parse_challenge():
    """Test that we can parse a challenge."""
    from tokendito.duo import parse_challenge

    verify_mfa = {"status": "SUCCESS", "result": "SUCCESS", "reason": "pytest"}
    assert parse_challenge(verify_mfa, None) == ("success", "pytest")

    verify_mfa = {"status": "UNKNOWN", "reason": "UNKNOWN"}
    challenge_result = {"result": "PYTEST"}
    assert parse_challenge(verify_mfa, challenge_result) == (challenge_result, "UNKNOWN")


@pytest.mark.parametrize(
    "return_value,side_effect,expected",
    [
        (("success", "pytest"), None, "pytest"),
        ((None, None), [(None, None), ("success", "pytest")], "pytest"),
        (("failure", "pytest"), None, SystemExit),
    ],
)
def test_mfa_verify(mocker, return_value, side_effect, expected):
    """Test MFA challenge completion.

    side_effect is utilized to return different values on different iterations.
    """
    from tokendito.duo import mfa_verify

    mocker.patch.object(HTTP_client, "post", return_value=None)
    mocker.patch("time.sleep", return_value=None)
    mocker.patch("tokendito.duo.get_mfa_response", return_value="pytest")
    mocker.patch(
        "tokendito.duo.parse_challenge", return_value=return_value, side_effect=side_effect
    )

    duo_info = {"host": "pytest_host", "sid": "pytest_sid"}
    txid = "pytest_txid"

    if expected == SystemExit:
        # Test failure as exit condition
        with pytest.raises(expected) as err:
            mfa_verify(duo_info, txid)
        assert err.value.code == 2
    else:
        # Test success, failure, and iterated calls
        assert mfa_verify(duo_info, txid) == expected


def test_factor_callback(mocker):
    """Test submitting factor to callback API."""
    from tokendito.duo import factor_callback

    duo_info = {"host": "pytest_host", "sid": "pytest_sid", "tile_sig": "pytest_tile_sig"}
    verify_mfa = {"result_url": "/pytest_result_url"}

    # Test successful retrieval of the cookie
    duo_api_response = {
        "stat": "OK",
        "response": {"txid": "pytest_txid", "cookie": "pytest_cookie"},
    }
    mocker.patch("tokendito.duo.api_post", return_value=duo_api_response)
    sig_response = factor_callback(duo_info, verify_mfa)
    assert sig_response == "pytest_cookie:pytest_tile_sig"

    # Test bad data passed in
    duo_api_response = "FAIL"
    mocker.patch("tokendito.duo.api_post", return_value=duo_api_response)
    with pytest.raises(SystemExit) as err:
        factor_callback(duo_info, verify_mfa)
    assert err.value.code == 2

    # Test bad data passed in
    duo_api_response = {"stat": "FAIL", "response": {"cookie": "pytest_cookie"}}
    duo_info = {"host": "pytest", "sid": "pytest"}
    mocker.patch("tokendito.duo.api_post", return_value=duo_api_response)
    with pytest.raises(SystemExit) as err:
        factor_callback(duo_info, verify_mfa)
    assert err.value.code == 2


def test_authenticate(mocker):
    """Test end to end authentication."""
    from tokendito.duo import authenticate

    mocker.patch(
        "tokendito.duo.get_sid",
        return_value=(
            {
                "sid": "pytest",
                "host": "pytest",
                "state_token": "pytest",
                "factor_id": "pytest",
                "okta_callback_url": "pytest",
            },
            "pytest",
        ),
    )
    # We mock a lot of functions here, but we're really just testing that the data can flow,
    # and that it can be parsed correctly to be sent to the API endpoint.
    mocker.patch("tokendito.duo.get_devices", return_value=[{"device": "pytest - device"}])
    mocker.patch("tokendito.user.select_preferred_mfa_index", return_value=0)
    mocker.patch("tokendito.user.input", return_value="0123456")
    mocker.patch("tokendito.duo.mfa_challenge", return_value="txid_pytest")
    mocker.patch("tokendito.duo.mfa_verify", return_value={"result_url": "/pytest_result_url"})
    mocker.patch("tokendito.duo.api_post", return_value=None)
    mocker.patch("tokendito.duo.factor_callback", return_value="pytest_cookie:pytest_tile_sig")
    selected_okta_factor = {
        "_embedded": {
            "factor": {
                "_embedded": {
                    "verification": {
                        "_links": {
                            "complete": {"href": "http://test.okta.href"},
                            "script": {"href": "python-v3.11"},
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

    res = authenticate(selected_okta_factor)
    assert {
        "id": "pytest",
        "sig_response": "pytest_cookie:pytest_tile_sig",
        "stateToken": "pytest",
    } == res
