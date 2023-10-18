# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures for DUO module."""
from unittest.mock import Mock


def test_set_passcode(mocker):
    """Check if numerical passcode can handle leading zero values."""
    from tokendito import duo

    mocker.patch("tokendito.user.tty_assertion", return_value=True)
    mocker.patch("tokendito.user.input", return_value="0123456")
    assert duo.set_passcode({"factor": "passcode"}) == "0123456"


def test_prepare_duo_info():
    """Test behaviour empty return duo info."""
    from tokendito.config import config
    from tokendito.duo import prepare_duo_info

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
    from tokendito.config import config
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


def test_get_mfa_response():
    """Test if mfa verify correctly."""
    from tokendito.duo import get_mfa_response

    mfa_result = Mock()
    mfa_result.json = Mock(return_value={"response": "test_response"})

    assert get_mfa_response(mfa_result) == "test_response"
