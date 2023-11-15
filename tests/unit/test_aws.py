# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures for AWS module."""
from unittest.mock import Mock

import pytest


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


def test_assume_role(mocker):
    """Test assuming role."""
    from tokendito import aws
    from tokendito.config import Config

    pytest_config = Config(
        okta={
            "username": "pytest",
            "password": "pytest",
            "org": "https://acme.okta.org/",
        }
    )
    role_arn = "0000000000000000000000000:role/testrole"
    session_name = "pytestsession"
    assumed_role_object = {
        "Credentials": {
            "AccessKeyId": "pytestaccesskey",
            "SecretAccessKey": "pytestsecretkey",
            "SessionToken": "pytestsessiontoken",
        }
    }
    mocker.patch("tokendito.aws.handle_assume_role", return_value=assumed_role_object)
    assert aws.assume_role(pytest_config, role_arn, session_name) == assumed_role_object
    mocker.patch("tokendito.aws.handle_assume_role", return_value={})
    with pytest.raises(SystemExit) as error:
        assert aws.assume_role(pytest_config, role_arn, session_name) == error


def test_select_assumeable_role_no_tiles():
    """Test exiting when there are no assumable roles."""
    from tokendito import aws

    tiles = [
        (
            "https://acme.okta.org/home/amazon_aws/0123456789abcdef0123/456",
            "saml_response",
            "arn:aws:iam::000000000000:saml/name,arn:aws:iam::000000000000:role/name",
            "Tile Label",
        )
    ]
    with pytest.raises(SystemExit) as err:
        aws.select_assumeable_role(tiles)
    assert err.value.code == 1


@pytest.mark.parametrize("status_code", [(400), (401), (404), (500), (503)])
def test_authenticate_to_roles(status_code, monkeypatch):
    """Test if function return correct response."""
    from tokendito.aws import authenticate_to_roles
    from tokendito.config import Config
    import tokendito.http_client as http_client

    # Create a mock response object
    mock_response = Mock()
    mock_response.status_code = status_code
    mock_response.text = "response"

    # Use monkeypatch to replace the HTTP_client.get method with the mock
    monkeypatch.setattr(http_client.HTTP_client, "get", lambda *args, **kwargs: mock_response)

    pytest_config = Config(
        okta={
            "org": "https://acme.okta.org/",
        }
    )

    with pytest.raises(SystemExit):
        authenticate_to_roles(pytest_config, [("http://test.url.com", "")])
