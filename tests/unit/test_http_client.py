"""Unit tests for the HTTPClient class."""
# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
import pytest
import requests
from tokendito import __title__
from tokendito import __version__
from tokendito.http_client import HTTPClient

# Unit test class for the HTTPClient.


@pytest.fixture
def client():
    """Fixture for setting up an HTTPClient instance."""
    # Initializing HTTPClient instance without the 'user_agent' parameter
    return HTTPClient()


def test_init(client):
    """Test initialization of HTTPClient instance."""
    # Check if the session property of the client is an instance of requests.Session
    assert isinstance(client.session, requests.Session)

    # Check if the User-Agent header was set correctly during initialization
    expected_user_agent = f"{__title__}/{__version__}"
    assert client.session.headers["User-Agent"] == expected_user_agent


def test_set_cookies(client):
    """Test setting cookies in the session."""
    cookies = {"test_cookie": "cookie_value"}
    client.set_cookies(cookies)
    # Check if the provided cookie is set correctly in the session
    assert client.session.cookies.get_dict() == cookies


def test_get(client, mocker):
    """Test GET request method."""
    mock_get = mocker.patch("requests.Session.get")
    mock_resp = mocker.Mock()
    mock_resp.status_code = 200
    mock_resp.text = "OK"
    mock_get.return_value = mock_resp

    response = client.get("http://test.com")
    # Check if the response status code and text match the expected values
    assert response.status_code == 200
    assert response.text == "OK"


def test_post(client, mocker):
    """Test POST request method."""
    mock_post = mocker.patch("requests.Session.post")
    mock_resp = mocker.Mock()
    mock_resp.status_code = 201
    mock_resp.text = "Created"
    mock_post.return_value = mock_resp

    response = client.post("http://test.com", json={"key": "value"})
    # Check if the response status code and text match the expected values
    assert response.status_code == 201
    assert response.text == "Created"


def test_get_failure(client, mocker):
    """Test GET request failure scenario."""
    mock_get = mocker.patch("requests.Session.get")
    mock_get.side_effect = requests.RequestException("Failed to connect")

    with pytest.raises(SystemExit):
        client.get("http://test.com")


def test_post_failure(client, mocker):
    """Test POST request failure scenario."""
    mock_post = mocker.patch("requests.Session.post")
    mock_post.side_effect = requests.RequestException("Failed to connect")

    with pytest.raises(SystemExit):
        client.post("http://test.com", json={"key": "value"})


def test_post_with_return_json(client, mocker):
    """Test POST request with return_json=True."""
    mock_post = mocker.patch("requests.Session.post")
    mock_resp = mocker.Mock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"status": "Created"}
    mock_post.return_value = mock_resp

    response = client.post("http://test.com", json={"key": "value"}, return_json=True)
    assert response == {"status": "Created"}


def test_reset(client):
    """Test the reset method."""
    # Updating the session headers to check if they are reset later
    client.session.headers.update({"Test-Header": "Test-Value"})

    client.reset()

    expected_user_agent = f"{__title__}/{__version__}"
    assert "Test-Header" not in client.session.headers
    assert client.session.headers["User-Agent"] == expected_user_agent


def test_get_generic_exception(client, mocker):
    """Test GET request with generic exception."""
    mock_get = mocker.patch("requests.Session.get")
    mock_get.side_effect = Exception("Some Exception")

    with pytest.raises(SystemExit):
        client.get("http://test.com")


def test_post_generic_exception(client, mocker):
    """Test POST request with generic exception."""
    mock_post = mocker.patch("requests.Session.post")
    mock_post.side_effect = Exception("Some Exception")

    with pytest.raises(SystemExit):
        client.post("http://test.com", json={"key": "value"})


def test_post_json_exception(client, mocker):
    """Test POST request when json() method raises an exception."""
    mock_post = mocker.patch("requests.Session.post")
    mock_resp = mocker.Mock()
    mock_resp.status_code = 201
    mock_resp.json.side_effect = Exception("JSON Exception")
    mock_post.return_value = mock_resp

    with pytest.raises(SystemExit):
        client.post("http://test.com", json={"key": "value"}, return_json=True)


def test_get_logging_on_exception(client, mocker):
    """Test if logging occurs during exception in GET request."""
    mock_get = mocker.patch("requests.Session.get")
    mock_get.side_effect = requests.RequestException("Failed to connect")
    mock_logger = mocker.patch("logging.Logger.error")

    with pytest.raises(SystemExit):
        client.get("http://test.com")
    mock_logger.assert_called()


def test_post_logging_on_exception(client, mocker):
    """Test if logging occurs during exception in POST request."""
    mock_post = mocker.patch("requests.Session.post")
    mock_post.side_effect = requests.RequestException("Failed to connect")
    mock_logger = mocker.patch("logging.Logger.error")

    with pytest.raises(SystemExit):
        client.post("http://test.com", json={"key": "value"})
    mock_logger.assert_called()


def test_get_device_token(client):
    """Test getting device token from the session."""
    device_token = "test-device-token"
    cookies = {"DT": device_token}
    client.set_cookies(cookies)

    # Check if the device token is set correctly in the session
    assert client.get_device_token() == device_token


def test_set_device_token(client):
    """Test setting device token in the session."""
    device_token = "test-device-token"
    client.set_device_token("http://test.com", device_token)

    # Check if the device token is set correctly in the session
    assert client.session.cookies.get("DT") == device_token
