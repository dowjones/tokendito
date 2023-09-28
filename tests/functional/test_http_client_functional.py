"""This module contains unit tests for the HTTPClient class."""
# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
import pytest
from requests import RequestException
from tokendito import __title__
from tokendito import __version__
from tokendito.http_client import HTTPClient


@pytest.fixture
def client():
    """Fixture to create and return an HTTPClient instance."""
    client = HTTPClient()
    client.session.headers.update({"User-Agent": f"{__title__}/{__version__}"})
    return client


def test_get_request(client):
    """Test the GET request functionality of HTTPClient."""
    # Make a GET request to the /get endpoint of httpbin which reflects the sent request data
    response = client.get("https://httpbin.org/get")
    json_data = response.json()

    # Assert that the request was successful and the returned User-Agent matches the one we set
    assert response.status_code == 200
    assert json_data["headers"]["User-Agent"] == f"{__title__}/{__version__}"


def test_post_request(client):
    """Test the POST request functionality of HTTPClient."""
    # Make a POST request to the /post endpoint of httpbin with sample data
    response = client.post("https://httpbin.org/post", json={"key": "value"})
    json_data = response.json()

    # Assert that the request was successful and the returned json data matches the data we sent
    assert response.status_code == 200
    assert json_data["json"] == {"key": "value"}


def test_set_cookies(client):
    """Test the ability to set cookies using HTTPClient."""
    # Set a test cookie for the client
    client.set_cookies({"test_cookie": "cookie_value"})

    # Make a request to the /cookies endpoint of httpbin which returns set cookies
    response = client.get("https://httpbin.org/cookies")
    json_data = response.json()

    # Assert that the cookie we set is correctly returned by the server
    assert json_data["cookies"] == {"test_cookie": "cookie_value"}


def test_custom_header(client):
    """Test the ability to send custom headers using HTTPClient."""
    # Make a GET request with a custom header
    response = client.get("https://httpbin.org/get", headers={"X-Test-Header": "TestValue"})
    json_data = response.json()

    # Assert that the custom header was correctly sent
    assert json_data["headers"]["X-Test-Header"] == "TestValue"


def test_bad_get_request(client, mocker):
    """Test GET request failure scenario."""
    mocker.patch("requests.Session.get", side_effect=RequestException("An error occurred"))
    with pytest.raises(SystemExit):
        client.get("https://httpbin.org/get")


def test_bad_post_request(client, mocker):
    """Test POST request failure scenario."""
    mocker.patch("requests.Session.post", side_effect=RequestException("An error occurred"))
    with pytest.raises(SystemExit):
        client.post("https://httpbin.org/post", json={"key": "value"})


def test_reset_session(client):
    """Test the reset method to ensure session is reset."""
    # Set a test cookie for the client
    client.set_cookies({"test_cookie": "cookie_value"})
    # Reset the session
    client.reset()

    # Make a request to the /cookies endpoint of httpbin which returns set cookies
    response = client.get("https://httpbin.org/cookies")
    json_data = response.json()

    # Assert that the cookies have been cleared
    assert json_data["cookies"] == {}
