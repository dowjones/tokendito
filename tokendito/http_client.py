# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module handles HTTP client operations."""

import logging
import sys
from urllib.parse import urlparse

import requests
from tokendito import __title__
from tokendito import __version__

logger = logging.getLogger(__name__)


class HTTPClient:
    """Handles HTTP client operations."""

    def __init__(self):
        """Initialize the HTTPClient with a session object."""
        user_agent = f"{__title__}/{__version__}"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def set_cookies(self, cookies):
        """Update session with additional cookies."""
        self.session.cookies.update(cookies)

    def get(self, url, params=None, headers=None):
        """Perform a GET request."""
        response = None
        try:
            logger.debug(f"Sending cookies: {self.session.cookies}")
            logger.debug(f"Sending headers: {self.session.headers}")
            response = self.session.get(url, params=params, headers=headers)
            response.raise_for_status()
            logger.debug(f"Received response from {url}: {response.text}")
            return response
        except requests.RequestException as e:
            logger.error(f"Error during GET request to {url}. Error: {e}")
            if response:
                logger.debug(f"Response Headers: {response.headers}")
                logger.debug(f"Response Content: {response.content}")
            else:
                logger.debug("No response received")
            sys.exit(1)

        except Exception as err:
            logger.error(f"The get request to {url} failed with {err}")
            sys.exit(1)

    def post(self, url, data=None, json=None, headers=None, params=None, return_json=False):
        """Perform a POST request."""
        try:
            response = self.session.post(url, data=data, json=json, params=params, headers=headers)
            response.raise_for_status()
            if return_json is True:
                try:
                    return response.json()
                except Exception as err:
                    logger.error(f"Problem with json response {err}")
                    sys.exit(1)
            else:
                return response
        except requests.RequestException as e:
            logger.error(f"Error during POST request to {url}. Error: {e}")
            sys.exit(1)
        except Exception as err:
            logger.error(f"The post request to {url} failed with {err}")
            sys.exit(1)

    def reset(self):
        """Reset the session object to its initial state."""
        user_agent = f"{__title__}/{__version__}"
        self.session.cookies.clear()
        self.session.headers = requests.utils.default_headers()
        self.session.headers.update({"User-Agent": user_agent})

    def get_device_token(self):
        """Get the device token from the current session cookies.

        :return: Device token or None
        """
        return self.session.cookies.get("DT", None)

    def set_device_token(self, org_url, device_token):
        """Set the device token in the current session cookies.

        :param org_url: The organization URL
        :param device_token: The device token
        :return: None
        """
        if not device_token:
            return

        self.session.cookies.set("DT", device_token, domain=urlparse(org_url).netloc, path="/")


HTTP_client = HTTPClient()
