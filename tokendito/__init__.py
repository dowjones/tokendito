# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""tokendito module initialization."""
import json
import os
from os.path import expanduser
import sys

from platformdirs import user_config_dir

__version__ = "2.1.0"
__title__ = "tokendito"
__description__ = "Get AWS STS tokens from Okta SSO"
__long_description_content_type__ = "text/markdown"
__url__ = "https://github.com/dowjones/tokendito"
__author__ = "tokendito"
__author_email__ = "tokendito@dowjones.com"
__license__ = "Apache 2.0"


class Config(object):
    """Creates configuration variables for the application."""

    _default_encoding = "utf-8"
    if hasattr(sys, "stdin") and getattr(sys, "stdin") is not None:
        if getattr(sys.stdin, "encoding") is not None:
            _default_encoding = sys.stdin.encoding

    # Instantiated objects can get Class defaults with get_defaults()
    _defaults = dict(
        user=dict(
            config_dir=user_config_dir(appname=__title__, appauthor=False),
            config_file=os.path.join(
                user_config_dir(appname=__title__, appauthor=False), f"{__title__}.ini"
            ),
            config_profile="default",
            encoding=_default_encoding,
            loglevel="INFO",
            log_output_file="",
            mask_items=[],
            quiet=False,
        ),
        aws=dict(
            config_file=os.path.join(expanduser("~"), ".aws", "config"),
            shared_credentials_file=os.path.join(expanduser("~"), ".aws", "credentials"),
            output="json",
            profile=None,
            region="us-east-1",
            role_arn=None,
        ),
        okta=dict(
            username="",
            password="",
            mfa=None,
            mfa_response=None,
            tile=None,
            org=None,
        ),
    )

    def __init__(self, **kwargs):
        """Create Config instance.

        :param **kwargs: Keyword arguments. The argument key must be exist in the class,
        and the value must be a dictionary. If no arguments are passed, an object with
        defaults values is created.
        :raises AttributeError: raised if the keyword passed does not exist.
        :raises KeyError: raised if the value passed for a keyword is not a dictionary.
        :raises ValueError:  raised if the configuration value does not exist in the object.
        """
        self.aws = dict()
        self.user = dict()
        self.okta = dict()

        if kwargs:
            # Argument validation
            self._check_constraints(**kwargs)
            # We create an object that contains only the values passed in.
            for key, val in kwargs.items():
                self.__dict__[key].update(val)
        else:
            self.set_defaults()

    def __repr__(self):
        """Provide a reusable representation of the object."""
        return json.dumps(self.__dict__, sort_keys=True, indent=4)

    def __str__(self):
        """Provide a string representation of the object."""
        return f"{json.dumps(self.__dict__, sort_keys=True)}"

    def __eq__(self, other):
        """Test equality with another object, using the JSON representation."""
        return repr(other) == repr(self)

    def update(self, other):
        """Update values from another Config object."""
        self._check_constraints(**other.__dict__)
        for key in other.__dict__.keys():
            self.__dict__[key].update(other.__dict__[key])
        return self

    def _check_constraints(self, **kwargs):
        """Ensure dictionaries that are part of the object are valid.

        :param self: Implicit reference to object.
        :param kwargs: dictionaries to check.
        :return: boolean on success, or raises an error
        :raises AttributeError: raised if the keyword passed does not exist.
        :raises KeyError: raised if the value passed for a keyword is not a dictionary.
        :raises ValueError: raised if the configuration value does not exist in the object.
        """
        for key, val in kwargs.items():
            # Guard against improper initialization.
            if key not in self._defaults:
                raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")
            if type(val) is not dict:
                raise KeyError(f"'{key}' must be a {type(dict())}, not '{type(val)}'")
            for subkey in val.keys():
                if subkey not in self._defaults[key]:
                    raise ValueError(f"'{subkey}' not available for assignment to key '{key}'")
        return True

    def set_defaults(self):
        """Update the object to default settings."""
        for key in self._defaults.keys():
            setattr(self, key, self._defaults[key])

    def get_defaults(self):
        """Retrieve default settings."""
        return getattr(self, "_defaults")


config = Config()
