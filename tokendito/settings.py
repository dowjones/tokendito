# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module is responsible for initialisation of global variables."""
from __future__ import absolute_import, division, print_function, unicode_literals

from os.path import expanduser
import sys

from future import standard_library

standard_library.install_aliases()


config_dir = expanduser("~") + "/.aws"
config_file = config_dir + "/okta_auth"
aws_config_file = config_dir + "/config"
aws_shared_credentials_file = config_dir + "/credentials"
aws_output = "json"
aws_profile = None
aws_region = "us-east-1"
encoding = sys.stdin.encoding
mfa_method = None
mfa_response = None
okta_aws_app_url = None
okta_status_dict = {
    "E0000004": "Authentication failed",
    "E0000047": "API call exceeded rate limit due to too many requests",
    "PASSWORD_EXPIRED": "Your password is expired",
    "LOCKED_OUT": "Your account is locked out",
}
okta_org = None
okta_password = ""
okta_profile = "default"
okta_username = ""
role_arn = None
