# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""pytest configuration, hooks, and global fixtures."""


def pytest_addoption(parser):
    """Add command-line options for running functional tests with credentials."""
    parser.addoption("--username", default="", help="username to login to Okta")
    parser.addoption("--password", default="", help="password to login to Okta.")
    parser.addoption("--okta-app-url", default=None, help="Okta App URL to use.")
    parser.addoption("--okta-mfa-method", default=None, help="Sets the MFA method")
    parser.addoption(
        "--okta-mfa-response", default=None, help="Sets the MFA response to a challenge"
    )
    parser.addoption("--aws-role-arn", default=None, help="Sets the IAM role")
    parser.addoption(
        "--config-file",
        default="/dev/null",
        help="Sets an optional config file to read from",
    )
