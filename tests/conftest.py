# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""pytest configuration, hooks, and global fixtures."""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from future import standard_library

standard_library.install_aliases()


def pytest_addoption(parser):
    """Add command-line option for running functional tests."""
    parser.addoption("--run-functional", action="store_true",
                     default=False, help="run functional tests")
    parser.addoption('--username',
                     help='username to login to Okta')
    parser.addoption('--password',
                     help='password to login to Okta.')
    parser.addoption('--okta-aws-app-url',
                     help='Okta App URL to use.')
    parser.addoption('--mfa-method',
                     help='Sets the MFA method')
    parser.addoption('--mfa-response',
                     help='Sets the MFA response to a challenge')
    parser.addoption('--role-arn',
                     help='Sets the IAM role')
    parser.addoption('--config-file',
                     default='/dev/null',
                     help='Sets an optional config file to read from')
