# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""pytest configuration, hooks, and global fixtures."""
import pytest


def pytest_addoption(parser):
    """Add command-line options for running functional tests with credentials."""
    parser.addoption("--username", default="", help="username to log in to Okta")
    parser.addoption("--password", default="", help="password to log in to Okta.")
    parser.addoption("--okta-tile", default=None, help="Okta tile URL to use.")
    parser.addoption("--okta-mfa", default=None, help="Sets the MFA method")
    parser.addoption(
        "--okta-mfa-response", default=None, help="Sets the MFA response to a challenge"
    )
    parser.addoption("--aws-role-arn", default=None, help="Sets the IAM role")
    parser.addoption(
        "--tool-config-file",
        default="/dev/null",
        help="Sets an optional config file to read from",
    )
    parser.addoption("--aws-profile", default="pytest", help="Sets the AWS profile name")


@pytest.fixture
def custom_args(request):
    """Search the custom command-line options and return a list of keys and values."""
    options = [
        "--username",
        "--password",
        "--okta-tile",
        "--okta-mfa",
        "--okta-mfa-response",
        "--aws-role-arn",
        "--config-file",
        "--aws-profile",
    ]
    arg_list = []
    # pytest does not have a method for listing options, so we have look them up.
    for item in options:
        if request.config.getoption(item):
            arg_list.extend([item, request.config.getoption(item)])
    return arg_list


@pytest.fixture(scope="session")
def config_file(tmp_path_factory):
    """Generate a path for a temporary ini file that multiple tests can share."""
    path = tmp_path_factory.mktemp("pytest") / "pytest.ini"
    return path


@pytest.fixture
def sample_json_response():
    """Return a response from okta server."""
    from okta_response_simulation import empty_dict
    from okta_response_simulation import error_dict
    from okta_response_simulation import no_auth_methods
    from okta_response_simulation import no_mfa
    from okta_response_simulation import no_mfa_no_session_token
    from okta_response_simulation import with_mfa

    okta_fixture_data = {
        "okta_response_no_auth_methods": no_auth_methods,
        "okta_response_empty": empty_dict,
        "okta_response_error": error_dict,
        "okta_response_no_mfa": no_mfa,
        "okta_response_no_mfa_no_session_token": no_mfa_no_session_token,
        "okta_response_mfa": with_mfa,
    }
    return okta_fixture_data
