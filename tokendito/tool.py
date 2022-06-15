# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module retrieves AWS credentials after authenticating with Okta."""
import logging
import sys

from tokendito import aws
from tokendito import config
from tokendito import okta
from tokendito import user


logger = logging.getLogger(__name__)


def cli(args):
    """Tokendito retrieves AWS credentials after authenticating with Okta."""
    # Set some required initial values
    user.process_options(args)
    user.setup_logging(config.user)
    logger.debug(f"Final configuration is {config}")

    user.process_okta_org_url(config)

    logger.debug("Set Okta credentials.")
    user.set_okta_username()
    user.set_okta_password()

    # Authenticate okta and AWS also use assumerole to assign the role
    logger.debug("Authenticate user with Okta and AWS.")

    secret_session_token = okta.authenticate_user(
        config.okta["org"], config.okta["username"], config.okta["password"]
    )

    session_cookies = None

    if config.okta["app_url"]:
        if not user.validate_okta_app_url(config.okta["app_url"]):
            logger.error(
                "Okta Application URL not found, or invalid. Please check "
                "your configuration and try again."
            )
            sys.exit(2)
    else:
        session_cookies = user.request_cookies(config.okta["org"], secret_session_token)
        config.okta["app_url"] = user.discover_app_url(config.okta["org"], session_cookies)

    saml_response_string, saml_xml = aws.authenticate_to_roles(
        secret_session_token, config.okta["app_url"], cookies=session_cookies
    )

    assume_role_response, role_name = aws.select_assumeable_role(saml_response_string, saml_xml)

    aws.ensure_keys_work(assume_role_response)

    user.set_local_credentials(
        assume_role_response, role_name, config.aws["region"], config.aws["output"]
    )
