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
    logger.debug(f"Final configuration is {config}")

    user.process_interactive_input(config)

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

        app_label = ""
        config.okta["app_url"] = (config.okta["app_url"], app_label)
    else:
        session_cookies = user.request_cookies(config.okta["org"], secret_session_token)
        config.okta["app_url"] = user.discover_app_url(config.okta["org"], session_cookies)

    auth_apps = aws.authenticate_to_roles(
        secret_session_token, config.okta["app_url"], cookies=session_cookies
    )

    (role_response, role_name) = aws.select_assumeable_role(auth_apps)

    identity = aws.assert_credentials(role_response=role_response)
    if "Arn" not in identity and "UserId" not in identity:
        logger.error(
            f"There was an error retrieving and verifying AWS credentials: {role_response}"
        )
        sys.exit(1)

    user.set_local_credentials(
        response=role_response,
        role=role_name,
        region=config.aws["region"],
        output=config.aws["output"],
    )

    user.display_selected_role(profile_name=role_name, role_response=role_response)
