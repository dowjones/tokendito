# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module retrieves AWS credentials after authenticating with Okta."""
import logging

from tokendito import aws
from tokendito import config
from tokendito import okta
from tokendito import user


logger = logging.getLogger(__name__)


def cli(args):
    """Tokendito retrieves AWS credentials after authenticating with Okta."""
    # Set some required initial values
    args = user.setup(args)

    logger.debug("tokendito retrieves AWS credentials after authenticating with Okta.")

    # Collect and organize user specific information
    user.process_options(args)

    # Authenticate okta and AWS also use assumerole to assign the role
    logger.debug("Authenticate user with Okta and AWS.")

    secret_session_token = okta.authenticate_user(
        config.okta["org"], config.okta["username"], config.okta["password"]
    )

    saml_response_string, saml_xml = aws.authenticate_to_roles(
        secret_session_token, config.okta["app_url"]
    )
    assume_role_response, role_name = aws.select_assumeable_role(saml_response_string, saml_xml)

    aws.ensure_keys_work(assume_role_response)

    user.set_local_credentials(
        assume_role_response, role_name, config.aws["region"], config.aws["output"]
    )
