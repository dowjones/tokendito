# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module retrieves AWS credentials after authenticating with Okta."""
from __future__ import absolute_import, division, print_function, unicode_literals

import logging

from future import standard_library
from tokendito import aws_helpers
from tokendito import helpers
from tokendito import okta_helpers
from tokendito import settings

standard_library.install_aliases()


def cli(args):
    """Tokendito retrieves AWS credentials after authenticating with Okta."""
    # Set some required initial values
    args = helpers.setup(args)

    logging.debug("tokendito retrieves AWS credentials after authenticating with Okta.")

    # Collect and organize user specific information
    helpers.process_options(args)

    # Authenticate okta and AWS also use assumerole to assign the role
    logging.debug("Authenticate user with Okta and AWS.")

    secret_session_token = okta_helpers.authenticate_user(
        settings.okta_org, settings.okta_username, settings.okta_password
    )

    saml_response_string, saml_xml = aws_helpers.authenticate_to_roles(
        secret_session_token, settings.okta_aws_app_url
    )

    assume_role_response, role_name = aws_helpers.select_assumeable_role(
        saml_response_string, saml_xml
    )

    aws_helpers.ensure_keys_work(assume_role_response)

    helpers.set_local_credentials(
        assume_role_response, role_name, settings.aws_region, settings.aws_output
    )
