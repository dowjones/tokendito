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
    args = user.parse_cli_args(args)

    # Early logging, in case the user requests debugging via env/CLI
    user.setup_early_logging(args)

    # Set some required initial values
    user.process_options(args)

    # Late logging (default)
    user.setup_logging(config.user)

    # Validate configuration
    message = user.validate_configuration(config)
    if message:
        quiet_msg = ""
        if config.user["quiet"] is not False:
            quiet_msg = " to run in quiet mode"
        logger.error(
            f"Could not validate configuration{quiet_msg}: {'. '.join(message)}. "
            "Please check your settings, and try again."
        )
        sys.exit(1)

    # Authenticate to okta
    session_cookies = okta.authenticate(config)

    if config.okta["tile"]:
        tile_label = ""
        config.okta["tile"] = (config.okta["tile"], tile_label)
    else:
        config.okta["tile"] = user.discover_tiles(config.okta["org"], session_cookies)

    # Authenticate to AWS roles
    auth_tiles = aws.authenticate_to_roles(config.okta["tile"], cookies=session_cookies)

    (role_response, role_name) = aws.select_assumeable_role(auth_tiles)

    identity = aws.assert_credentials(role_response=role_response)
    if "Arn" not in identity and "UserId" not in identity:
        logger.error(
            f"There was an error retrieving and verifying AWS credentials: {role_response}"
        )
        sys.exit(1)

    user.set_profile_name(config, role_name)

    user.set_local_credentials(
        response=role_response,
        role=config.aws["profile"],
        region=config.aws["region"],
        output=config.aws["output"],
    )

    user.display_selected_role(profile_name=config.aws["profile"], role_response=role_response)
