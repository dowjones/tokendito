# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module handles the all aws workflow operations.

Tasks include:
1. Aws Authentication with SAML
2. Updating the AWS Credentials
3. Updating the AWS Config

"""
import codecs
import logging
import sys

from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError
import botocore.session
from tokendito import okta
from tokendito import user

logger = logging.getLogger(__name__)


def get_regions(profile=None):
    """Get avaliable regions from botocore.

    :return: List of available regions.
    """
    regions = []
    try:
        session = botocore.session.get_session(env_vars=profile)
        regions = session.get_available_regions("sts")
        logger.debug(f"Found AWS regions: {regions}")
    except Exception:
        pass
    return regions


def get_output_types():
    """Provide available output types.

    Currently, this cannot be done dynamically.
    :return: List of available output types.
    """
    return ["json", "text", "csv", "yaml", "yaml-stream"]


def authenticate_to_roles(urls, cookies=None):
    """Authenticate AWS user with saml.

    :param urls: list of tuples or tuple, with tiles info
    :param cookies: html cookies
    :return: response text

    """
    url_list = [urls] if isinstance(urls, tuple) else urls
    responses = []
    tile_count = len(url_list)
    plural = ""
    if tile_count > 1:
        plural = "s"

    logger.info(f"Discovering roles in {tile_count} tile{plural}.")
    for url, label in url_list:
        response = user.request_wrapper("GET", url, cookies=cookies)
        saml_response_string = response.text

        saml_xml = okta.extract_saml_response(saml_response_string)
        if not saml_xml:
            if "Extra Verification" in saml_response_string:
                logger.error("Step-Up Authentication required, but not supported.")
            elif "App Access Locked" in saml_response_string:
                logger.error(
                    "Access to this application is not allowed at this time."
                    " Please contact your administrator for details."
                )
            else:
                logger.error("Invalid data detected in SAML response. Aborting.")
            logger.debug(saml_response_string)
            sys.exit(1)
        responses.append((url, saml_response_string, saml_xml, label))

    return responses


def assume_role(role_arn, provider_arn, saml):
    """Return AssumeRoleWithSaml API response.

    :param role_arn: IAM role arn to assume
    :param provider_arn: ARN of saml-provider resource
    :param saml: decoded saml response from okta
    :return: AssumeRoleWithSaml API response

    """
    default_error = "Unable to assume role {}: {}"

    encoded_xml = codecs.encode(saml.encode("utf-8"), "base64")
    assume_role_response = None
    # Attempt to assume a role with the following durations:
    # 12h, 8h, 6h, 4h, 2h, 1h, 30m, 15m
    session_times = [43200, 28800, 21600, 14400, 7200, 3600, 1800, 900, "exit"]
    for duration in session_times:
        if duration == "exit":
            logger.error(
                default_error.format(
                    role_arn,
                    f"IAM role session time is not within set: {session_times[:-1]}",
                )
            )
            sys.exit(2)

        assume_role_response = handle_assume_role(
            role_arn, provider_arn, encoded_xml, duration, default_error
        )
        if "Credentials" in assume_role_response:
            break

    return assume_role_response


def handle_assume_role(role_arn, provider_arn, encoded_xml, duration, default_error):
    """Handle assume role with saml.

    :param role_arn: IAM role arn to assume
    :param provider_arn: ARN of saml-provider resource
    :param saml: decoded saml response from okta
    :return: AssumeRoleWithSaml API responses
    """
    logger.debug(f"Attempting session time [{duration}]")
    try:
        session = botocore.session.get_session()
        client = session.create_client("sts", config=Config(signature_version=UNSIGNED))
        assume_role_response = client.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=provider_arn,
            SAMLAssertion=encoded_xml.decode(),
            DurationSeconds=duration,
        )
        # Client Exceptions
    except ClientError as error:
        if error.response["Error"]["Code"] == "ValidationError":
            logger.debug(
                f"AssumeRoleWithSaml failed with {error.response['Error']['Code']} "
                f"for duration {duration}"
            )
            assume_role_response = "continue"
        elif error.response["Error"]["Code"] == "AccessDenied":
            errmsg = f"Error assuming intermediate {provider_arn} SAML role"
            logger.error(errmsg)
            sys.exit(2)
        else:
            logger.error(default_error.format(role_arn, str(error)))
            sys.exit(1)
        # Service Exceptions
    except Exception as error:
        logger.error(default_error.format(role_arn, str(error)))
        sys.exit(1)

    return assume_role_response


def assert_credentials(role_response={}):
    """Validate the temporary AWS credentials.

    :param assume_role_response: dictionary with response. It should contain the credentials to AWS.
    :return: Dictionary with identity object

    """
    logger.debug("Validate the temporary AWS credentials")

    try:
        aws_access_key = role_response["Credentials"]["AccessKeyId"]
        aws_secret_key = role_response["Credentials"]["SecretAccessKey"]
        aws_session_token = role_response["Credentials"]["SessionToken"]
    except (KeyError, TypeError):
        logger.error("SAML Response did not contain credentials")
        sys.exit(1)

    identity = {}
    try:
        session = botocore.session.get_session()

        client = session.create_client(
            "sts",
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            aws_session_token=aws_session_token,
        )
        identity = client.get_caller_identity()
        logger.debug(f"Logged on with role ARN: {identity['Arn']}")
    except Exception as auth_error:
        logger.error(f"There was an error authenticating your keys with AWS: {auth_error}")
        sys.exit(1)
    return identity


def select_assumeable_role(tiles):
    """Select the role to perform the AssumeRoleWithSaml.

    :param tiles: tiles metadata, list of tuples
    :return: tuple with AWS AssumeRoleWithSaml response and role name
    """
    authenticated_tiles = {}
    for url, saml_response, saml, label in tiles:
        roles_and_providers = user.extract_arns(saml)
        authenticated_tiles[url] = {
            "roles": list(roles_and_providers.keys()),
            "saml": saml,
            "saml_response_string": saml_response,
            "roles_and_providers": roles_and_providers,
            "label": label,
        }

    role_arn, _id = user.select_role_arn(authenticated_tiles)
    role_name = role_arn.split("/")[-1]

    assume_role_response = assume_role(
        role_arn,
        authenticated_tiles[_id]["roles_and_providers"][role_arn],
        authenticated_tiles[_id]["saml"],
    )

    return (assume_role_response, role_name)
