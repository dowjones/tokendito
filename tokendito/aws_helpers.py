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

import boto3
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError
import requests
from tokendito import helpers


def authenticate_to_roles(secret_session_token, url):
    """Authenticate AWS user with saml.

    :param secret_session_token: secret session token
    :param url: url of the AWS account
    :return: response text

    """
    payload = {"onetimetoken": secret_session_token}
    logging.debug(f"Authenticate AWS user with SAML URL [{url}]")
    try:
        response = requests.get(url, params=payload)
        saml_response_string = response.text
        if response.status_code == 400 or response.status_code == 401:
            errmsg = "Invalid Credentials."
            logging.critical(f"{errmsg}\nExiting with code:{response.status_code}")
            sys.exit(2)
        elif response.status_code == 404:
            errmsg = "Invalid Okta application URL. Please verify your configuration."
            logging.critical(f"{errmsg}")
            sys.exit(2)
        elif response.status_code >= 500 and response.status_code < 504:
            errmsg = "Unable to establish connection with Okta. Verify Okta Org URL and try again."
            logging.critical(f"{errmsg}\nExiting with code:{response.status_code}")
            sys.exit(2)
        elif response.status_code != 200:
            logging.critical(f"Exiting with code:{response.status_code}")
            logging.debug(saml_response_string)
            sys.exit(2)

    except Exception as error:
        errmsg = f"Okta auth failed:\n{error}"
        logging.critical(errmsg)
        sys.exit(1)

    saml_xml = helpers.validate_saml_response(saml_response_string)

    return saml_response_string, saml_xml


def assume_role(role_arn, provider_arn, saml):
    """Return AssumeRoleWithSaml API response.

    :param role_arn: IAM role arn to assume
    :param provider_arn: ARN of saml-provider resource
    :param saml: decoded saml response from okta
    :return: AssumeRoleWithSaml API response

    """
    default_error = (
        "\nUnable to assume role with the following details:\n"
        "- Role ARN: {}\n"
        "- Error: {}\n"
    )

    encoded_xml = codecs.encode(saml.encode("utf-8"), "base64")

    # Attempt to assume a role with the following durations:
    # 12h, 8h, 6h, 4h, 2h, 1h, 30m, 15m
    session_times = [43200, 28800, 21600, 14400, 7200, 3600, 1800, 900, "exit"]

    for duration in session_times:
        if duration == "exit":
            logging.critical(
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
    logging.debug(f"Attempting session time [{duration}]")
    client = boto3.client("sts", config=Config(signature_version=UNSIGNED))
    try:
        assume_role_response = client.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=provider_arn,
            SAMLAssertion=encoded_xml.decode(),
            DurationSeconds=duration,
        )
        # Client Exceptions
    except ClientError as error:
        if error.response["Error"]["Code"] == "ValidationError":
            logging.info(
                f"AssumeRoleWithSaml failed with {error.response['Error']['Code']} "
                f"for duration {duration}"
            )
            assume_role_response = "continue"
        elif error.response["Error"]["Code"] == "AccessDenied":
            errmsg = f"Error assuming intermediate {provider_arn} SAML role"
            logging.critical(errmsg)
            sys.exit(2)
        else:
            logging.critical(default_error.format(role_arn, str(error)))
            sys.exit(1)
        # Service Exceptions
    except Exception as error:
        logging.critical(default_error.format(role_arn, str(error)))
        sys.exit(1)

    return assume_role_response


def ensure_keys_work(assume_role_response):
    """Validate the temporary AWS credentials.

    :param aws_access_key: AWS access key
    :param aws_secret_key: AWS secret key
    :param aws_session_token: AWS session token
    :return:

    """
    logging.debug("Validate the temporary AWS credentials")

    aws_access_key = assume_role_response["Credentials"]["AccessKeyId"]
    aws_secret_key = assume_role_response["Credentials"]["SecretAccessKey"]
    aws_session_token = assume_role_response["Credentials"]["SessionToken"]

    try:
        client = boto3.client(
            "sts",
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            aws_session_token=aws_session_token,
        )
        client.get_caller_identity()
    except Exception as auth_error:
        logging.critical(
            f"There was an error authenticating your keys with AWS: {auth_error}"
        )
        sys.exit(1)


def select_assumeable_role(saml_response_string, saml):
    """Select the role to perform the AssumeRoleWithSaml.

    :param saml_response_string response from Okta with saml data:
    :param saml decoded saml response from Okta:
    :return AWS AssumeRoleWithSaml response, role name:
    """
    roles_and_providers = helpers.extract_arns(saml)
    role_arn = helpers.select_role_arn(
        list(roles_and_providers.keys()), saml, saml_response_string
    )
    role_name = role_arn.split("/")[-1]

    assume_role_response = assume_role(role_arn, roles_and_providers[role_arn], saml)

    return assume_role_response, role_name
