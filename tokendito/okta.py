# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""
This module handles the all Okta operations.

1. Okta authentication
2. Update Okta Config File

"""
import json
import logging
import sys
import time


import requests
from tokendito import config
from tokendito import duo
from tokendito import user


logger = logging.getLogger(__name__)

_status_dict = dict(
    E0000004="Authentication failed",
    E0000047="API call exceeded rate limit due to too many requests",
    PASSWORD_EXPIRED="Your password has expired",
    LOCKED_OUT="Your account is locked out",
)


def okta_verify_api_method(url, payload, headers=None):
    """Okta MFA authentication.

    :param mfa_challenge_url: MFA challenge url
    :param payload: JSON Payload
    :param headers: Headers of the request
    :return: Dictionary with authentication response
    """
    try:
        if headers:
            response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
        else:
            response = requests.request("POST", url, data=payload)
    except Exception as request_error:
        logger.error(f"There was an error connecting to {url}: {request_error}")
        sys.exit(1)

    logger.debug(f"Authentication response is {response}")
    ret = dict()
    try:
        ret = response.json()
    except ValueError:
        logger.error(f"Received invalid type of response {type(response.text)} from {url}")
        sys.exit(1)

    if "errorCode" in ret:
        login_error_code_parser(ret["errorCode"])
        sys.exit(1)

    return ret


def login_error_code_parser(status=None):
    """Status code parsing.

    param status: Response status
    return message: status message
    """
    if status in _status_dict.keys():
        message = f"Okta auth failed: {_status_dict[status]}"
    else:
        message = f"Okta auth failed: {status}. Please verify your settings and try again."
    logger.error(message)
    logger.debug(f"Parsing error [{message}] ")
    return message


def user_session_token(primary_auth, headers):
    """Get session_token.

    param headers: Headers of the request
    param primary_auth: Primary authentication
    return session_token: Session Token from JSON response
    """
    status = None
    if primary_auth.get("errorCode"):
        status = primary_auth.get("errorCode")
    else:
        status = primary_auth.get("status")

    if status == "SUCCESS":
        session_token = primary_auth.get("sessionToken")
    elif status == "MFA_REQUIRED":
        session_token = user_mfa_challenge(headers, primary_auth)
    elif status is None:
        logger.debug(f"Error parsing response: {json.dumps(primary_auth)}")
        logger.error("Okta auth failed: unknown status")
        sys.exit(1)
    else:
        login_error_code_parser(status)
        sys.exit(1)
    return session_token


def authenticate_user(url, username, password):
    """Authenticate user with okta credential.

    :param url: company specific URL of the okta
    :param username: okta username
    :param password: okta password
    :return: MFA session options
    """
    headers = {"content-type": "application/json", "accept": "application/json"}
    payload = {"username": username, "password": password}

    primary_auth = okta_verify_api_method(f"{url}/api/v1/authn", payload, headers)
    logger.debug(f"Authenticate Okta header [{headers}] ")

    session_token = user_session_token(primary_auth, headers)
    logger.info("User has been succesfully authenticated.")
    return session_token


def mfa_provider_type(
    mfa_provider,
    selected_factor,
    mfa_challenge_url,
    primary_auth,
    selected_mfa_option,
    headers,
    payload,
):
    """Receive session key.

    :param mfa_provider: MFA provider
    :param selected_factor: Selected MFA factor
    :param mfa_challenge_url: MFA challenge url
    :param primary_auth: Primary authentication
    :param selected_mfa_option: Selected MFA option
    :return: session_key

    """
    mfa_verify = dict()
    if mfa_provider == "duo":
        payload, headers, callback_url = duo.authenticate_duo(selected_factor)
        okta_verify_api_method(callback_url, payload)
        payload.pop("id", "sig_response")
        mfa_verify = okta_verify_api_method(mfa_challenge_url, payload, headers)
    elif mfa_provider == "okta" or mfa_provider == "google":
        mfa_verify = user_mfa_options(
            selected_mfa_option, headers, mfa_challenge_url, payload, primary_auth
        )
    else:
        logger.error(
            f"Sorry, the MFA provider '{mfa_provider}' is not yet supported."
            " Please retry with another option."
        )
        exit(1)
    return mfa_verify["sessionToken"]


def user_mfa_index(preset_mfa, available_mfas, mfa_options):
    """Get mfa method index in request.

    :param preset_mfa: preset mfa method from settings
    :param available_mfas: available mfa method ids
    :param mfa_options: available mfa methods
    """
    logger.debug("Get mfa method index in request.")
    if preset_mfa is not None and preset_mfa in available_mfas:
        mfa_index = available_mfas.index(preset_mfa)
    else:
        mfa_index = user.select_preferred_mfa_index(mfa_options)

    return mfa_index


def user_mfa_challenge(headers, primary_auth):
    """Handle user mfa challenges.

    :param headers: headers what needs to be sent to api
    :param primary_auth: primary authentication
    :return: Okta MFA Session token after the successful entry of the code
    """
    logger.debug("Handle user MFA challenges")
    try:
        mfa_options = primary_auth["_embedded"]["factors"]
    except KeyError as error:
        logger.error(f"There was a wrong response structure: \n{error}")
        sys.exit(1)

    preset_mfa = config.okta["mfa_method"]

    available_mfas = [d["factorType"] for d in mfa_options]

    if available_mfas.count(preset_mfa) > 1:
        mfa_method = config.okta["mfa_method"]
        mfa_index = available_mfas.index(preset_mfa)
        provider = mfa_options[mfa_index]["provider"]
        mfa_id = mfa_options[mfa_index]["id"]

        logger.warning(
            f"\n\nMore than one method found with {mfa_method}.\n"
            f"Defaulting to {provider} - {mfa_method} - Id: {mfa_id}.\n"
            "This functionality will be deprecated in"
            "the next major release.\n"
        )

    mfa_index = user_mfa_index(preset_mfa, available_mfas, mfa_options)

    # time to challenge the mfa option
    selected_mfa_option = mfa_options[mfa_index]
    logger.debug(f"Selected MFA is [{selected_mfa_option}]")

    mfa_challenge_url = selected_mfa_option["_links"]["verify"]["href"]

    payload = {
        "stateToken": primary_auth["stateToken"],
        "factorType": selected_mfa_option["factorType"],
        "provider": selected_mfa_option["provider"],
        "profile": selected_mfa_option["profile"],
    }
    selected_factor = okta_verify_api_method(mfa_challenge_url, payload, headers)

    mfa_provider = selected_factor["_embedded"]["factor"]["provider"].lower()
    logger.debug(f"MFA Challenge URL: [{mfa_challenge_url}] headers: {headers}")
    mfa_session_token = mfa_provider_type(
        mfa_provider,
        selected_factor,
        mfa_challenge_url,
        primary_auth,
        selected_mfa_option,
        headers,
        payload,
    )

    return mfa_session_token


def user_mfa_options(selected_mfa_option, headers, mfa_challenge_url, payload, primary_auth):
    """Handle user mfa options.

    :param selected_mfa_option: Selected MFA option (SMS, push, etc)
    :param headers: headers
    :param mfa_challenge_url: MFA challenge URL
    :param payload: payload
    :param primary_auth: Primary authentication method
    :return: payload data

    """
    logger.debug("Handle user MFA options")

    logger.debug(f"User MFA options selected: [{selected_mfa_option['factorType']}]")
    if selected_mfa_option["factorType"] == "push":
        return push_approval(headers, mfa_challenge_url, payload)

    if config.okta["mfa_response"] is None:
        logger.debug("Getting verification code from user.")
        print("Type verification code and press Enter")
        config.okta["mfa_response"] = user.get_input()

    # time to verify the mfa method
    payload = {"stateToken": primary_auth["stateToken"], "passCode": config.okta["mfa_response"]}
    mfa_verify = okta_verify_api_method(mfa_challenge_url, payload, headers)
    logger.debug(f"mfa_verify [{json.dumps(mfa_verify)}]")

    return mfa_verify


def push_approval(headers, mfa_challenge_url, payload):
    """Handle push approval from the user.

    :param headers: HTTP headers sent to API call
    :param mfa_challenge_url: MFA challenge url
    :param payload: payload which needs to be sent
    :return: Session Token if succeeded or terminates if user wait goes 5 min

    """
    logger.debug(f"Handle push approval from the user [{headers}] [{mfa_challenge_url}]")

    print("Waiting for an approval from device...")
    mfa_status = "WAITING"
    mfa_verify = None
    while mfa_status == "WAITING":
        mfa_verify = okta_verify_api_method(mfa_challenge_url, payload, headers)

        logger.debug(f"MFA Response:\n{json.dumps(mfa_verify)}")

        if "factorResult" in mfa_verify:
            mfa_status = mfa_verify["factorResult"]
        elif mfa_verify["status"] == "SUCCESS":
            break
        else:
            logger.error("There was an error getting your MFA status.")
            logger.debug(mfa_verify)
            if "status" in mfa_verify:
                logger.error(f"Exiting due to error: {mfa_verify['status']}")
            sys.exit(1)

        if mfa_status == "REJECTED":
            logger.error("The Okta Verify push has been denied. Please retry later.")
            sys.exit(2)
        elif mfa_status == "TIMEOUT":
            logger.error("Device approval window has expired.")
            sys.exit(2)

        time.sleep(2)

    return mfa_verify
