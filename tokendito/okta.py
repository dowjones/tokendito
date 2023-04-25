# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""
This module handles the all Okta operations.

1. Okta authentication
2. Update Okta Config File

"""
import codecs
import json
import logging
import re
import sys
import time

import bs4
from bs4 import BeautifulSoup
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


def api_wrapper(url, payload, headers=None):
    """Okta MFA authentication.

    :param url: url to call
    :param payload: JSON Payload
    :param headers: Headers of the request
    :return: Dictionary with authentication response
    """
    logger.debug(f"url is {url}")
    try:
        response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
    except Exception as err:
        logger.error(f"There was an error with the call to {url}: {err}")
        sys.exit(1)

    logger.debug(f"Response is {response}")

    try:
        ret = response.json()
    except ValueError as e:
        logger.error(
            f"{type(e).__name__} - Failed to parse response\n"
            f"URL: {url}\n"
            f"Status: {response.status_code}\n"
            f"Content: {response.content}\n"
        )
        sys.exit(1)

    if "errorCode" in ret:
        api_error_code_parser(ret["errorCode"])
        sys.exit(1)

    return ret


def api_error_code_parser(status=None):
    """Status code parsing.

    param status: Response status
    return message: status message
    """
    if status and status in _status_dict.keys():
        message = f"Okta auth failed: {_status_dict[status]}"
    else:
        message = f"Okta auth failed: {status}. Please verify your settings and try again."
    logger.error(message)
    logger.debug(f"Parsing error [{message}] ")
    return message


def get_auth_properties(config):
    """Make a call to the webfinger endpoint.

    Determine whether or not we can authenticate a user locally.
    """
    logger.debug("Call out to Webfinger")
    url = f"{config.okta['org']}/.well-known/webfinger"
    headers = {"accept": "application/jrd+json"}
    payload = {
        "resource": f"okta:acct:{config.okta['username']}",
    }

    try:
        logger.debug(f"Calling {url} with {payload} and {headers}")
        response = requests.get(url, params=payload, headers=headers)
        response.raise_for_status()
    except Exception as err:
        logger.error(f"There was an error with the call to {url}: {err}")
        sys.exit(1)

    auth_properties = dict()
    try:
        ret = response.json()
        auth_properties = ret["links"][0]["properties"]
    except (KeyError, ValueError) as e:
        logger.error(f"Failed to parse authentication type in {url}:{str(e)}")
        logger.debug(f"Response: {response.text}")
        sys.exit(1)

    return auth_properties


def get_saml_request(auth_properties):
    url = f"{config.okta['org']}/sso/idps/{auth_properties['okta:idp:id']}"
    saml_request = None
    try:
        logger.debug(f"Calling {url}")
        response = requests.get(url)
        response.raise_for_status()
    except Exception as err:
        logger.error(f"There was an error with the call to {url}: {err}")
        sys.exit(1)

    saml_request = {
        "post_url": extract_form_post_url(response.text),
        "relay_state": extract_saml_relaystate(response.text),
        "request": extract_saml_request(response.text, raw=True),
    }
    return saml_request


def get_saml_response(saml_request, cookies):
    payload = {
        "loginHint": config.okta["username"],
        "relayState": saml_request["relay_state"],
        "SAMLRequest": saml_request["request"],
    }
    headers = {"accept": "text/html,application/xhtml+xml,application/xml"}
    url = saml_request["post_url"]
    saml_response = dict()
    try:
        logger.debug(f"Calling {url} with {cookies}, {payload}, and {headers}")
        response = requests.post(url=url, data=payload, headers=headers, cookies=cookies)
        response.raise_for_status()
    except Exception as err:
        logger.error(f"There was an error with the call to {url}: {err}")
        sys.exit(1)

    saml_response = {
        "response": extract_saml_response(response.text, raw=True),
        "relay_state": extract_saml_relaystate(response.text),
        "post_url": extract_form_post_url(response.text),
    }
    return saml_response


def send_saml_response(saml_response):
    url = saml_response["post_url"]
    headers = {"accept": "text/html,application/xhtml+xml,application/xml"}
    payload = {
        "SAMLResponse": saml_response["response"],
        "RelayState": saml_response["relay_state"],
    }

    try:
        logger.debug(f"Calling {url} with {payload} and {headers}")
        response = requests.post(
            url=url,
            data=payload,
            headers=headers,
        )
        response.raise_for_status()
    except Exception as err:
        logger.error(f"There was an error with the call to {url}: {err}")
        sys.exit(1)

    logger.debug(f"Have session: {response.cookies['sid']}")
    session_cookies = response.cookies
    return session_cookies


def get_session_token(primary_auth, headers):
    """Get session_token.

    param headers: Headers of the request
    param primary_auth: Primary authentication
    return session_token: Session Token from JSON response
    """
    status = primary_auth.get("status", None)

    if status == "SUCCESS" and "sessionToken" in primary_auth:
        session_token = primary_auth.get("sessionToken")
    elif status == "MFA_REQUIRED":
        session_token = mfa_challenge(headers, primary_auth)
    else:
        logger.debug(f"Error parsing response: {json.dumps(primary_auth)}")
        logger.error("Okta auth failed: unknown status.")
        sys.exit(1)

    user.add_sensitive_value_to_be_masked(session_token)

    return session_token


def authenticate(config):
    """Authenticate user.

    :param config: Config object
    :return: session token, or sid cookie.
    """
    auth_properties = get_auth_properties(config)
    token = None
    sid = None

    if auth_properties["okta:idp:type"] == "OKTA":
        token = local_auth(config)
    elif auth_properties["okta:idp:type"] == "SAML2":
        saml_request = get_saml_request(auth_properties)
        url = user.get_base_url(saml_request["post_url"])
        config.okta["org"] = url
        session_token = local_auth(config)
        session_cookies = user.request_cookies(url=url, session_token=session_token)
        saml_response = get_saml_response(saml_request, session_cookies)
        sid = send_saml_response(saml_response)
        url = user.get_base_url(saml_response["post_url"])
        config.okta["org"] = url
    else:
        logger.error(
            f"{auth_properties['okta:idp:type']} login via IdP Discovery is not curretly supported"
        )
        sys.exit(1)
    return (token, sid)


def local_auth(config):
    """Authenticate local user with okta credential.

    :param config: Config object
    :return: MFA session with options
    """
    session_token = None
    headers = {"content-type": "application/json", "accept": "application/json"}
    payload = {"username": config.okta["username"], "password": config.okta["password"]}

    logger.debug("Authenticate user to Okta")
    logger.debug(f"Sending {headers}, {payload} to {config.okta['org']}")
    primary_auth = api_wrapper(f"{config.okta['org']}/api/v1/authn", payload, headers)

    while session_token is None:
        session_token = get_session_token(primary_auth, headers)
    logger.info("User has been succesfully authenticated.")
    return session_token


def extract_saml_response(html, raw=False):
    """Parse html, and extract a SAML document.

    :param html: String with HTML document.
    :param raw: Boolean that determines whether or not the response should be decoded.
    :return: XML Document, or None
    """
    soup = BeautifulSoup(html, "html.parser")
    xml = None
    saml_base64 = None
    retval = None

    elem = soup.find("input", attrs={"name": "SAMLResponse"})
    if type(elem) is bs4.element.Tag:
        saml_base64 = str(elem.get("value"))
        xml = codecs.decode(saml_base64.encode("ascii"), "base64").decode("utf-8")

        retval = xml
        if raw:
            retval = saml_base64
    return retval


def extract_saml_request(html, raw=False):
    """Parse html, and extract a SAML document.

    :param html: String with HTML document.
    :param raw: Boolean that determines whether or not the response should be decoded.
    :return: XML Document, or None
    """
    soup = BeautifulSoup(html, "html.parser")
    xml = None
    saml_base64 = None
    retval = None

    elem = soup.find("input", attrs={"name": "SAMLRequest"})
    if type(elem) is bs4.element.Tag:
        saml_base64 = str(elem.get("value"))
        xml = codecs.decode(saml_base64.encode("ascii"), "base64").decode("utf-8")

        retval = xml
        if raw:
            retval = saml_base64
    return retval


def extract_form_post_url(html):
    """Parse html, and extract a Form Action POST URL.

    :param html: String with HTML document.
    :return: URL string, or None
    """
    soup = BeautifulSoup(html, "html.parser")
    post_url = None

    elem = soup.find("form", attrs={"id": "appForm"})
    if type(elem) is bs4.element.Tag:
        post_url = elem.get("action")
    return str(post_url)


def extract_saml_relaystate(html):
    """Parse html, and extract SAML relay state from a form.

    :param html: String with HTML document.
    :return: relay state value, or None
    """
    soup = BeautifulSoup(html, "html.parser")
    relay_state = None

    elem = soup.find("input", attrs={"name": "RelayState"})
    if type(elem) is bs4.element.Tag:
        relay_state = str(elem.get("value"))
    return relay_state


def extract_state_token(html):
    """Parse an HTML document, and extract a state token.

    :param html: String with HTML document
    :return: string with state token, or None
    """
    soup = BeautifulSoup(html, "html.parser")
    state_token = None
    pattern = re.compile(r"var stateToken = '(?P<stateToken>.*)';", re.MULTILINE)

    script = soup.find("script", text=pattern)
    if type(script) is bs4.element.Tag:
        match = pattern.search(script.text)
        if match:
            encoded_token = match.group("stateToken")
            state_token = codecs.decode(encoded_token, "unicode-escape")

    return state_token


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
    factor_type = selected_factor["_embedded"]["factor"]["factorType"]

    if mfa_provider == "DUO":
        payload, headers, callback_url = duo.authenticate_duo(selected_factor)
        duo.duo_api_post(callback_url, payload=payload)
        mfa_verify = api_wrapper(mfa_challenge_url, payload, headers)
    elif mfa_provider == "OKTA" and factor_type == "push":
        mfa_verify = push_approval(headers, mfa_challenge_url, payload)
    elif mfa_provider in ["OKTA", "GOOGLE"] and factor_type in ["token:software:totp", "sms"]:
        mfa_verify = totp_approval(
            selected_mfa_option, headers, mfa_challenge_url, payload, primary_auth
        )
    else:
        logger.error(
            f"Sorry, the MFA provider '{mfa_provider} {factor_type}' is not yet supported."
            " Please retry with another option."
        )
        exit(1)

    if "sessionToken" not in mfa_verify:
        logger.error(
            f"Could not verify MFA Challenge with {mfa_provider} {primary_auth['factorType']}"
        )
    return mfa_verify["sessionToken"]


def mfa_index(preset_mfa, available_mfas, mfa_options):
    """Get mfa index in request.

    :param preset_mfa: preset mfa from settings
    :param available_mfas: available mfa ids
    :param mfa_options: available mfas
    """
    indices = []
    # Gets the index number from each preset MFA in the list of avaliable ones.
    if preset_mfa:
        logger.debug(f"Get mfa from {available_mfas}.")
        indices = [i for i, elem in enumerate(available_mfas) if preset_mfa in elem]

    index = None
    if len(indices) == 0:
        logger.debug(f"No matches with {preset_mfa}, going to get user input")
        index = user.select_preferred_mfa_index(mfa_options)
    elif len(indices) == 1:
        logger.debug(f"One match: {preset_mfa} in {indices}")
        index = indices[0]
    else:
        logger.error(
            f"{preset_mfa} is not unique in {available_mfas}. Please check your configuration."
        )
        sys.exit(1)

    return index


def mfa_challenge(headers, primary_auth):
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

    preset_mfa = config.okta["mfa"]

    # This creates a list where each elements looks like provider_factor_id.
    # For example, OKTA_push_9yi4bKJNH2WEWQ0x8, GOOGLE_token:software:totp_9yi4bKJNH2WEWQ
    available_mfas = [f"{d['provider']}_{d['factorType']}_{d['id']}" for d in mfa_options]

    index = mfa_index(preset_mfa, available_mfas, mfa_options)

    # time to challenge the mfa option
    selected_mfa_option = mfa_options[index]
    logger.debug(f"Selected MFA is [{selected_mfa_option}]")

    mfa_challenge_url = selected_mfa_option["_links"]["verify"]["href"]

    payload = {
        "stateToken": primary_auth["stateToken"],
        "factorType": selected_mfa_option["factorType"],
        "provider": selected_mfa_option["provider"],
        "profile": selected_mfa_option["profile"],
    }
    selected_factor = api_wrapper(mfa_challenge_url, payload, headers)

    mfa_provider = selected_factor["_embedded"]["factor"]["provider"]
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


def totp_approval(selected_mfa_option, headers, mfa_challenge_url, payload, primary_auth):
    """Handle user mfa options.

    :param selected_mfa_option: Selected MFA option (SMS, push, etc)
    :param headers: headers
    :param mfa_challenge_url: MFA challenge URL
    :param payload: payload
    :param primary_auth: Primary authentication method
    :return: payload data

    """
    logger.debug(f"User MFA options selected: [{selected_mfa_option['factorType']}]")
    if config.okta["mfa_response"] is None:
        logger.debug("Getting verification code from user.")
        config.okta["mfa_response"] = user.get_input("Enter your verification code: ")
        user.add_sensitive_value_to_be_masked(config.okta["mfa_response"])

    # time to verify the mfa
    payload = {"stateToken": primary_auth["stateToken"], "passCode": config.okta["mfa_response"]}
    # FIXME: This call needs to catch a 403 coming from a bad token
    mfa_verify = api_wrapper(mfa_challenge_url, payload, headers)
    if "sessionToken" in mfa_verify:
        user.add_sensitive_value_to_be_masked(mfa_verify["sessionToken"])
    logger.debug(f"mfa_verify [{json.dumps(mfa_verify)}]")

    return mfa_verify


def push_approval(headers, mfa_challenge_url, payload):
    """Handle push approval from the user.

    :param headers: HTTP headers sent to API call
    :param mfa_challenge_url: MFA challenge url
    :param payload: payload which needs to be sent
    :return: Session Token if succeeded or terminates if user wait goes 5 min

    """
    logger.debug(f"Push approval with headers:{headers} challenge_url:{mfa_challenge_url}")

    user.print("Waiting for an approval from the device...")
    status = "MFA_CHALLENGE"
    result = "WAITING"
    response = {}
    challenge_displayed = False

    while status == "MFA_CHALLENGE" and result == "WAITING":
        response = api_wrapper(mfa_challenge_url, payload, headers)
        if "sessionToken" in response:
            user.add_sensitive_value_to_be_masked(response["sessionToken"])

        logger.debug(f"MFA Response:\n{json.dumps(response)}")
        # Retrieve these values from the object, and set a sensible default if they do not
        # exist.
        status = response.get("status", "UNKNOWN")
        result = response.get("factorResult", "UNKNOWN")

        # The docs at https://developer.okta.com/docs/reference/api/authn/#verify-push-factor
        # state that the call will return a factorResult in [ SUCCESS, REJECTED, TIMEOUT,
        # WAITING]. However, on success, SUCCESS is not set and we have to rely on the
        # response["status"] instead
        answer = (
            response.get("_embedded", {})
            .get("factor", {})
            .get("_embedded", {})
            .get("challenge", {})
            .get("correctAnswer", None)
        )
        if answer and not challenge_displayed:
            # If a Number Challenge response exists, retrieve it from this deeply nested path,
            # otherwise set to None.
            user.print(f"Number Challenge response is {answer}")
            challenge_displayed = True
        time.sleep(1)

    if status == "SUCCESS" and "sessionToken" in response:
        # noop, we will return the variable later
        pass
    # Everything else should have a status of "MFA_CHALLENGE", and the result provides a
    # hint on why the challenge failed.
    elif result == "REJECTED":
        logger.error("The Okta Verify push has been denied.")
        sys.exit(2)
    elif result == "TIMEOUT":
        logger.error("Device approval window has expired.")
        sys.exit(2)
    else:
        logger.error(f"Push response type {result} for {status} not implemented.")
        sys.exit(2)

    return response
