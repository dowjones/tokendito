# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""
This module handles the all Okta operations.

1. Okta authentication
2. Update Okta Config File

"""
import codecs
from copy import deepcopy
import json
import logging
import re
import sys
import time

import bs4
from bs4 import BeautifulSoup
import requests
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
    logger.debug(f"Calling {url} with {headers}")
    try:
        response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
    except Exception as err:
        logger.error(f"There was an error with the call to {url}: {err}")
        sys.exit(1)

    logger.debug(f"{response.url} responded with status code {response.status_code}")

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


def get_auth_properties(userid=None, url=None):
    """Make a call to the webfinger endpoint.

    :param userid: User for which we are requesting an auth endpoint.
    :param url: Site where we are looking up the user.
    :returns: dictionary with authentication properties.
    """
    payload = {"resource": f"okta:acct:{userid}", "rel": "okta:idp"}
    headers = {"accept": "application/jrd+json"}
    url = f"{url}/.well-known/webfinger"

    logger.debug(f"Looking up auth endpoint for {userid} in {url}")
    response = user.request_wrapper("GET", url, headers=headers, params=payload)

    try:
        ret = response.json()["links"][0]["properties"]
    except (KeyError, ValueError) as e:
        logger.error(f"Failed to parse authentication type in {url}:{str(e)}")
        logger.debug(f"Response: {response.text}")
        sys.exit(1)

    # Try to get metadata, type, and ID if available, but ensure
    # that a dictionary with the correct keys is returned.
    properties = {}
    properties["metadata"] = ret.get("okta:idp:metadata", None)
    properties["type"] = ret.get("okta:idp:type", None)
    properties["id"] = ret.get("okta:idp:id", None)

    logger.debug(f"Auth properties are {properties}")
    return properties


def get_saml_request(auth_properties):
    """
    Get a SAML Request object from the Service Provider, to be submitted to the IdP.

    :param auth_properties: dict with the IdP ID and type.
    :returns: dict with post_url, relay_state, and base64 encoded saml request.
    """
    headers = {"accept": "text/html,application/xhtml+xml,application/xml"}
    base_url = user.get_base_url(auth_properties["metadata"])
    url = f"{base_url}/sso/idps/{auth_properties['id']}"

    logger.debug(f"Getting SAML request from {url}")
    response = user.request_wrapper("GET", url, headers=headers)
    saml_request = {
        "base_url": user.get_base_url(extract_form_post_url(response.text)),
        "post_url": extract_form_post_url(response.text),
        "relay_state": extract_saml_relaystate(response.text),
        "request": extract_saml_request(response.text, raw=True),
    }
    user.add_sensitive_value_to_be_masked(saml_request["request"])
    logger.debug(f"SAML request is {saml_request}")
    return saml_request


def send_saml_request(saml_request, cookies):
    """Submit SAML request to IdP, and get the response back.

    :param cookies: session cookies with `sid`
    :param saml_request: dict with IdP post_url, relay_state, and saml_request
    :returns: dict with with SP post_url, relay_state, and saml_response
    """
    payload = {
        "relayState": saml_request["relay_state"],
        "SAMLRequest": saml_request["request"],
    }
    headers = {"accept": "text/html,application/xhtml+xml,application/xml"}
    url = saml_request["post_url"]
    logger.debug(f"Sending SAML request to {url}")

    response = user.request_wrapper("GET", url, headers=headers, data=payload, cookies=cookies)
    saml_response = {
        "response": extract_saml_response(response.text, raw=True),
        "relay_state": extract_saml_relaystate(response.text),
        "post_url": extract_form_post_url(response.text),
    }
    user.add_sensitive_value_to_be_masked(saml_response["response"])
    logger.debug(f"SAML response is {saml_response}")
    return saml_response


def send_saml_response(saml_response):
    """Submit SAML response to the SP.

    :param saml_response: dict with with SP post_url, relay_state, and saml_response
    :returns: `sid` session cookie
    """
    payload = {
        "SAMLResponse": saml_response["response"],
        "RelayState": saml_response["relay_state"],
    }
    headers = {"accept": "text/html,application/xhtml+xml,application/xml"}
    url = saml_response["post_url"]

    logger.debug(f"Sending SAML response back to {url}")
    response = user.request_wrapper("POST", url, data=payload, headers=headers)
    session_cookies = response.cookies
    sid = session_cookies.get("sid")
    if sid is not None:
        user.add_sensitive_value_to_be_masked(sid)
    logger.debug(f"Have session cookies: {session_cookies}")
    return session_cookies


def get_session_token(config, primary_auth, headers):
    """Get session_token.

    :param config: Configuration object
    :param headers: Headers of the request
    :param primary_auth: Primary authentication
    :return: Session Token from JSON response
    """
    status = None
    try:
        status = primary_auth.get("status", None)
    except AttributeError:
        pass

    if status == "SUCCESS" and "sessionToken" in primary_auth:
        session_token = primary_auth.get("sessionToken")
    elif status == "MFA_REQUIRED":
        session_token = mfa_challenge(config, headers, primary_auth)
    else:
        logger.debug(f"Error parsing response: {json.dumps(primary_auth)}")
        logger.error("Okta auth failed: unknown status.")
        sys.exit(1)

    user.add_sensitive_value_to_be_masked(session_token)

    return session_token


def authenticate(config):
    """Authenticate user.

    :param config: Config object
    :return: session ID cookie.
    """
    auth_properties = get_auth_properties(userid=config.okta["username"], url=config.okta["org"])
    if "type" not in auth_properties:
        logger.error("Okta auth failed: unknown type.")
        sys.exit(1)
    sid = None

    if is_local_auth(auth_properties):
        session_token = local_auth(config)
        sid = user.request_cookies(config.okta["org"], session_token)
    elif is_saml2_auth(auth_properties):
        sid = saml2_auth(config, auth_properties)
    else:
        logger.error(f"{auth_properties['type']} login via IdP Discovery is not curretly supported")
        sys.exit(1)
    return sid


def is_local_auth(auth_properties):
    """Check whether authentication happens locally.

    :param auth_properties: auth_properties dict
    :return: True for local auth, False otherwise.
    """
    try:
        if auth_properties["type"] == "OKTA":
            return True
    except (TypeError, KeyError):
        pass
    return False


def is_saml2_auth(auth_properties):
    """Check whether authentication happens via SAML2 on a different IdP.

    :param auth_properties: auth_properties dict
    :return: True for SAML2 on Okta, False otherwise.
    """
    try:
        if auth_properties["type"] == "SAML2":
            return True
    except (TypeError, KeyError):
        pass
    return False


def local_auth(config):
    """Authenticate local user with okta credential.

    :param config: Config object
    :return: MFA session with options
    """
    session_token = None
    headers = {"content-type": "application/json", "accept": "application/json"}
    payload = {"username": config.okta["username"], "password": config.okta["password"]}

    logger.debug(f"Authenticate user to {config.okta['org']}")
    logger.debug(f"Sending {headers}, {payload} to {config.okta['org']}")
    primary_auth = api_wrapper(f"{config.okta['org']}/api/v1/authn", payload, headers)

    while session_token is None:
        session_token = get_session_token(config, primary_auth, headers)
    logger.info(f"User has been succesfully authenticated to {config.okta['org']}.")
    return session_token


def saml2_auth(config, auth_properties):
    """SAML2 authentication flow.

    :param config: Config object
    :param auth_properties: dict with authentication properties
    :returns: session ID cookie, if successful.
    """
    # Get the SAML request details
    saml_request = get_saml_request(auth_properties)

    # Create a copy of our configuration, so that we can freely reuse it
    # without Python's pass-as-reference-value interfering with it.
    saml2_config = deepcopy(config)
    saml2_config.okta["org"] = saml_request["base_url"]
    logger.info(f"Authentication is being redirected to {saml2_config.okta['org']}.")
    # Try to authenticate using the new configuration. This could cause
    # recursive calls, which allows for IdP chaining.
    session_cookies = authenticate(saml2_config)

    # Once we are authenticated, send the SAML request to the IdP.
    # This call requires session cookies.
    saml_response = send_saml_request(saml_request, session_cookies)

    # Send SAML response from the IdP back to the SP, which will generate new
    # session cookies.
    session_id = send_saml_response(saml_response)
    return session_id


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
        post_url = str(elem.get("action"))
    return post_url


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
    config,
    mfa_provider,
    selected_factor,
    mfa_challenge_url,
    primary_auth,
    selected_mfa_option,
    headers,
    payload,
):
    """Receive session key.

    :param config: Config object
    :param mfa_provider: MFA provider
    :param selected_factor: Selected MFA factor
    :param mfa_challenge_url: MFA challenge url
    :param primary_auth: Primary authentication
    :param selected_mfa_option: Selected MFA option
    :return: session_key

    """
    mfa_verify = dict()
    factor_type = selected_factor.get("_embedded", {}).get("factor", {}).get("factorType", None)

    if mfa_provider == "DUO":
        payload, headers, callback_url = duo.authenticate_duo(selected_factor)
        duo.duo_api_post(callback_url, payload=payload)
        mfa_verify = api_wrapper(mfa_challenge_url, payload, headers)
    elif mfa_provider == "OKTA" and factor_type == "push":
        mfa_verify = push_approval(headers, mfa_challenge_url, payload)
    elif mfa_provider in ["OKTA", "GOOGLE"] and factor_type in ["token:software:totp", "sms"]:
        mfa_verify = totp_approval(
            config, selected_mfa_option, headers, mfa_challenge_url, payload, primary_auth
        )
    else:
        logger.error(
            f"Sorry, the MFA provider '{mfa_provider}:{factor_type}' is not yet supported."
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


def mfa_challenge(config, headers, primary_auth):
    """Handle user mfa challenges.

    :param config: Config object
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
        config,
        mfa_provider,
        selected_factor,
        mfa_challenge_url,
        primary_auth,
        selected_mfa_option,
        headers,
        payload,
    )

    return mfa_session_token


def totp_approval(config, selected_mfa_option, headers, mfa_challenge_url, payload, primary_auth):
    """Handle user mfa options.

    :param config: Config object
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
    payload = {
        "stateToken": primary_auth["stateToken"],
        "passCode": config.okta["mfa_response"],
    }
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
