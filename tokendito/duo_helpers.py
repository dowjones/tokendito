# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module handles Duo operations."""
from __future__ import absolute_import, division, print_function, unicode_literals

import json
import logging
import sys
import time
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup
from future import standard_library
import requests
from tokendito import helpers
from tokendito import settings

standard_library.install_aliases()


def prepare_duo_info(selected_okta_factor):
    """Aggregate most of the parameters needed throughout the Duo authentication process.

    :param selected_okta_factor: dict response describing Duo factor in Okta.
    :return duo_info: dict of parameters for Duo
    """
    duo_info = {}
    okta_factor = selected_okta_factor["_embedded"]["factor"]["_embedded"][
        "verification"
    ]
    duo_info["okta_factor"] = okta_factor
    duo_info["factor_id"] = selected_okta_factor["_embedded"]["factor"]["id"]

    duo_info["state_token"] = selected_okta_factor["stateToken"]
    duo_info["okta_callback_url"] = okta_factor["_links"]["complete"]["href"]
    duo_info["tx"] = okta_factor["signature"].split(":")[0]
    duo_info["app_sig"] = okta_factor["signature"].split(":")[1]
    duo_info["parent"] = "{}/signin/verify/duo/web".format(settings.okta_org)
    duo_info["host"] = okta_factor["host"]
    duo_info["sid"] = ""

    version = okta_factor["_links"]["script"]["href"].split("-v")[1]
    duo_info["version"] = version.strip(".js")

    return duo_info


def duo_api_post(url, params={}, headers={}, payload={}):
    """Error handling and response parsing wrapper for Duo POSTs.

    :param url: The URL being connected to.
    :param params: URL query parameters.
    :param headers: Request headers.
    :param payload: Request body.
    :return response: Response to the API request.
    """
    try:
        response = requests.request(
            "POST", url, params=params, headers=headers, data=payload
        )
    except Exception as request_issue:
        logging.error(
            "There was an error connecting to the Duo API: \n{}".format(request_issue)
        )
        sys.exit(1)

    json_message = None
    try:
        json_message = response.json()
    except ValueError:
        logging.debug("Non-json response from Duo API: \n{}".format(response))

    if response.status_code != 200:
        logging.critical(
            "Your Duo authentication has failed with status {}.".format(
                response.status_code
            )
        )
        if json_message and json_message["stat"].lower() != "ok":
            logging.critical(
                "\n{}, {}".format(response.status_code, json_message["message"])
            )
        else:
            logging.critical(
                "Please re-run the program with parameter"
                ' "--loglevel debug" to see more information.'
            )
        sys.exit(2)

    return response


def get_duo_sid(duo_info):
    """Perform the initial Duo authentication request to obtain the SID.

    The SID is referenced throughout the authentication process for Duo.

    :param duo_info: dict response describing Duo factor in Okta.
    :return: duo_info with added SID.
    :return: duo_auth_response, contains html content listing available factors.
    """
    params = helpers.prepare_payload(
        tx=duo_info["tx"], v=duo_info["version"], parent=duo_info["parent"]
    )

    url = "https://{}/frame/web/v1/auth".format(duo_info["host"])
    logging.info(
        "Calling Duo {} with params {}".format(urlparse(url).path, params.keys())
    )
    duo_auth_response = duo_api_post(url, params=params)

    try:
        duo_auth_redirect = urlparse("{}".format(unquote(duo_auth_response.url))).query
        duo_info["sid"] = duo_auth_redirect.strip("sid=")
    except Exception as sid_error:
        logging.error(
            "There was an error getting your SID."
            "Please try again. \n{}".format(sid_error)
        )

    return duo_info, duo_auth_response


def get_duo_devices(duo_auth):
    """Parse Duo auth response to extract user's MFA options.

    The /frame/web/v1/auth API returns an html page that lists
    devices and their mfa options for the user logging in.
    The return data type (list of dicts) is intended to allow us to
    do printout padding and indexing when interacting with the end user.

    :param duo_auth: contains html content listing available factors.
    :return factor_options: list of dict objects describing each MFA option.
    """
    soup = BeautifulSoup(duo_auth.content, "html.parser")

    device_soup = soup.find("select", {"name": "device"}).findAll("option")
    devices = ["{} - {}".format(d["value"], d.text) for d in device_soup]
    if not devices:
        logging.error("Please configure devices for your Duo MFA and retry.")
        sys.exit(2)

    factor_options = []
    for device in devices:
        options = soup.find("fieldset", {"data-device-index": device.split(" - ")[0]})
        factors = options.findAll("input", {"name": "factor"})
        for factor in factors:
            factor_option = {}
            factor_option["device"] = device
            factor_option["factor"] = factor["value"]
            factor_options.append(factor_option)
    return factor_options


def parse_duo_mfa_challenge(mfa_challenge):
    """Gracefully parse Duo MFA challenge response.

    :param mfa_challenge: Duo API response for MFA challenge.
    :return txid: Duo transaction ID.
    """
    try:
        mfa_challenge = mfa_challenge.json()
        mfa_status = mfa_challenge["stat"]
        txid = mfa_challenge["response"]["txid"]
    except ValueError as value_error:
        logging.error(
            "The Duo API returned a non-json response: \n{}".format(value_error)
        )
        sys.exit(1)
    except KeyError as key_error:
        logging.error(
            "The Duo API response is missing a required parameter: \n{}".format(
                key_error
            )
        )
        print(json.dumps(mfa_challenge))
        sys.exit(1)

    if mfa_status == "fail":
        logging.error(
            "Your Duo authentication has failed: \n{}".format(mfa_challenge["message"])
        )
        sys.exit(1)
    return txid


def duo_mfa_challenge(duo_info, mfa_option, passcode):
    """Poke Duo to challenge the selected factor.

    After the user has selected their device and factor of choice,
    tell Duo to send a challenge. This is where the end user will receive
    a phone call or push.

    :param duo_info: dict of parameters for Duo
    :param mfa_option: the user's selected second factor.
    :return txid: Duo transaction ID used to track this auth attempt.
    """
    url = "https://{}/frame/prompt".format(duo_info["host"])
    device = mfa_option["device"].split(" - ")[0]
    mfa_data = helpers.prepare_payload(
        factor=mfa_option["factor"],
        device=device,
        sid=duo_info["sid"],
        out_of_date=False,
        days_out_of_date=0,
        days_to_block=None,
    )
    mfa_data["async"] = True  # async is a reserved keyword
    if passcode:
        mfa_data["passcode"] = passcode
    mfa_challenge = duo_api_post(url, payload=mfa_data)
    txid = parse_duo_mfa_challenge(mfa_challenge)

    logging.debug("Sent MFA Challenge and obtained Duo transaction ID.")
    return txid


def get_mfa_response(mfa_result):
    """Extract json from mfa response.

    :param mfa_result: raw response from mfa api
    :return verify_mfa: json response from mfa api
    """
    try:
        verify_mfa = mfa_result.json()["response"]
    except Exception as parse_error:
        logging.error(
            "There was an error parsing the mfa challenge result: \n{}".format(
                parse_error
            )
        )
        sys.exit(1)
    return verify_mfa


def parse_challenge(verify_mfa, challenge_result):
    """Parse the challenge response.

    :param mfa_result: response from MFA challenge status request
    :return challenge status: status of MFA challenge
    :return challenge reason: additional info about challenge status
    """
    challenge_reason = None

    if "status" in verify_mfa:
        print(verify_mfa["status"])

    if "reason" in verify_mfa:
        challenge_reason = verify_mfa["reason"]

    if "result" in verify_mfa:
        logging.info("Result received: {}".format(verify_mfa["result"]))
        challenge_result = verify_mfa["result"].lower()

    logging.debug("Challenge result is {}".format(challenge_result))
    return challenge_result, challenge_reason


def duo_mfa_verify(duo_info, txid):
    """Verify MFA challenge completion.

    After the user has received the MFA challenge, query the Duo API
    until the challenge is completed.

    :param duo_info: dict of parameters for Duo.
    :param mfa_option: the user's selected second factor.
    :return txid: Duo transaction ID used to track this auth attempt.
    """
    url = "https://{}/frame/status".format(duo_info["host"])
    challenged_mfa = helpers.prepare_payload(txid=txid, sid=duo_info["sid"])
    challenge_result = None

    while True:
        logging.debug("Waiting for MFA challenge response")
        mfa_result = duo_api_post(url, payload=challenged_mfa)
        verify_mfa = get_mfa_response(mfa_result)
        challenge_result, challenge_reason = parse_challenge(
            verify_mfa, challenge_result
        )

        if challenge_result is None:
            continue
        elif challenge_result == "success":
            logging.debug("Successful MFA challenge received")
            break
        elif challenge_result == "failure":
            logging.critical(
                "MFA challenge has failed:"
                " {}. Please try again.".format(challenge_reason)
            )
            sys.exit(2)
        else:
            logging.debug(
                "MFA challenge result: {}"
                "Reason: {}\n\n".format(challenge_result, challenge_reason)
            )
        time.sleep(1)

    return verify_mfa


def duo_factor_callback(duo_info, verify_mfa):
    """Inform factor callback api of successful challenge.

    This request seems to inform this factor's callback url
    that the challenge process has been completed.

    :param duo_info: dict of parameters for Duo.
    :param verify_mfa: verified mfa challenge response from status api.
    :return sig_response: required to sign final Duo callback request.
    """
    factor_callback_url = "https://{}{}".format(
        duo_info["host"], verify_mfa["result_url"]
    )
    factor_callback = duo_api_post(
        factor_callback_url, payload={"sid": duo_info["sid"]}
    )

    try:
        sig_response = "{}:{}".format(
            factor_callback.json()["response"]["cookie"], duo_info["app_sig"]
        )
    except Exception as sig_error:
        logging.error(
            "There was an error getting your"
            " application signature from Duo: \n{}".format(json.dumps(sig_error))
        )

    logging.debug("Completed factor callback.")
    return sig_response


def set_passcode(mfa_option):
    """Set totp passcode.

    If the user has selected the passcode option, collect their TOTP.

    :param mfa_option: selected factor
    :return passcode: passcode value from user
    """
    passcode = None
    if mfa_option["factor"].lower() == "passcode":
        print("Type your TOTP and press Enter")
        passcode = helpers.get_input()
    return passcode


def authenticate_duo(selected_okta_factor):
    """Accomplish MFA via Duo.

    This is the main function that coordinates the Duo
    multifactor fetching, presentation, selection, challenge,
    and verification until making an Okta callback.

    :param selected_okta_factor: Duo factor information retrieved from Okta.
    :return payload: required payload for Okta callback
    :return headers: required headers for Okta callback
    """
    try:
        duo_info = prepare_duo_info(selected_okta_factor)
    except KeyError as missing_key:
        logging.error(
            "There was an issue parsing the Okta factor."
            " Please try again. \n{}".format(missing_key)
        )
        sys.exit(1)

    # Collect devices, factors, auth params for Duo
    duo_info, duo_auth_response = get_duo_sid(duo_info)
    factor_options = get_duo_devices(duo_auth_response)
    mfa_index = helpers.select_preferred_mfa_index(
        factor_options, factor_key="factor", subfactor_key="device"
    )

    mfa_option = factor_options[mfa_index]
    logging.debug("Selected MFA is [{}]".format(mfa_option))
    passcode = set_passcode(mfa_option)

    txid = duo_mfa_challenge(duo_info, mfa_option, passcode)
    verify_mfa = duo_mfa_verify(duo_info, txid)

    # Make factor callback to Duo
    sig_response = duo_factor_callback(duo_info, verify_mfa)

    # Prepare for Okta callback
    payload = helpers.prepare_payload(
        id=duo_info["factor_id"],
        sig_response=sig_response,
        stateToken=duo_info["state_token"],
    )
    headers = {}
    headers["content-type"] = "application/json"
    headers["accept"] = "application/json"

    return payload, headers, duo_info["okta_callback_url"]
