# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""
This module handles the all Okta operations.

1. Okta authentication
2. Update Okta Config File

"""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,  # noqa: F401
                      int, list, map, next, object, oct, open, pow, range,
                      round, str, super, zip)
import json
import logging
import sys
import time

from future import standard_library
import requests
from tokendito import helpers
from tokendito import settings
standard_library.install_aliases()


def okta_verify_api_method(mfa_challenge_url, payload, headers):
    """Okta MFA authentication.

    :param mfa_challenge_url: MFA challenge url
    :param payload: JSON Payload
    :param headers: Headers of the request
    :return: Okta authentication response
    """
    logging.debug("Okta MFA authentication URL [{}] headers [{}]".format(
        mfa_challenge_url, headers))

    try:
        response = json.loads(requests.request('POST', mfa_challenge_url,
                                               data=json.dumps(payload), headers=headers).text)
    except Exception as request_error:
        logging.error(
            "There was an error connecting to Okta: \n{}".format(request_error))
        sys.exit(1)

    if 'errorCode' in response:
        error_string = "Exiting due to Okta API error [{}]\n{}".format(
            response['errorCode'], response['errorSummary'])
        if len(response['errorCauses']) > 0:
            error_string += "\n{}".format(json.dumps(response['errorCauses']))
        logging.error(error_string)
        sys.exit(1)

    return response


def authenticate_user(okta_url, okta_username, okta_password):
    """Authenticate user with okta credential.

    :param okta_url: company specific URL of the okta
    :param okta_username: okta username
    :param okta_password: okta password
    :return: MFA session options

    """
    logging.debug(
        "Authenticate user with okta credential [{} user {}]".format(
            okta_url, okta_username))
    headers = {
        'content-type': 'application/json',
        'accept': 'application/json'
    }
    payload = prepare_payload(
        username=okta_username, password=okta_password)

    primary_auth = okta_verify_api_method(
        '{}/api/v1/authn'.format(okta_url), payload, headers)
    logging.debug("Authenticate Okta header [{}] ".format(headers))

    return user_mfa_challenge(headers, primary_auth)


def user_mfa_challenge(headers, primary_auth):
    """Handle user mfa challenges.

    :param headers: headers what needs to be sent to api
    :param primary_auth: primary authentication
    :return: Okta MFA Session token after the successful entry of the code

    """
    logging.debug("Handle user MFA challenges")
    try:
        mfa_options = primary_auth['_embedded']['factors']
    except KeyError:
        logging.error("Okta auth failed: "
                      "Could not retrieve list of MFA methods")
        logging.debug("Error parsing response: {}".format(
            json.dumps(primary_auth)))
        sys.exit(1)

    mfa_setup_statuses = [
        d['status'] for d in mfa_options if 'status' in d and d['status'] != "ACTIVE"]

    if len(mfa_setup_statuses) == len(mfa_options):
        logging.error("MFA not configured. "
                      "Please enable MFA on your account and try again.")
        sys.exit(2)

    preset_mfa = settings.mfa_method
    available_mfas = [d['factorType'] for d in mfa_options]
    if preset_mfa is not None and preset_mfa in available_mfas:
        mfa_index = available_mfas.index(settings.mfa_method)
    else:
        logging.warning(
            "No MFA provided or provided MFA does not exist. [{}]".format(
                settings.mfa_method))
        mfa_index = select_preferred_mfa_index(mfa_options)

    # time to challenge the mfa option
    selected_mfa_option = mfa_options[mfa_index]
    logging.debug("Selected MFA is [{}]".format(selected_mfa_option))

    mfa_challenge_url = selected_mfa_option['_links']['verify']['href']
    payload = prepare_payload(stateToken=primary_auth['stateToken'],
                              factorType=selected_mfa_option['factorType'],
                              provider=selected_mfa_option['provider'],
                              profile=selected_mfa_option['profile'])
    okta_verify_api_method(mfa_challenge_url, payload, headers)
    logging.debug("mfa_challenge_url [{}] headers [{}]".format(
        mfa_challenge_url, headers))
    mfa_verify = user_mfa_options(selected_mfa_option,
                                  headers, mfa_challenge_url, payload, primary_auth)
    return mfa_verify['sessionToken']


def user_mfa_options(selected_mfa_option,
                     headers, mfa_challenge_url,
                     payload, primary_auth):
    """Handle user mfa options.

    :param selected_mfa_option: Selected MFA option (SMS, push, etc)
    :param headers: headers
    :param mfa_challenge_url: MFA challenge URL
    :param payload: payload
    :param primary_auth: Primary authentication method
    :return: payload data

    """
    logging.debug("Handle user MFA options")

    logging.debug("User MFA options selected: [{}]".format(
        selected_mfa_option['factorType']))
    if selected_mfa_option['factorType'] == 'push':
        return push_approval(headers, mfa_challenge_url, payload)

    if settings.mfa_response is None:
        logging.debug("Getting verification code from user.")
        print('Type verification code and press Enter')
        settings.mfa_response = helpers.to_unicode(input('-> '))

    # time to verify the mfa method
    payload = prepare_payload(
        stateToken=primary_auth['stateToken'], passCode=settings.mfa_response)
    mfa_verify = okta_verify_api_method(mfa_challenge_url, payload, headers)
    logging.debug("mfa_verify [{}]".format(mfa_verify))

    return mfa_verify


def prepare_payload(**kwargs):
    """Prepare payload for the HTTP request header.

    :param kwargs: parameters to get together
    :return: payload for the http header

    """
    logging.debug("Prepare payload")

    payload_dict = {}
    if kwargs is not None:
        for key, value in list(kwargs.items()):
            payload_dict[key] = value

            if key != 'password':
                logging.debug("Prepare payload [{} {}]".format(key, value))

    return payload_dict


def push_approval(headers, mfa_challenge_url, payload):
    """Handle push approval from the user.

    :param headers: HTTP headers sent to API call
    :param mfa_challenge_url: MFA challenge url
    :param payload: payload which needs to be sent
    :return: Session Token if succeeded or terminates if user wait goes 5 min

    """
    logging.debug("Handle push approval from the user [{}] [{}]".format(
        headers, mfa_challenge_url))

    print('Waiting for an approval from device...')
    mfa_status = "WAITING"

    while mfa_status == "WAITING":
        mfa_verify = okta_verify_api_method(
            mfa_challenge_url, payload, headers)

        logging.debug("MFA Response:\n{}".format(json.dumps(mfa_verify)))

        if 'factorResult' in mfa_verify:
            mfa_status = mfa_verify['factorResult']
        elif mfa_verify['status'] == 'SUCCESS':
            break
        else:
            logging.error(
                "There was an error getting your MFA status.")
            logging.debug(mfa_verify)
            if 'status' in mfa_verify:
                logging.error("Exiting due to error: {}".format(
                    mfa_verify['status']))
            sys.exit(1)

        if mfa_status == 'REJECTED':
            logging.error(
                "The Okta Verify push has been denied. Please retry later.")
            sys.exit(2)
        elif mfa_status == 'TIMEOUT':
            logging.error("Device approval window has expired.")
            sys.exit(2)

        time.sleep(2)

    return mfa_verify


def select_preferred_mfa_index(mfa_options):
    """Show all the MFA options to the users.

    :param mfa_options: List of available MFA options
    :return: MFA option selected index by the user from the output
    """
    logging.debug("Show all the MFA options to the users.")
    print('\nSelect your preferred MFA method and press Enter')
    for (mfa_counter, mfa_option) in enumerate(mfa_options):
        print("[{}] {}".format(mfa_counter, mfa_option['factorType']))
    while True:
        user_input = helpers.to_unicode(input('-> '))
        logging.debug("User input [{}]".format(user_input))

        try:
            user_input = int(user_input)
        except ValueError as error:
            print('Invalid input, try again.\n{}'.format(error))
            continue
        if user_input in range(0, len(mfa_options)):
            break
        print('Invalid choice')
        continue
    return user_input
