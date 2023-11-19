# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""
Handle the all Okta operations.

1. Okta authentication
2. Update Okta Config File

"""
import base64
import codecs
from copy import deepcopy
import hashlib
import json
import logging
import os
import re
import sys
import time
from urllib.parse import urlencode
from urllib.parse import urlparse

import bs4
from bs4 import BeautifulSoup
import requests.cookies
from tokendito import duo
from tokendito import user
from tokendito.http_client import HTTP_client

logger = logging.getLogger(__name__)

_status_dict = dict(
    E0000004="Authentication failed",
    E0000047="API call exceeded rate limit due to too many requests",
    PASSWORD_EXPIRED="Your password has expired",
    LOCKED_OUT="Your account is locked out",
)


def api_error_code_parser(status=None):
    """Status code parsing.

    param status: Response status
    return message: status message
    """
    if status and status in _status_dict.keys():
        message = f"Okta auth failed: {_status_dict[status]}"
    else:
        message = f"Okta auth failed: {status}. Please verify your settings and try again."
    logger.debug(f"Parsing error [{message}] ")
    return message


def get_auth_pipeline(url=None):
    """Get auth pipeline version."""
    logger.debug(f"get_auth_pipeline({url})")
    headers = {"accept": "application/json"}
    url = f"{url}/.well-known/okta-organization"

    response = HTTP_client.get(url, headers=headers)

    try:
        response_json = response.json()
    except AttributeError as e:
        logger.error(f"Failed to parse json in {url}{e}")
        sys.exit(1)
    try:
        auth_pipeline = response_json.get("pipeline", None)
    except (KeyError, ValueError) as e:
        logger.error(f"Failed to parse pipeline for {url}:{e}")
        sys.exit(1)
    if auth_pipeline != "idx" and auth_pipeline != "v1":
        logger.error(f"unsupported auth pipeline version {auth_pipeline}")
        sys.exit(1)
    logger.debug(f"Pipeline is of type {auth_pipeline}")
    return auth_pipeline


def get_auth_properties(userid=None, url=None):
    """Make a call to the webfinger endpoint to get the auth properties metadata.

    :param userid: User's ID for which we are requesting an auth endpoint.
    :param url: Okta organization URL where we are looking up the user.
    :returns: Dictionary containing authentication properties.
    """
    payload = {"resource": f"okta:acct:{userid}", "rel": "okta:idp"}
    headers = {"accept": "application/jrd+json"}
    url = f"{url}/.well-known/webfinger"
    logger.debug(f"Looking up auth endpoint for {userid} in {url}")

    # Make a GET request to the webfinger endpoint.
    response = HTTP_client.get(url, params=payload, headers=headers)

    # Extract properties from the response.
    try:
        ret = response.json()["links"][0]["properties"]
    except (KeyError, ValueError) as e:
        logger.error(f"Failed to parse authentication type in {url}:{str(e)}")
        logger.debug(f"Response: {response.text}")
        sys.exit(1)

    # Extract specific authentication properties if available.
    # Return a dictionary with 'metadata', 'type', and 'id' keys.
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
    # Prepare the headers for the request to retrieve the SAML request.
    headers = {"accept": "text/html,application/xhtml+xml,application/xml"}

    # Build the URL based on the metadata and ID provided in the auth properties.
    base_url = user.get_base_url(auth_properties["metadata"])
    url = f"{base_url}/sso/idps/{auth_properties['id']}"

    logger.debug(f"Getting SAML request from {url}")

    # Make a GET request using the HTTP client to retrieve the SAML request.
    response = HTTP_client.get(url, headers=headers)

    # Extract the required parameters from the SAML request.
    saml_request = {
        "base_url": user.get_base_url(extract_form_post_url(response.text)),
        "post_url": extract_form_post_url(response.text),
        "relay_state": extract_saml_relaystate(response.text),
        "request": extract_saml_request(response.text, raw=True),
    }

    # Mask sensitive data in the logs for security.
    user.add_sensitive_value_to_be_masked(saml_request["request"])

    logger.debug(f"SAML request is {saml_request}")
    return saml_request


def send_saml_request(saml_request):
    """
    Submit SAML request to IdP, and get the response back.

    :param saml_request: dict with IdP post_url, relay_state, and saml_request
    :param cookies: session cookies with `sid`
    :returns: dict with with SP post_url, relay_state, and saml_response
    """
    # Define the payload and headers for the request
    payload = {
        "relayState": saml_request["relay_state"],
        "SAMLRequest": saml_request["request"],
    }

    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml",
        "Content-Type": "application/json",
    }

    # Construct the URL from the provided saml_request
    url = saml_request["post_url"]

    # Log the SAML request details
    logger.debug(f"Sending SAML request to {url}")

    # Use the HTTP client to make a GET request
    response = HTTP_client.get(url, params=payload, headers=headers)

    logger.debug(f"{base64.b64decode(payload['SAMLRequest'])}")

    # Extract relevant information from the response to form the saml_response dictionary
    saml_response = {
        "response": extract_saml_response(response.text, raw=True),
        "relay_state": extract_saml_relaystate(response.text),
        "post_url": extract_form_post_url(response.text),
    }

    # Mask sensitive values for logging purposes
    user.add_sensitive_value_to_be_masked(saml_response["response"])

    # Return the formed SAML response
    return saml_response


def create_authz_cookies(oauth2_config, oauth2_session_data):
    """
    Set authorize redirect cookies for the HTTP client.

    Needed for SAML2 flow for OIE.
    """
    session_token = HTTP_client.session.cookies.get("sessionToken")
    try:
        oauth2_url = f"{oauth2_config['org']}/oauth2/v1"
        oauth2_config_reformatted = {
            "responseType": "code",
            "state": oauth2_session_data["state"],
            "clientId": oauth2_config["client_id"],
            "authorizeUrl": oauth2_config["authorization_endpoint"],
            "tokenUrl": oauth2_config["token_endpoint"],
            "scope": "openid",
            "sessionToken": session_token,
            "userInfoUrl": f"{oauth2_url}/userinfo",
            "revokeUrl": f"{oauth2_url}/revoke",
            "logoutUrl": f"{oauth2_url}/logout",
        }
    except KeyError as e:
        logger.error(f"Missing key in config:{e}")
        sys.exit(1)

    cookiejar = requests.cookies.RequestsCookieJar()
    domain = urlparse(oauth2_config["org"]).netloc
    cookiejar.set(
        "okta-oauth-redirect-params",
        f"{{{urlencode(oauth2_config_reformatted)}}}",
        domain=domain,
        path="/",
    )
    cookiejar.set("okta-oauth-state", oauth2_session_data["state"], domain=domain, path="/")
    HTTP_client.add_cookies(cookiejar)  # add cookies


def send_saml_response(config, saml_response):
    """
    Submit SAML response to the SP.

    :param saml_response: dict with SP post_url, relay_state, and saml_response
    """
    # Define the payload and headers for the request.
    payload = {
        "SAMLResponse": saml_response["response"],
        "RelayState": saml_response["relay_state"],
    }
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    url = saml_response["post_url"]

    logger.debug(f"{base64.b64decode(saml_response['response'])}")
    # Log the SAML response details.
    logger.debug(f"Sending SAML response to {url}")
    # Use the HTTP client to make a POST request.
    response = HTTP_client.post(url, data=payload, headers=headers)

    # Get the 'sid' value from the reponse cookies.
    sid = response.cookies.get("sid", None)
    logger.debug(f"New sid is {sid}")

    # If 'sid' is present, mask its value for logging purposes.
    if sid:
        user.add_sensitive_value_to_be_masked(sid)
    else:
        logger.debug("We did not find a 'sid' entry in the cookies.")

    # Extract the state token from the response.
    state_token = extract_state_token(response.text)
    if state_token:  # TODO: this is not working yet.
        params = {"stateToken": state_token}
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml",
            "content-type": "application/json",
        }
        response = HTTP_client.get(
            # myurl, allow_redirects=False, params={"stateToken": state_token}
            f"{config.okta['org']}/login/token/redirect",
            params=params,
            headers=headers,
        )
        logger.warning(
            f"""
            State token from {url}: {state_token}. TODO: need to go from this state token
            to an idx cookies.
            """
        )


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
        # Note: mfa_challenge should also be modified to accept and use http_client
        session_token = mfa_challenge(config, headers, primary_auth)
    else:
        logger.debug(f"Error parsing response: {json.dumps(primary_auth)}")
        logger.error(f"Okta auth failed: unknown status {status}")
        sys.exit(1)

    user.add_sensitive_value_to_be_masked(session_token)

    return session_token


def get_access_token(oauth2_config, oauth2_session_data, authorize_code):
    """Get OAuth token from Okta by calling /token endpoint.

    This method does not seem to be needed, calling /authorize sets the idx cookies,
    but we put it here to follow the flow vervatim.

    :param url: URL of the Okta OAuth token endpoint
    :return: OAuth token
    """
    try:
        payload = {
            "code": authorize_code,
            "state": oauth2_session_data["state"],
            "grant_type": oauth2_session_data["grant_type"],
            "redirect_uri": oauth2_session_data["redirect_uri"],
            "client_id": oauth2_config["client_id"],
            "code_verifier": oauth2_session_data["code_verifier"],
        }
    except KeyError as e:
        logger.error(f"Missing key in config:{e}")
        sys.exit(1)

    headers = {"accept": "application/json"}
    # Using the http_client to make the POST request
    response = HTTP_client.post(
        oauth2_config["token_endpoint"], data=payload, headers=headers, return_json=True
    )
    # We now have response['access_token'] and response['id_token'], but we dont seem to need
    # them to access the resources.
    access_token = None
    try:
        access_token = response["access_token"]
    except KeyError:
        logger.debug(f"Error parsing response: {json.dumps(response)}")
        # Don't do anything but a debug message, as the /token call doesnt seem to be needed.
    return access_token


def get_enduser_url(url):
    """Retrieve enduser URL.

    :url: Okta URL to retrieve enduser URL from
    :returns: enduser URL or None
    """
    enduser_url = None

    res = HTTP_client.get(url)
    soup = BeautifulSoup(res.text, "html.parser")
    pattern = re.compile(r".*enduser-v.*enduser.*")
    script = soup.find("script", src=pattern)
    if type(script) is bs4.element.Tag:
        logger.debug(f"Found script tag: {script['src']}")
        enduser_url = script["src"]
    return enduser_url


def get_client_id_by_url(url):
    """Retrieve clientId.

    :url: Javascript URL to retrieve clientId from
    :returns: clientId or None
    """
    client_id = None
    enduser_url = get_enduser_url(url)
    if enduser_url:
        res = HTTP_client.get(enduser_url)
        pattern = re.compile(r',clientId:"(?P<clientId>.*?)",')

        match = pattern.search(res.text)
        if match:
            logger.debug(f"Found clientId: {match.group('clientId')}")
            client_id = match.group("clientId")

    return client_id


def get_client_id(config):
    """Get the client id needed by the Authorization Code Flow.

    If a command line parameter was passed, it will take precedence.
    If no command line parameter was passed, it will try to determine it.

    """
    if "client_id" in config.okta and config.okta["client_id"]:
        return config.okta["client_id"]
    else:
        return get_client_id_by_url(config.okta["org"])


def get_redirect_uri(oauth2_url):
    """
    Get the redirect uri needed by the Authorization Code Flow.

    Return url
    """
    uri = f"{oauth2_url}/enduser/callback"
    return uri


def get_response_type():
    """
     We're only implementing code response type.

    So we're only returning "code"
    """
    return "code"


def get_authorize_scope():
    """We're only implementing openid scope.

    So we're only returning "openid", which is ok for what we do.
    """
    return "openid"


def get_oauth2_state():
    """Generate a random string for state."""
    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    return state


def get_pkce_code_challenge_method():
    """
    Return code challenge.

    Only S256 is implemented.
    """
    return "S256"


def get_pkce_code_challenge(code_verifier=None):
    """
    Get PKCE Code Challenge.

    Base64-URL-encoded string of the SHA256 hash of the code verifier
    https://www.oauth.com/oauth2-servers/pkce/authorization-request/

    :param: code_verifier
    :return: code_challenge
    """
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")
    return code_challenge


def get_pkce_code_verifier():
    """
    Get pkce code verifier.

    :return: code_verifier
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
    return code_verifier


def pkce_enabled():
    """
    Check of PKCE is enabled.

    Altho the authorization server config tells us our okta doesnt PKCE enabled, omitting its
    settings will cause the authorize code flow to fail, so we always return True.
    """
    return True


def get_authorize_code(response, session_token):
    """
    Get the authorize code.

    This will exit with error if we cannot get the code.
    It will also check the response from the /authorize call for callback errors,
    And if any, print and exit with error.
    """
    callback_url = response.url
    error_code = re.search(r"(?<=error=)[^&]+", callback_url)
    error_desc = re.search(r"(?<=error_description=)[^&]+", callback_url)
    if error_code:
        error_value = error_code.group()
        if not session_token and error_value == "login_required":
            return (
                None  # if we arent authenticated we wont have sessionToken, so ignore login error.
            )
        else:
            logger.error(f"Oauth2 callback error:{error_value}:{error_desc.group()}")
            logger.debug(f"Response: {response.text}")
            sys.exit(1)
    authorize_code = re.search(r"(?<=code=)[^&]+", callback_url)
    if authorize_code:
        return authorize_code.group()


def authorization_code_enabled(oauth2_config):
    """
    Determine if authorization code grant is enabled.

    Returns True if the dict key is in authorization server info, and False otherwise,
    """
    if "org" not in oauth2_config:
        logger.error(f"No org in config:{oauth2_config}")
        sys.exit(1)
    try:
        if "authorization_code" not in oauth2_config["grant_types_supported"]:
            return False
    except (KeyError, ValueError) as e:
        logger.error(f"No grant types supported on {oauth2_config['org']}:{str(e)}")
        sys.exit(1)
    return True


def authorize_request(oauth2_config, oauth2_session_data):
    """
    Call /authorize endpoint.

    :param
    :return: authorization code, needed for /token call
    """
    logger.debug(f"oauth_code_request({oauth2_config}, {oauth2_session_data})")
    headers = {"accept": "application/json", "content-type": "application/json"}

    session_token = HTTP_client.session.cookies.get("sessionToken")

    try:
        payload = {
            "client_id": oauth2_config["client_id"],
            "redirect_uri": oauth2_session_data["redirect_uri"],
            "response_type": oauth2_session_data["response_type"],
            "scope": oauth2_session_data["scope"],
            "state": oauth2_session_data["state"],
            "code_challenge": oauth2_session_data["code_challenge"],
            "code_challenge_method": oauth2_session_data["code_challenge_method"],
            "prompt": "none",  # dont authenticate
            "sessionToken": session_token,
        }
    except KeyError as e:
        logger.error(f"Missing key in config:{e}")
        sys.exit(1)

    response = HTTP_client.get(
        oauth2_config["authorization_endpoint"],
        headers=headers,
        params=payload,
    )

    authorize_code = get_authorize_code(response, session_token)
    return authorize_code


def generate_oauth2_session_data(url):
    """
    Generate some oauth2 session data.

    We do this to have the same in oath2 cookies and /authorize call.
    """
    authz_session_data = {
        "response_type": get_response_type(),
        "scope": get_authorize_scope(),
        "state": get_oauth2_state(),
        "redirect_uri": get_redirect_uri(url),
        "grant_type": "authorization_code",
    }
    if pkce_enabled():
        code_verifier = get_pkce_code_verifier()
        authz_session_data["code_verifier"] = code_verifier
        authz_session_data["code_challenge"] = get_pkce_code_challenge(code_verifier)
        authz_session_data["code_challenge_method"] = get_pkce_code_challenge_method()

    return authz_session_data


def get_oauth2_configuration(config):
    """Get authorization server configuration data from Okta instance.

    :param url: URL of the Okta org
    :return: dict of conguration values
    """
    url = f"{config.okta['org']}/.well-known/oauth-authorization-server"
    headers = {"accept": "application/json"}
    response = HTTP_client.get(url, headers=headers)
    logger.debug(f"Authorization Server info: {response.json()}")
    # todo: handle errors.n
    oauth2_config = response.json()
    oauth2_config["org"] = config.okta["org"]
    oauth2_config["client_id"] = get_client_id(config)
    validate_oauth2_configuration(oauth2_config)
    return oauth2_config


def validate_oauth2_configuration(oauth2_config):
    """
    Validate that the oauth2 configuration has our implementation.

    Will exit with error if a mandatory config is missing.
    :param oauth2_config: dict of configuration values
    """
    mandadory_oauth2_config_items = {
        "authorization_endpoint",
        "token_endpoint",
        "grant_types_supported",
        "response_types_supported",
        "scopes_supported",
        "client_id",
        "org",
    }  # the authorization server must have these config elements
    for item in mandadory_oauth2_config_items:
        if item not in oauth2_config:
            logger.error(f"No {item} found in oauth2 configuration.")
            sys.exit(1)

    if "authorization_code" not in oauth2_config["grant_types_supported"]:
        logger.error("Authorization code grant not found.")
        sys.exit(1)
    if "code" not in oauth2_config["response_types_supported"]:
        logger.error("Code response type not found.")
        sys.exit(1)


def create_authn_cookies(authn_org_url, session_token):
    """
    Create session cookie.

    :param authn_org_url: org url
    :param session_token: session token, str
    :returns: cookies jar with session_id value we got using the token
    """
    # Construct the URL from the base URL provided.
    url = f"{authn_org_url}/api/v1/sessions"

    # Define the payload and headers for the request.
    data = {"sessionToken": session_token}
    headers = {"Content-Type": "application/json", "accept": "application/json"}

    # Log the request details.
    logger.debug(f"Requesting session cookies from {url}")

    # Use the HTTP client to make a POST request.
    response_json = HTTP_client.post(url, json=data, headers=headers, return_json=True)

    if "id" not in response_json:
        logger.error(f"'id' not found in response. Full response: {response_json}")
        sys.exit(1)
    session_id = response_json["id"]
    user.add_sensitive_value_to_be_masked(session_id)

    cookiejar = requests.cookies.RequestsCookieJar()
    domain = urlparse(url).netloc
    cookiejar.set("sid", session_id, domain=urlparse(url).netloc, path="/")
    cookiejar.set("sessionToken", session_token, domain=domain, path="/")
    HTTP_client.add_cookies(cookiejar)  # add cookies


def idp_authenticate(config):
    """Authenticate user to okta."""
    auth_properties = get_auth_properties(userid=config.okta["username"], url=config.okta["org"])

    if "type" not in auth_properties:
        logger.error("Okta auth failed: unknown type.")
        sys.exit(1)

    auth_properties = get_auth_properties(userid=config.okta["username"], url=config.okta["org"])

    if "type" not in auth_properties:
        logger.error("Okta auth failed: unknown type.")
        sys.exit(1)

    if is_saml2_authentication(auth_properties):
        # We may loop thru the saml2 servers until
        # we find the authentication server.
        saml2_authenticate(config, auth_properties)
    elif local_authentication_enabled(auth_properties):
        session_token = local_authenticate(config)
        # authentication sends us a token
        # which we then put in our session cookies
        create_authn_cookies(config.okta["org"], session_token)
    else:
        logger.error(f"{auth_properties['type']} login via IdP Discovery is not curretly supported")
        sys.exit(1)


def access_control(config):
    """Authenticate and authorize with the IDP.

    if OIE is enabled and a client_id is found,run Authorization code flow and PKCE being
    the only implemented grant types.

    Okta uses cookies to manage sessions.

    :param config: Config object
    """
    logger.debug(f"access_control({config})")

    oauth2_config = None
    oauth2_session_data = None

    is_oie = oie_enabled(config.okta["org"])
    # We set the oauth2 data (variables and cookies) that will be used at /authorize and during
    # saml2 for chained orgs.
    if is_oie:
        logger.debug("OIE enabled")
        # save some oauth2 config data + create session data, and create authz cookies
        oauth2_config = get_oauth2_configuration(config)
        oauth2_session_data = generate_oauth2_session_data(config.okta["org"])
        create_authz_cookies(oauth2_config, oauth2_session_data)
        # The flow says to initially call /authorize here, but that doesnt do anything...
        # idp_authorize(oauth2_config, oauth2_session_data)

    idp_authenticate(config)

    if is_oie:
        # call /authorize . Note: we are authenticated.
        idp_authorize(oauth2_config, oauth2_session_data)


def idp_authorize(oauth2_config, oauth2_session_data):
    """
    Authorize on the okta authorization server.

    If we arent authenticated, we will still call /authorize but won't get a code.
    When we are authenticated, we get an idx cookies and dont need to do anything else.
    """
    if "client_id" not in oauth2_config or not oauth2_config["client_id"]:
        logger.error("We are calling /authorize without a client_id")
        sys.exit(1)

    if authorization_code_enabled(oauth2_config):
        authorize_code = authorize_request(oauth2_config, oauth2_session_data)
        # The following get_access_token does not seem to matter, the /authorize call above sets
        # the idx cookies and we're done. We put it here in an attempt to follow the flow verbatim.
        if authorize_code:  # We got value if we were authenticated.
            get_access_token(oauth2_config, oauth2_session_data, authorize_code)


def step_up_authenticate(config, state_token):
    """Try to step up authenticate the user. Only supported for local auth.

    :param config: Configuration object
    :param state_token: The state token
    :return: True if step up authentication was successful; False otherwise
    """
    auth_properties = get_auth_properties(userid=config.okta["username"], url=config.okta["org"])
    if "type" not in auth_properties or not local_authentication_enabled(auth_properties):
        return False

    headers = {"content-type": "application/json", "accept": "application/json"}
    payload = {"stateToken": state_token}

    auth = HTTP_client.post(
        f"{config.okta['org']}/api/v1/authn", json=payload, headers=headers, return_json=True
    )

    status = auth.get("status", None)
    if status == "SUCCESS":
        return True
    elif status == "MFA_REQUIRED":
        mfa_challenge(config, headers, auth)
        return True

    logger.error("Okta auth failed: unknown status for step up authentication.")
    return False


def saml2_authenticate(config, auth_properties):
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
    idp_authenticate(saml2_config)

    # Once we are authenticated, send the SAML request to the IdP.
    # This call requires session cookies.
    saml_response = send_saml_request(saml_request)

    # Send SAML response from the IdP back to the SP, which will generate new
    # session cookies.
    send_saml_response(config, saml_response)


def oie_enabled(url):
    """
    Determine if OIE is enabled.

    :pamam url: okta org url
    :return: True if OIE is enabled, False otherwise
    """
    if get_auth_pipeline(url) == "idx":  # oie
        return True
    else:
        return False


def local_authenticate(config):
    """Authenticate user on local okta instance.

    :param config: Config object
    :return: authn token
    """
    session_token = None
    headers = {"content-type": "application/json", "accept": "application/json"}
    payload = {"username": config.okta["username"], "password": config.okta["password"]}

    logger.debug(f"Authenticate user to {config.okta['org']}/api/v1/authn")
    logger.debug(f"Sending {headers}, {payload} to {config.okta['org']}/api/vi/authn")

    primary_auth = HTTP_client.post(
        f"{config.okta['org']}/api/v1/authn",
        json=payload,
        headers=headers,
        return_json=True,
    )

    if "errorCode" in primary_auth:
        api_error_code_parser(primary_auth["errorCode"])
        sys.exit(1)

    while session_token is None:
        session_token = get_session_token(config, primary_auth, headers)
    logger.info(f"User has been successfully authenticated to {config.okta['org']}.")
    return session_token


def local_authentication_enabled(auth_properties):
    """Check whether authentication happens on the current instance.

    :param auth_properties: auth_properties dict
    :return: True if this is the place to authenticate, False otherwise.
    """
    try:
        if auth_properties["type"] == "OKTA":
            return True
    except (TypeError, KeyError):
        pass
    return False


def is_saml2_authentication(auth_properties):
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

    script = soup.find("script", string=pattern)
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
        mfa_verify = duo.authenticate(selected_factor)
        headers = {"content-type": "application/json", "accept": "application/json"}
        mfa_verify = HTTP_client.post(
            mfa_challenge_url, json=payload, headers=headers, return_json=True
        )

    elif mfa_provider == "OKTA" and factor_type == "push":
        mfa_verify = push_approval(mfa_challenge_url, payload)
    elif mfa_provider in ["OKTA", "GOOGLE"] and factor_type in ["token:software:totp", "sms"]:
        mfa_verify = totp_approval(
            config, selected_mfa_option, headers, mfa_challenge_url, payload, primary_auth
        )
    else:
        logger.error(
            f"Sorry, the MFA provider '{mfa_provider}:{factor_type}' is not yet supported."
            " Please retry with another option."
        )
        sys.exit(1)

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

    available_mfas = [f"{d['provider']}_{d['factorType']}_{d['id']}" for d in mfa_options]
    index = mfa_index(preset_mfa, available_mfas, mfa_options)

    selected_mfa_option = mfa_options[index]
    logger.debug(f"Selected MFA is [{selected_mfa_option}]")

    mfa_challenge_url = selected_mfa_option["_links"]["verify"]["href"]

    payload = {
        "stateToken": primary_auth["stateToken"],
        "factorType": selected_mfa_option["factorType"],
        "provider": selected_mfa_option["provider"],
        "profile": selected_mfa_option["profile"],
    }

    selected_factor = HTTP_client.post(
        mfa_challenge_url, json=payload, headers=headers, return_json=True
    )

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

    logger.debug(f"MFA Session Token: [{mfa_session_token}]")
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

    # Using the http_client to make the POST request
    mfa_verify = HTTP_client.post(
        mfa_challenge_url, json=payload, headers=headers, return_json=True
    )

    if "sessionToken" in mfa_verify:
        user.add_sensitive_value_to_be_masked(mfa_verify["sessionToken"])
    logger.debug(f"mfa_verify [{json.dumps(mfa_verify)}]")

    # Clear out any MFA response since it is no longer valid
    config.okta["mfa_response"] = None

    return mfa_verify


def push_approval(mfa_challenge_url, payload):
    """Handle push approval from the user.

    :param mfa_challenge_url: MFA challenge url
    :param payload: payload which needs to be sent
    :return: Session Token if succeeded or terminates if user wait goes 5 min

    """
    logger.debug(f"Push approval with challenge_url:{mfa_challenge_url}")

    user.print("Waiting for an approval from the device...")
    status = "MFA_CHALLENGE"
    result = "WAITING"
    response = {}
    challenge_displayed = False

    headers = {"content-type": "application/json", "accept": "application/json"}

    while status == "MFA_CHALLENGE" and result == "WAITING":
        response = HTTP_client.post(
            mfa_challenge_url, json=payload, headers=headers, return_json=True
        )

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
