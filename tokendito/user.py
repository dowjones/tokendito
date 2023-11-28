# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Helper module for AWS and Okta configuration, management and data flow."""
import argparse
import builtins
import codecs
import configparser
from datetime import timezone
from getpass import getpass
import json
import logging
import os
from pathlib import Path
from pkgutil import iter_modules
import platform
import re
import sys
from urllib.parse import urlparse

from botocore import __version__ as __botocore_version__
from bs4 import __version__ as __bs4_version__  # type: ignore (bs4 does not have PEP 561 support)
from bs4 import BeautifulSoup
import requests
from tokendito import __version__
from tokendito import aws
from tokendito import okta
from tokendito.config import Config
from tokendito.config import config
from tokendito.http_client import HTTP_client

# Unfortunately, readline is only available in non-Windows systems. There is no substitution.
try:
    import readline  # noqa: F401
except ModuleNotFoundError:
    pass

logger = logging.getLogger(__name__)

mask_items = []


def cmd_interface(args):
    """Tokendito retrieves AWS credentials after authenticating with Okta."""
    args = parse_cli_args(args)

    # Early logging, in case the user requests debugging via env/CLI
    setup_early_logging(args)

    # Set some required initial values
    process_options(args)

    # Late logging (default)
    setup_logging(config.user)

    # Validate configuration
    message = validate_configuration(config)
    if message:
        quiet_msg = ""
        if config.user["quiet"] is not False:
            quiet_msg = " to run in quiet mode"
        logger.error(
            f"Could not validate configuration{quiet_msg}: {'. '.join(message)}. "
            "Please check your settings, and try again."
        )
        sys.exit(1)

    if config.user["use_device_token"]:
        device_token = config.okta["device_token"]
        if device_token:
            HTTP_client.set_device_token(config.okta["org"], device_token)
        else:
            logger.warning(
                f"Device token unavailable for config profile {args.user_config_profile}. "
                "May see multiple MFA requests this time."
            )

    # get authentication and authorization cookies from okta
    okta.access_control(config)
    logger.debug(
        f"""
        about to call discover_tile
        we have client cookies: {HTTP_client.session.cookies}
        """
    )
    if config.okta["tile"]:
        tile_label = ""
        config.okta["tile"] = (config.okta["tile"], tile_label)
    else:
        config.okta["tile"] = discover_tiles(config.okta["org"])

    # Authenticate to AWS roles
    auth_tiles = aws.authenticate_to_roles(config, config.okta["tile"])

    (role_response, role_name) = aws.select_assumeable_role(auth_tiles)

    identity = aws.assert_credentials(role_response=role_response)
    if "Arn" not in identity and "UserId" not in identity:
        logger.error(
            f"There was an error retrieving and verifying AWS credentials: {role_response}"
        )
        sys.exit(1)

    set_profile_name(config, role_name)

    set_local_credentials(
        response=role_response,
        role=config.aws["profile"],
        region=config.aws["region"],
        output=config.aws["output"],
    )

    device_token = HTTP_client.get_device_token()
    if config.user["use_device_token"] and device_token:
        logger.info(f"Saving device token to config profile {args.user_config_profile}")
        config.okta["device_token"] = device_token
        update_device_token(config)

    display_selected_role(profile_name=config.aws["profile"], role_response=role_response)


class MaskLoggerSecret(logging.Filter):
    """Masks secrets in logger messages."""

    def __init__(self):
        """Initialize filter."""
        logging.Filter.__init__(self)

    def filter(self, record):
        """Apply filter on logger messages."""
        for secret in mask_items:
            if not isinstance(secret, str):
                secret = str(secret)
            if not isinstance(record.msg, str):
                record.msg = str(record.msg)
            record.msg = record.msg.replace(secret, "*****")
        return True


def parse_cli_args(args):
    """Parse command line arguments.

    :return: args parse object
    """
    parser = argparse.ArgumentParser(
        prog="tokendito", description="Gets an STS token to use with the AWS CLI and SDK."
    )
    parser.add_argument("--version", action="store_true", help="Displays version and exit")
    parser.add_argument(
        "--configure",
        action="store_true",
        help="Prompt user for configuration parameters",
    )
    parser.add_argument(
        "--username",
        dest="okta_username",
        help="username to log in to Okta. You can "
        "also use the TOKENDITO_OKTA_USERNAME environment variable.",
    )
    parser.add_argument(
        "--password",
        dest="okta_password",
        help="password to log in to Okta. You "
        "can also use the TOKENDITO_OKTA_PASSWORD environment variable.",
    )
    parser.add_argument(
        "--profile",
        dest="user_config_profile",
        default=config.user["config_profile"],
        help="Tokendito configuration profile to use.",
    )
    parser.add_argument(
        "--config-file",
        dest="user_config_file",
        default=config.user["config_file"],
        help=f"Use an alternative configuration file. Defaults to {config.user['config_file']}",
    )
    parser.add_argument(
        "--loglevel",
        "-l",
        type=lambda s: s.upper(),
        dest="user_loglevel",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="[DEBUG|INFO|WARN|ERROR], default loglevel is WARNING.",
    )
    parser.add_argument(
        "--log-output-file",
        dest="user_log_output_file",
        help="Optional file to log output to.",
    )
    parser.add_argument("--aws-config-file", help="AWS Configuration file to write to.")
    parser.add_argument(
        "--aws-output",
        help="Sets the output type for the AWS profile.",
    )
    parser.add_argument(
        "--aws-profile",
        help="AWS profile to save as in the credentials file.",
    )
    parser.add_argument(
        "--aws-region",
        help="Sets the region for the AWS profile.",
    )
    parser.add_argument("--aws-role-arn", help="Sets the IAM role.")
    parser.add_argument("--aws-shared-credentials-file", help="AWS credentials file to write to.")

    okta_me_group = parser.add_mutually_exclusive_group()
    okta_me_group.add_argument(
        "--okta-org",
        dest="okta_org",
        help="Set the Okta Org base URL. This enables role auto-discovery",
    )
    okta_me_group.add_argument(
        "--okta-tile",
        help="Okta tile URL to use.",
    )
    parser.add_argument(
        "--okta-client-id",
        help="""For OIE enabled Orgs this sets the Okta client ID to replace the value
        found by tokendito. It is used in the authorize code flow.""",
    )
    parser.add_argument(
        "--okta-mfa",
        help="Sets the MFA method. You "
        "can also use the TOKENDITO_OKTA_MFA environment variable.",
    )
    parser.add_argument(
        "--okta-mfa-response",
        help="Sets the MFA response to a challenge. You "
        "can also use the TOKENDITO_OKTA_MFA_RESPONSE environment variable.",
    )
    parser.add_argument(
        "--use-device-token",
        dest="user_use_device_token",
        action="store_true",
        default=False,
        help="Use device token across sessions",
    )
    parser.add_argument(
        "--quiet",
        dest="user_quiet",
        action="store_true",
        default=False,
        help="Suppress output",
    )

    parsed_args = parser.parse_args(args)

    return parsed_args


def utc_to_local(utc_dt):
    """Convert UTC time into local time.

    :param:utc_str:datetime
    :return:local_time:string
    """
    try:
        local_time = utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)
        local_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z")
    except TypeError as err:
        logger.error(f"Could not convert time: {err}")
        sys.exit(1)
    return local_time


def create_directory(dir_name):
    """Create directories on the local machine."""
    if os.path.isdir(dir_name) is False:
        try:
            os.makedirs(dir_name, exist_ok=True)
        except OSError as error:
            logger.error(f"Cannot continue creating directory: {dir_name}: {error.strerror}")
            sys.exit(1)


def get_submodule_names():
    """Inspect the current module and find any submodules.

    :return: List of submodule names

    """
    package = Path(__file__).resolve(strict=True)
    submodules = [x.name for x in iter_modules([str(package.parent)])]
    return submodules


def setup_early_logging(args):
    """Do a best-effort attempt to enable early logging.

    :param args: list of arguments to parse
    :return: dict with values set
    """
    # Get some sane defaults
    early_logging = config.get_defaults()["user"].copy()

    if "TOKENDITO_USER_LOGLEVEL" in os.environ:
        early_logging["loglevel"] = os.environ["TOKENDITO_USER_LOGLEVEL"]
    if "TOKENDITO_USER_LOG_OUTPUT_FILE" in os.environ:
        early_logging["log_output_file"] = os.environ["TOKENDITO_USER_LOG_OUTPUT_FILE"]

    if "user_loglevel" in args and args.user_loglevel:
        early_logging["loglevel"] = args.user_loglevel
    if "user_log_output_file" in args and args.user_log_output_file:
        early_logging["log_output_file"] = args.user_log_output_file

    setup_logging(early_logging)
    return early_logging


def setup_logging(conf):
    """Set logging level.

    :param conf: dictionary with config
    :return: loglevel name
    """
    root_logger = logging.getLogger()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s |%(name)s %(funcName)s():%(lineno)i| %(message)s"
    )
    handler = logging.StreamHandler()

    if "log_output_file" in conf and conf["log_output_file"]:
        handler = logging.FileHandler(conf["log_output_file"])
    handler.setFormatter(formatter)

    # Set a reasonable default logging format.
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.addFilter(MaskLoggerSecret())

    # Pre-create a log handler for each submodule
    # with the same format and level. Settings are
    # inherited from the root logger.
    submodules = [f"tokendito.{x}" for x in get_submodule_names()]
    if "loglevel" in conf:
        conf["loglevel"] = conf["loglevel"].upper()
        for submodule in submodules:
            submodule_logger = logging.getLogger(submodule)
            submodule_logger.addFilter(MaskLoggerSecret())
            try:
                submodule_logger.setLevel(conf["loglevel"])
            except ValueError as err:
                root_logger.setLevel(config.get_defaults()["user"]["loglevel"])
                submodule_logger.warning(f"{err}. Plese check your configuration and try again.")
                break
    loglevel = logging.getLogger(submodules[0]).getEffectiveLevel()
    return loglevel


def print(args):
    """Print only if not in quiet mode. Does not affect logging."""
    if config.user["quiet"] is not True:
        builtins.print(args)
    return args


def select_role_arn(authenticated_tiles):
    """Select the role user wants to pick.

    :param: authenticated_tiles, mapping of authenticated tiles metadata, dict
    :return: user role and associated url, tuple
    """
    selected_role = None

    for url, tile in authenticated_tiles.items():
        logger.debug(f"Select the role user wants to pick [{tile['roles']}]")
        role_names = dict((role.split("/")[-1], role) for role in tile["roles"])
        roles = [role.split("/")[-1] for role in tile["roles"]]

        if roles.count(config.aws["profile"]) > 1:
            logger.error(
                "There are multiple matches for the profile selected, "
                "please use the --aws-role-arn option to select one"
            )
            sys.exit(2)

        if config.aws["profile"] in role_names.keys():
            selected_role = (role_names[config.aws["profile"]], url)
            logger.debug(f"Using aws_profile env var for role: [{config.aws['profile']}]")
            break
        elif config.aws["role_arn"] in tile["roles"]:
            selected_role = (config.aws["role_arn"], url)
            break

    if selected_role is None:
        if config.aws["role_arn"] is None:
            selected_role = prompt_role_choices(authenticated_tiles)
        else:
            logger.error(f"User provided rolename does not exist [{config.aws['role_arn']}]")
            sys.exit(2)

    logger.debug(f"Selected role: [{selected_role}]")

    return selected_role


def factor_type_info(factor_type, mfa_option):
    """Get factor info from okta reply.

    :param factor_type: mfa
    :param mfa_option: mfa_option
    :return: info about mfa
    """
    logger.debug("Choose factor info depending on factor type.")
    factor_info = "Not Presented"
    default_value = "Unknown"

    if factor_type in ["token", "token:software:totp", "token:hardware"]:
        factor_info = mfa_option.get("profile").get("credentialId", default_value)
    elif factor_type == "push":
        factor_info = mfa_option.get("profile").get("name", default_value)
    elif factor_type == "sms" or factor_type == "call":
        factor_info = mfa_option.get("profile").get("phoneNumber", default_value)
    elif factor_type == "webauthn":
        factor_info = mfa_option.get("profile").get("authenticatorName", default_value)
    elif factor_type in ["web", "u2f", "token:hotp"]:
        factor_info = mfa_option.get("vendorName", default_value)
    elif factor_type == "question":
        factor_info = mfa_option.get("profile").get("question", default_value)
    elif factor_type == "email":
        factor_info = mfa_option.get("profile").get("email", default_value)

    # We return the string representation of the value retrieved. There are cases where
    # .get() will retrieve `None` as a value (this is somehow valid). When that happens,
    # the caller function cannot sort the list of values.
    return str(factor_info)


def mfa_option_info(mfa_option):
    """Build an optional string with the MFA factor information.

    :param mfa_option: dictionary with a single MFA response.
    :return: pre-formatted string with MFA factor info if available, None
             otherwise.
    """
    logger.debug(f"Building info for: {json.dumps(mfa_option)}")
    factor_info = "Not Presented"
    if "factorType" in mfa_option:
        factor_type = mfa_option["factorType"]
        factor_info = factor_type_info(factor_type, mfa_option)
    return factor_info


def select_preferred_mfa_index(mfa_options, factor_key="provider", subfactor_key="factorType"):
    """Show all the MFA options to the users.

    :param mfa_options: List of available MFA options
    :return: MFA option selected index by the user from the output
    """
    logger.debug("Show all the MFA options to the users.")
    logger.debug(json.dumps(mfa_options))
    print("\nSelect your preferred MFA method and press Enter:")

    longest_index = len(str(len(mfa_options)))
    longest_factor_name = max([len(d[factor_key]) for d in mfa_options])
    longest_subfactor_name = max([len(d[subfactor_key]) for d in mfa_options])
    factor_info_indent = max([len(mfa_option_info(d)) for d in mfa_options])

    for i, mfa_option in enumerate(mfa_options):
        factor_id = mfa_option.get("id", "Not presented")
        factor_info = mfa_option_info(mfa_option)
        mfa = mfa_option.get(subfactor_key, "Not presented")
        provider = mfa_option.get(factor_key, "Not presented")
        print(
            f"[{i: >{longest_index}}]  "
            f"{provider: <{longest_factor_name}}  "
            f"{mfa: <{longest_subfactor_name}} "
            f"{factor_info: <{factor_info_indent}} "
            f"Id: {factor_id}"
        )

    user_input = collect_integer(len(mfa_options))

    return user_input


def prompt_role_choices(aut_tiles):
    """Ask user to select role.

    :param aut_tiles: mapping of authenticated tiles metadata, dict
    :return: user's role and associated url, tuple
    """
    aliases_mapping = []

    for url, tile in aut_tiles.items():
        logger.debug(f"Getting aliases for {url}")
        alias_table = get_account_aliases(tile["saml"], tile["saml_response_string"])

        for role in tile["roles"]:
            if alias_table:
                aliases_mapping.append((tile["label"], alias_table[role.split(":")[4]], role, url))
            else:
                logger.debug(f"There were no labels in {url}. Using account ID")
                aliases_mapping.append((tile["label"], role.split(":")[4], role, url))

    logger.debug("Ask user to select role")
    print("\nPlease select one of the following:")

    longest_alias = max(len(i[1]) for i in aliases_mapping)
    longest_index = len(str(len(aliases_mapping)))
    aliases_mapping = sorted(aliases_mapping)
    print_label = ""

    for i, data in enumerate(aliases_mapping):
        label, alias, role, _ = data
        padding_index = longest_index - len(str(i))
        if print_label != label:
            print_label = label
            print(f"\n{label}:")

        print(f"[{i}] {padding_index * ' '}" f"{alias: <{longest_alias}}  {role}")

    user_input = collect_integer(len(aliases_mapping))
    selected_role = (aliases_mapping[user_input][2], aliases_mapping[user_input][3])
    logger.debug(f"Selected role [{user_input}]")

    return selected_role


def display_selected_role(profile_name="", role_response={}):
    """Print details about how to assume role.

    :param profile_name: AWS profile name
    :param role_response: Assume Role response dict
    :return: message displayed.

    """
    try:
        expiration_time = role_response["Credentials"]["Expiration"]
    except (KeyError, TypeError) as err:
        logger.error(f"Could not retrieve expiration time: {err}")
        sys.exit(1)

    expiration_time_local = utc_to_local(expiration_time)
    msg = (
        f"\nGenerated profile '{profile_name}' in "
        f"{config.aws['shared_credentials_file']}.\n"
        "\nUse profile to authenticate to AWS:\n\t"
        f"aws --profile '{profile_name}' sts get-caller-identity"
        "\nOR\n\t"
        f"export AWS_PROFILE='{profile_name}'\n\n"
        f"Credentials are valid until {expiration_time} ({expiration_time_local})."
    )

    print(msg)
    return msg


def extract_arns(saml):
    """Extract arns from SAML decoded xml.

    :param saml: results saml decoded
    :return: Dict of Role and Provider ARNs
    """
    logger.debug("Decode response string as a SAML decoded value.")

    roles_and_providers = {}
    arn_regex = ">(arn:aws:iam::.*?,arn:aws:iam::.*?)<"

    # find all provider and role pairs.
    arns = re.findall(arn_regex, saml)
    logger.debug(f"found ARNs: {arns}")

    # stuff into dict, role is dict key.
    if arns:
        roles_and_providers = {i.split(",")[1]: i.split(",")[0] for i in arns}

    logger.debug(f"Collected ARNs: {roles_and_providers}")

    return roles_and_providers


def validate_okta_org(input_url=None):
    """Validate whether a given URL is a valid AWS Org URL in Okta.

    :param input_url: string
    :return: bool. True if valid, False otherwise
    """
    logger.debug(f"Will try to match '{input_url}' to a valid URL")

    url = urlparse(input_url)
    logger.debug(f"URL parsed as {url}")
    if (
        url.scheme == "https"
        and (url.path == "" or url.path == "/")
        and url.params == ""
        and url.query == ""
        and url.fragment == ""
    ):
        return True

    logger.debug(f"{url} does not look like a valid match.")
    return False


def validate_okta_tile(input_url=None):
    """Validate whether a given URL is a valid AWS tile URL in Okta.

    :param input_url: string
    :return: bool. True if valid, False otherwise
    """
    logger.debug(f"Will try to match '{input_url}' to a valid URL")

    url = urlparse(input_url)
    logger.debug(f"URL parsed as {url}")
    # Here, we could also check url.netloc against r'.*\.okta(preview)?\.com$'
    # but Okta allows the usage of custome URLs such as login.acme.com
    if (
        url.scheme == "https"
        and re.match(r"^/home/amazon_aws/\w{20}/\d{3}$", str(url.path)) is not None
    ):
        return True

    logger.debug(f"{url} does not look like a valid match.")
    return False


def get_account_aliases(saml_xml, saml_response_string):
    """Parse AWS SAML page for account aliases.

    :param saml_xml: Decoded saml response from Okta
    :param saml_response_string response from Okta with saml data:
    :return: mapping table of account ids to their aliases
    """
    soup = BeautifulSoup(saml_response_string, "html.parser")
    form = soup.find("form")
    action = form.get("action")  # type: ignore (bs4 does not have PEP 561 support)
    url = str(action)

    encoded_xml = codecs.encode(saml_xml.encode("utf-8"), "base64")
    aws_response = None
    try:
        aws_response = HTTP_client.post(url, data={"SAMLResponse": encoded_xml})
    except Exception as request_error:
        logger.error(f"There was an error retrieving the AWS SAML page: \n{request_error}")
        logger.debug(json.dumps(aws_response))
        sys.exit(1)

    if "Account: " not in aws_response.text:
        logger.debug("No labels found")
        logger.debug(json.dumps(aws_response.text))
        return None

    soup = BeautifulSoup(aws_response.text, "html.parser")
    account_names = soup.find_all(text=re.compile("Account:"))
    alias_table = {str(i.split(" ")[-1]).strip("()"): i.split(" ")[1] for i in account_names}

    return alias_table


def display_version():
    """Print program version and exit."""
    python_version = platform.python_version()
    (system, _, release, _, _, _) = platform.uname()
    logger.debug(f"Display version: {__version__}")
    print(
        f"tokendito/{__version__} "
        f"Python/{python_version} "
        f"{system}/{release} "
        f"botocore/{__botocore_version__} "
        f"bs4/{__bs4_version__} "
        f"requests/{requests.__version__}"
    )


def add_sensitive_value_to_be_masked(value, key=None):
    """Add value to be masked from the logs."""
    """If a key is passed only add it if the key refers to a secret element."""
    sensitive_keys = ("password", "mfa_response", "sessionToken")
    if key is None or key in sensitive_keys:
        mask_items.append(value)


def process_ini_file(file, profile):
    """Process options from a ConfigParser ini file.

    :param file: filename
    :param profile: profile to read
    :return: Config object with configuration values
    """
    res = dict()
    pattern = re.compile(r"^(.*?)_(.*)")

    ini = configparser.RawConfigParser(default_section=config.user["config_profile"])
    # Here, group(1) is the dictionary key, and group(2) the configuration element
    try:
        ini.read(file)
        for key, val in ini.items(profile):
            match = re.search(pattern, key.lower())
            if match:
                if match.group(1) not in res:
                    res[match.group(1)] = dict()
                res[match.group(1)][match.group(2)] = val
                add_sensitive_value_to_be_masked(val, match.group(2))
    except configparser.Error as err:
        logger.error(f"Could not load profile '{profile}': {str(err)}")
        sys.exit(2)
    logger.debug(f"Found ini directives: {res}")

    try:
        config_ini = Config(**res)

    except (AttributeError, KeyError, ValueError) as err:
        logger.error(
            f"The configuration file {file} in [{profile}] is incorrect: {err}"
            ". Please check your settings and try again."
        )
        sys.exit(1)
    return config_ini


def process_arguments(args):
    """Process command-line arguments.

    :param args: argparse object
    :return: Config object with configuration values
    """
    res = dict()
    pattern = re.compile(r"^(.*?)_(.*)")

    for key, val in vars(args).items():
        match = re.search(pattern, key.lower())
        if match:
            if match.group(1) not in get_submodule_names():
                continue
            if match.group(1) not in res:
                res[match.group(1)] = dict()
            if val:
                res[match.group(1)][match.group(2)] = val
                add_sensitive_value_to_be_masked(val, match.group(2))
    logger.debug(f"Found arguments: {res}")

    try:
        config_args = Config(**res)

    except (AttributeError, KeyError, ValueError) as err:
        logger.error(
            f"Command line arguments not correct: {err}"
            ". This should not happen, please contact the package maintainers."
        )
        sys.exit(1)
    return config_args


def process_environment(prefix="tokendito"):
    """Process environment variables.

    :return: Config object with configuration values.
    """
    res = dict()
    pattern = re.compile(rf"^({prefix})_(.*?)_(.*)")
    # Here, group(1) is the prefix variable, group(2) is the dictionary key,
    # and group(3) the configuration element.
    for key, val in os.environ.items():
        match = re.search(pattern, key.lower())
        if match:
            if match.group(2) not in res:
                res[match.group(2)] = dict()
            if val:
                res[match.group(2)][match.group(3)] = val
                add_sensitive_value_to_be_masked(val, match.group(3))
    logger.debug(f"Found environment variables: {res}")

    try:
        config_env = Config(**res)

    except (AttributeError, KeyError, ValueError) as err:
        logger.error(
            f"The environment variables are incorrectly set: {err}"
            ". Please check your settings and try again."
        )
        sys.exit(1)
    return config_env


def process_interactive_input(config, skip_password=False):
    """
    Request input interactively interactively for elements that are not proesent.

    :param config: Config object with some values set.
    :param skip_password: Whether or not ask the user for a password.
    :returns: Config object with necessary values set.
    """
    # Return quickly if the user attempts to run in quiet (non-interactive) mode.
    if config.user["quiet"] is True:
        logger.debug(f"Skipping interactive config: quiet mode is {config.user['quiet']}")
        return config

    # Reuse interactive config. It will only request the portions needed.
    try:
        details = get_interactive_config(
            tile=config.okta["tile"],
            org=config.okta["org"],
            username=config.okta["username"],
        )
    except (AttributeError, KeyError, ValueError) as err:
        logger.error(f"Interactive arguments are not correct: {err}")
        sys.exit(1)

    # Create a dict that can be passed to Config later
    res = dict(okta=dict())
    # Copy the values set by get_interactive_config
    if "okta_tile" in details:
        res["okta"]["tile"] = details["okta_tile"]
    if "okta_org" in details:
        res["okta"]["org"] = details["okta_org"]
    if "okta_username" in details:
        res["okta"]["username"] = details["okta_username"]

    if ("password" not in config.okta or config.okta["password"] == "") and not skip_password:
        logger.debug("No password set, will try to get one interactively")
        res["okta"]["password"] = get_password()
        add_sensitive_value_to_be_masked(res["okta"]["password"])

    config_int = Config(**res)
    logger.debug(f"Interactive configuration is: {config_int}")
    config.update(config_int)
    return config_int


def get_interactive_config(tile=None, org=None, username=""):
    """Obtain user input from the user.

    :return: dictionary with values
    """
    logger.debug("Obtain user input for the user.")
    details = {}

    # We need either one of these two:
    while not validate_okta_org(org) and not validate_okta_tile(tile):
        org = get_org()
        tile = get_tile()

    while username == "":
        username = get_username()

    if org is not None:
        details["okta_org"] = org
    if tile is not None:
        details["okta_tile"] = tile
    details["okta_username"] = username

    logger.debug(f"Details: {details}")
    return details


def get_base_url(urlstring):
    """
    Extract base url from string.

    :param urlstring: url string
    :returns: base URL
    """
    url = urlparse(urlstring)
    baseurl = f"{url.scheme}://{url.netloc}"
    return baseurl


def get_org():
    """Get Org URL from user.

    :return: string with sanitized value, or the empty string.
    """
    message = "Okta Org URL. E.g. https://acme.okta.com/: "
    res = ""

    while res == "":
        user_data = get_input(prompt=message)
        user_data = user_data.strip()
        if user_data == "":
            break
        if not user_data.startswith("https://"):
            user_data = f"https://{user_data}"
        if validate_okta_org(user_data):
            res = user_data
        else:
            print("Invalid input, try again.")
    logger.debug(f"Org URL is: {res}")
    return res


def get_tile():
    """Get tile URL from user.

    :return: string with sanitized value, or the empty string.
    """
    message = (
        "Okta tile URL. E.g. https://acme.okta.com/home/" "amazon_aws/b07384d113edec49eaa6/123: "
    )
    res = ""

    while res == "":
        user_data = get_input(prompt=message)
        user_data = user_data.strip()
        if user_data == "":
            break
        if not user_data.startswith("https://"):
            user_data = f"https://{user_data}"
        if validate_okta_tile(user_data):
            res = user_data
        else:
            print("Invalid input, try again.")
    logger.debug(f"App URL is: {res}")
    return res


def get_username():
    """Get username from user.

    :return: string with sanitized value.
    """
    message = "Organization username. E.g. jane.doe@acme.com: "
    res = ""
    while res == "":
        user_data = get_input(prompt=message)
        user_data = user_data.strip()
        if user_data != "":
            res = user_data
        else:
            print("Invalid input, try again.")
    logger.debug(f"Username is {res}")
    return res


def get_password():
    """Set okta password interactively.

    :param args: command line arguments
    :return: okta_password

    """
    res = ""
    logger.debug("Set password.")

    tty_assertion()
    while res == "":
        password = getpass()
        res = password
        logger.debug("password set interactively")
    return res


def get_interactive_profile_name(default):
    """Get AWS profile name from user.

    :return: string with sanitized value, or the default string.
    """
    message = f"Enter a profile name or leave blank to use '{default}': "
    res = ""

    while res == "":
        user_data = get_input(prompt=message)
        user_data = user_data.strip()
        if user_data == "":
            res = default
            break
        if re.fullmatch("[a-zA-Z][a-zA-Z0-9_-]*", user_data):
            res = user_data
        else:
            print("Invalid input, try again.")
    logger.debug(f"Profile name is: {res}")
    return res


def set_profile_name(config_obj, role_name):
    """Set AWS Role alias name based on user preferences.

    :param config: Config object.
    :param role_name: Role name.
    :return: Config object.
    """
    if config_obj.aws["profile"] is None or config_obj.aws["profile"] == "":
        config_obj.aws["profile"] = get_interactive_profile_name(role_name)

    return config_obj


def update_configuration(config):
    """Update configuration file on local system.

    :param ini_file: Configuration file
    :param profile: profile in which to write.
    :return: None
    """
    logger.debug("Update configuration file on local system.")
    ini_file = config.user["config_file"]
    profile = config.user["config_profile"]

    contents = {}
    # Copy relevant parts of the configuration into an dictionary that
    # will be written out to disk
    if "org" in config.okta and config.okta["org"] is not None:
        contents["okta_org"] = config.okta["org"]
    if "tile" in config.okta and config.okta["tile"] is not None:
        contents["okta_tile"] = config.okta["tile"]
    if "mfa" in config.okta and config.okta["mfa"] is not None:
        contents["okta_mfa"] = config.okta["mfa"]
    if "username" in config.okta and config.okta["username"] != "":
        contents["okta_username"] = config.okta["username"]
    logger.debug(f"Adding {contents} to config file.")
    update_ini(profile=profile, ini_file=ini_file, **contents)
    logger.info(f"Updated {ini_file} with profile {profile}")


def update_device_token(config):
    """Update configuration file on local system with device token.

    :param config: the current configuration
    :return: None
    """
    logger.debug("Update configuration file on local system with device token.")
    ini_file = config.user["config_file"]
    profile = config.user["config_profile"]

    contents = {}
    # Copy relevant parts of the configuration into an dictionary that
    # will be written out to disk
    if "device_token" in config.okta and config.okta["device_token"] is not None:
        contents["okta_device_token"] = config.okta["device_token"]

    logger.debug(f"Adding {contents} to config file.")
    update_ini(profile=profile, ini_file=ini_file, **contents)
    logger.info(f"Updated {ini_file} with profile {profile}")


def set_local_credentials(response={}, role="default", region="us-east-1", output="json"):
    """Write to local files to insert credentials.

    :param response: AWS AssumeRoleWithSaml response
    :param role: the name of the assumed role, used for local profile
    :param region: configured region for aws credential profile
    :param output: configured datatype for aws cli output
    :return: Role name on a successful call.
    """
    try:
        aws_access_key_id = response["Credentials"]["AccessKeyId"]
        aws_secret_access_key = response["Credentials"]["SecretAccessKey"]
        aws_session_token = response["Credentials"]["SessionToken"]
    except KeyError as err:
        logger.error(f"Could not retrieve crendentials: {err}")
        sys.exit(1)

    update_ini(
        profile=role,
        ini_file=config.aws["shared_credentials_file"],
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
    )

    update_ini(
        profile=f"profile {role}",
        ini_file=config.aws["config_file"],
        output=output,
        region=region,
    )

    return role


def update_ini(profile="", ini_file="", **kwargs):
    """Update a generic INI file.

    :param profile: Profile name
    :param ini_file: File to write to.
    :param **kwargs: key/value pairs to write to the ini file
    :return: ConfigParser object written
    """
    ini_dir = os.path.dirname(ini_file)
    logger.debug(f"Updating: '{ini_file}'")

    create_directory(ini_dir)

    ini = configparser.RawConfigParser()
    try:
        ini.read(ini_file, encoding=config.user["encoding"])
        logger.debug(f"Parsed '{ini_file}'")
    except (configparser.Error, OSError) as err:
        logger.error(f"Failed to read '{ini_file}': {err}")
        sys.exit(1)

    if not ini.has_section(profile):
        ini.add_section(profile)

    for key, value in kwargs.items():
        ini.set(profile, key, value)

    try:
        with open(ini_file, "w+", encoding=config.user["encoding"]) as file:
            ini.write(file)
        logger.debug(f"Wrote {len(kwargs.items())} keys to '{ini_file}'")
    except (configparser.Error, OSError) as err:
        logger.error(f"Failed to write to '{ini_file}': {err}")
        sys.exit(1)
    return ini


def check_within_range(user_input, valid_range):
    """Validate the user input is within the range of the presented menu.

    :param user_input: integer-validated user input.
    :param valid_range: the valid range presented on the user's menu.
    :return range_validation: true or false
    """
    range_validation = False
    if int(user_input) in range(0, valid_range):
        range_validation = True
    else:
        logger.debug(f"Valid range is {valid_range}")
        logger.error("Value is not in within the selection range.")
    return range_validation


def check_integer(value):
    """Validate integer.

    :param value: value to be validated.
    :return: True when the number is a positive integer, false otherwise.
    """
    integer_validation = False
    if str(value).isdigit():
        integer_validation = True
    else:
        logger.error("Please enter a valid integer.")

    return integer_validation


def validate_input(value, valid_range):
    """Validate user input is an integer and within menu range.

    :param value: user input
    :param valid_range: valid range based on how many menu options available to user.
    """
    integer_validation = check_integer(value)
    if integer_validation and valid_range:
        integer_validation = check_within_range(value, valid_range)
    return integer_validation


def tty_assertion():
    """Ensure that a TTY is present."""
    try:
        assert os.isatty(sys.stdin.fileno()) is True
    except (AttributeError, AssertionError, EOFError, OSError, RuntimeError):
        logger.error(
            "sys.stdin is not available, and interactive invocation requires stdin to be present. "
            "Please check the --help argument and documentation for more details.",
        )
        sys.exit(1)


def get_input(prompt="-> "):
    """Collect user input for TOTP.

    :param prompt: optional string with prompt.
    :return user_input: raw from user.
    """
    tty_assertion()

    user_input = input(f"{prompt}")
    logger.debug(f"User input: {user_input}")

    return user_input


def collect_integer(valid_range=0):
    """Collect input from user.

    Prompt the user for input. Validate it and cast to integer.

    :param valid_range: number of menu options available to user.
    :return user_input: validated, casted integer from user.
    """
    user_input = None
    while True:
        user_input = get_input()
        valid_input = validate_input(user_input, valid_range)
        logger.debug(f"User input validation status is {valid_input}")
        if valid_input:
            user_input = int(user_input)
            break
    return user_input


def process_options(args):
    """Collect all user-specific credentials and config params."""
    if args.version:
        display_version()
        sys.exit(0)

    # 1: read ini file (if it exists)
    config_ini = Config()
    if not args.configure:
        config_ini = process_ini_file(args.user_config_file, args.user_config_profile)

    # 2: override with ENV
    config_env = process_environment()

    # 3: override with args
    config_args = process_arguments(args)

    config.update(config_ini)
    config.update(config_env)
    config.update(config_args)

    # 4: Get missing data from the user, if necessary
    config_int = process_interactive_input(config, args.configure)
    config.update(config_int)

    sanitize_config_values(config)
    logger.debug(f"Final configuration is {config}")

    if args.configure:
        update_configuration(config)
        sys.exit(0)


def validate_basic_configuration(config):
    """Ensure that basic configuration values are sane.

    :param config: Config element with final configuration.
    :return: message with validation issues.
    """
    message = []
    if not config.okta["username"] or config.okta["username"] == "":
        message.append("Username not set")
    if not config.okta["password"] or config.okta["password"] == "":
        message.append("Password not set")
    if not config.okta["org"] and not config.okta["tile"]:
        message.append("Either Okta Org or tile URL must be defined")
    if config.okta["tile"] and not validate_okta_tile(config.okta["tile"]):
        message.append(f"Tile URL {config.okta['tile']} is not valid")
    if config.okta["org"] and not validate_okta_org(config.okta["org"]):
        message.append(f"Org URL {config.okta['org']} is not valid")
    if (
        config.okta["org"]
        and config.okta["tile"]
        and not config.okta["tile"].startswith(config.okta["org"])
    ):
        message.append(
            f"Org URL {config.okta['org']} and Tile URL"
            f" {config.okta['tile']} must be in the same domain"
        )

    return message


def validate_quiet_configuration(config):
    """Ensure that minimum configuration settings for running quietly are met.

    This is kept separately from validate_basic_configuration to avoid complexity
    and avoid testability. These functions should always be used together.

    :param config: Config element with final configuration.
    :return: message with validation issues.
    """
    message = []
    if "quiet" in config.user and config.user["quiet"] is not False:
        if not config.aws["role_arn"]:
            message.append("AWS role ARN not set")
        if not config.okta["mfa"]:
            message.append("MFA Method not set")
        if not config.okta["mfa_response"] and config.okta["mfa"] != "push":
            message.append("MFA Response not set")

    return message


def validate_configuration(config):
    """
    Ensure that configuration settings are appropriate before contacting the Okta endpoint.

    :param config: Config element with final configuration.
    :return: message with validation issues.
    """
    messages = validate_basic_configuration(config) + validate_quiet_configuration(config)
    return messages


def sanitize_config_values(config):
    """Adjust values that may need to be corrected.

    :param config: Config object to adjust
    :returns: modified object.
    """
    if config.okta["tile"]:
        base_url = get_base_url(config.okta["tile"])
        config.okta["org"] = base_url

    if config.aws["output"] not in aws.get_output_types():
        config.aws["output"] = config.get_defaults()["aws"]["output"]
        logger.warning(f"AWS Output reset to {config.aws['output']}")

    if config.aws["region"] not in aws.get_regions():
        config.aws["region"] = config.get_defaults()["aws"]["region"]
        logger.warning(f"AWS Region reset to {config.aws['region']}")

    # Expand any "~", if given by the user
    if "config_dir" in config.user:
        config.user["config_dir"] = os.path.expanduser(config.user["config_dir"])
    if "config_file" in config.user:
        config.user["config_file"] = os.path.expanduser(config.user["config_file"])
    if "config_file" in config.aws:
        config.aws["config_file"] = os.path.expanduser(config.aws["config_file"])
    if "shared_credentials_file" in config.aws:
        config.aws["shared_credentials_file"] = os.path.expanduser(
            config.aws["shared_credentials_file"]
        )

    return config


def discover_tiles(url):
    """
    Discover aws tile url on user's okta dashboard.

    :param url: okta org url
    :param cookies: HTML cookies
    :returns: aws tile url. str
    """
    url = f"{url}/api/v1/users/me/home/tabs"
    params = {
        "type": "all",
        "expand": ["items", "items.resource"],
    }
    logger.debug(f"Performing auto-discovery on {url}.")
    logger.debug(f"in discover_tiles we have cookies: {HTTP_client.session.cookies}")
    response_with_tabs = HTTP_client.get(url, params=params)

    tabs = response_with_tabs.json()

    aws_tiles = []
    for tab in tabs:
        for tile in tab["_embedded"]["items"]:
            if "amazon_aws" in tile["_embedded"]["resource"]["linkUrl"]:
                aws_tiles.append(tile["_embedded"]["resource"])

    if not aws_tiles:
        logger.error("AWS tile url not found please set url and try again")
        sys.exit(2)

    tile = (
        {(url["linkUrl"], url["label"]) for url in aws_tiles}
        if len(aws_tiles) > 1
        else (aws_tiles[0]["linkUrl"], aws_tiles[0]["label"])
    )
    logger.debug(f"Discovered {len(tile)} URLs.")

    return tile
