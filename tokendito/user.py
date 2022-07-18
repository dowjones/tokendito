# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Helper module for AWS and Okta configuration, management and data flow."""
import argparse
import codecs
import configparser
from datetime import timezone
import getpass
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
from bs4 import __version__ as __bs4_version__
from bs4 import BeautifulSoup
import requests
from tokendito import __version__
from tokendito import Config
from tokendito import config as config

logger = logging.getLogger(__name__)


def parse_cli_args(args):
    """Parse command line arguments.

    :return: args parse object
    """
    parser = argparse.ArgumentParser(
        prog="tokendito", description="Gets a STS token to use with the AWS CLI and SDK."
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
        help="username to login to Okta. You can "
        "also use the OKTA_USERNAME environment variable.",
    )
    parser.add_argument(
        "--password",
        dest="okta_password",
        help="password to login to Okta. You "
        "can also user the OKTA_PASSWORD environment variable.",
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
        help="Use an alternative configuration file",
    )
    parser.add_argument(
        "--loglevel",
        "-l",
        type=lambda s: s.upper(),
        dest="user_loglevel",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="[DEBUG|INFO|WARN|ERROR], default loglevel is WARNING."
        " Note: DEBUG level will display credentials",
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
        "--okta-org-url",
        dest="okta_org",
        help="Set the Okta Org base URL. This enables role auto-discovery",
    )
    okta_me_group.add_argument(
        "--okta-app-url",
        help="Okta App URL to use.",
    )
    parser.add_argument("--okta-mfa-method", help="Sets the MFA method")
    parser.add_argument(
        "--okta-mfa-response",
        help="Sets the MFA response to a challenge",
    )

    parsed_args = parser.parse_args(args)

    return parsed_args


def utc_to_local(utc_dt):
    """Convert UTC time into local time.

    :param:utc_str:datetime
    :return:local_time:string
    """
    local_time = utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)
    local_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z")

    return local_time


def create_directory(dir_name):
    """Create directories on the local machine."""
    if os.path.isdir(dir_name) is False:
        try:
            os.mkdir(dir_name)
        except OSError as error:
            logger.error(
                f"Cannot continue creating directory: {config.user['config_dir']}: {error.strerror}"
            )
            sys.exit(1)


def set_okta_username():
    """Set okta username in a constant settings variable.

    :return: okta_username

    """
    logger.debug("Set username.")

    if config.okta["username"] == "":
        username = input("Username: ")
        config.okta["username"] = username
        logger.debug("username set interactively.")
    return config.okta["username"]


def set_okta_password():
    """Set okta password in a constant settings variable.

    :param args: command line arguments
    :return: okta_password

    """
    logger.debug("Set password.")

    while config.okta["password"] == "":
        password = getpass.getpass()
        config.okta["password"] = password
    logger.debug("password set interactively")

    return config.okta["password"]


def get_submodule_names(location=__file__):
    """Inspect the current module and find any submodules.

    :return: List of submodule names

    """
    submodules = []

    try:
        package = Path(location).resolve()
        submodules = [x.name for x in iter_modules([str(package.parent)])]
    except Exception as err:
        logger.warning(f"Could not resolve modules: {str(err)}")

    return submodules


def setup_logging(conf):
    """Set logging level.

    :param conf: User config
    :return: None

    """
    root_logger = logging.getLogger()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(name)s [%(funcName)s():%(lineno)i] - %(levelname)s - %(message)s"
    )
    handler = logging.StreamHandler()
    if conf["log_output_file"]:
        handler = logging.FileHandler(conf["log_output_file"])
    handler.setFormatter(formatter)

    # Set a reasonable default logging format.
    root_logger.addHandler(handler)

    # Pre-create a log handler for each submodule
    # with the same format and level. Settings are
    # inherited from the root logger.
    for submodule in get_submodule_names():
        submodule_logger = logging.getLogger(f"tokendito.{submodule}")
        submodule_logger.setLevel(conf["loglevel"])


def select_role_arn(authenticated_aps):
    """Select the role user wants to pick.

    :param: authenticated_aps, mapping of authenticated apps metadata, dict
    :return: user role and associated url, tuple
    """
    selected_role = None

    for url, app in authenticated_aps.items():
        logger.debug(f"Select the role user wants to pick [{app['roles']}]")
        role_names = dict((role.split("/")[-1], role) for role in app["roles"])
        roles = [role.split("/")[-1] for role in app["roles"]]

        if roles.count(config.aws["profile"]) > 1:
            logger.error(
                "There are multiple matches for the profile selected, "
                "please use the --role-arn option to select one"
            )
            sys.exit(2)

        if config.aws["profile"] in role_names.keys():
            selected_role = (role_names[config.aws["profile"]], url)
            logger.debug(f"Using aws_profile env var for role: [{config.aws['profile']}]")
            break
        elif config.aws["role_arn"] in app["roles"]:
            selected_role = (config.aws["role_arn"], url)
            break

    if selected_role is None:
        if config.aws["role_arn"] is None:
            selected_role = prompt_role_choices(authenticated_aps)
        else:
            logger.error(f"User provided rolename does not exist [{config.aws['role_arn']}]")
            sys.exit(2)

    logger.debug(f"Selected role: [{selected_role}]")

    return selected_role


def factor_type_info(factor_type, mfa_option):
    """Get factor info from okta reply.

    :param factor_type: mfa_method
    :param mfa_option: mfa_option
    :return: info about mfa_method
    """
    logger.debug("Choose factor info depending on factor type.")
    factor_info = "Not Presented"

    if factor_type in ["token", "token:software:totp", "token:hardware"]:
        factor_info = mfa_option.get("profile").get("credentialId")
    elif factor_type == "push":
        factor_info = mfa_option.get("profile").get("name")
    elif factor_type == "sms" or factor_type == "call":
        factor_info = mfa_option.get("profile").get("phoneNumber")
    elif factor_type == "webauthn":
        factor_info = mfa_option.get("profile").get("authenticatorName")
    elif factor_type in ["web", "u2f", "token:hotp"]:
        factor_info = mfa_option.get("vendorName")
    elif factor_type == "question":
        factor_info = mfa_option.get("profile").get("question")
    elif factor_type == "email":
        factor_info = mfa_option.get("profile").get("email")

    return factor_info


def mfa_option_info(mfa_option):
    """Build an optional string with the MFA factor information.

    :param mfa_option: dictionary with a single MFA response.
    :return: pre-formatted string with MFA factor info if available, None
             otherwise.
    """
    logger.debug(f"Building info for: {json.dumps(mfa_option)}")
    factor_info = None
    if "factorType" in mfa_option:
        factor_type = mfa_option["factorType"]
        factor_info = factor_type_info(factor_type, mfa_option)

    if not factor_info:
        factor_info = "Not Presented"
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

    for (i, mfa_option) in enumerate(mfa_options):
        factor_id = mfa_option.get("id", "Not presented")
        factor_info = mfa_option_info(mfa_option)
        mfa_method = mfa_option.get(subfactor_key, "Not presented")
        provider = mfa_option.get(factor_key, "Not presented")
        print(
            f"[{i: >{longest_index}}]  {provider: <{longest_factor_name}}  "
            f"{mfa_method: <{longest_subfactor_name}} "
            f"{factor_info: <{factor_info_indent}} Id: {factor_id}"
        )

    user_input = collect_integer(len(mfa_options))

    return user_input


def prompt_role_choices(aut_aps):
    """Ask user to select role.

    :param aut_aps: mapping of authenticated apps metadata, dict
    :return: user's role and associated url, tuple
    """
    aliases_mapping = []

    for url, app in aut_aps.items():
        logger.debug(f"Getting aliases for {url}")
        alias_table = get_account_aliases(app["saml"], app["saml_response_string"])

        for role in app["roles"]:
            if alias_table:
                aliases_mapping.append((app["label"], alias_table[role.split(":")[4]], role, url))
            else:
                logger.debug(f"There were no labels in {url}. Using account ID")
                aliases_mapping.append((app["label"], role.split(":")[4], role, url))

    logger.debug("Ask user to select role")
    print("Please select one of the following:")

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

        print(f"[{i}] {padding_index * ' '}{alias: <{longest_alias}}  {role}")

    user_input = collect_integer(len(aliases_mapping))
    selected_role = (aliases_mapping[user_input][2], aliases_mapping[user_input][3])
    logger.debug(f"Selected role [{user_input}]")

    return selected_role


def print_selected_role(profile_name, expiration_time):
    """Print details about how to assume role.

    :param profile_name: AWS profile name
    :param expiration_time: Credentials expiration time
    :return:

    """
    expiration_time_local = utc_to_local(expiration_time)
    msg = (
        f"\nGenerated profile '{profile_name}' in {config.aws['shared_credentials_file']}.\n"
        "\nUse profile to authenticate to AWS:\n\t"
        f"aws --profile '{profile_name}' sts get-caller-identity"
        "\nOR\n\t"
        f"export AWS_PROFILE='{profile_name}'\n\n"
        f"Credentials are valid until {expiration_time} ({expiration_time_local})."
    )

    return print(msg)


def extract_arns(saml):
    """Extract arns from SAML decoded xml.

    :param saml: results saml decoded
    :return: Dict of Role and Provider ARNs
    """
    logger.debug("Decode response string as a SAML decoded value.")

    arn_regex = ">(arn:aws:iam::.*?,arn:aws:iam::.*?)<"

    # find all provider and role pairs.
    arns = re.findall(arn_regex, saml)

    if len(arns) == 0:
        logger.error("No IAM roles found in SAML response.")
        logger.debug(arns)
        sys.exit(2)

    # stuff into dict, role is dict key.
    roles_and_providers = {i.split(",")[1]: i.split(",")[0] for i in arns}

    logger.debug(f"Collected ARNs: {json.dumps(roles_and_providers)}")

    return roles_and_providers


def validate_saml_response(html):
    """Parse html to validate that saml a saml response was returned."""
    soup = BeautifulSoup(html, "html.parser")

    xml = None
    for elem in soup.find_all("input", attrs={"name": "SAMLResponse"}):
        saml_base64 = elem.get("value")
        xml = codecs.decode(saml_base64.encode("ascii"), "base64").decode("utf-8")

    if xml is None:
        logger.error(
            "Invalid data detected in SAML response. View the response with the DEBUG loglevel."
        )
        logger.debug(html)
        sys.exit(1)

    return xml


def validate_okta_org_url(input_url=None):
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
    ) or (url.scheme == "" and url.params == "" and url.query == "" and url.fragment == ""):
        return True

    logger.debug(f"{url} does not look like a valid match.")
    return False


def validate_okta_app_url(input_url=None):
    """Validate whether a given URL is a valid AWS app URL in Okta.

    :param input_url: string
    :return: bool. True if valid, False otherwise
    """
    logger.debug(f"Will try to match '{input_url}' to a valid URL")

    url = urlparse(input_url)
    logger.debug(f"URL parsed as {url}")
    # Here, we could also check url.netloc against r'.*\.okta(preview)?\.com$'
    # but Okta allows the usage of custome URLs such as login.acme.com
    if url.scheme == "https" and re.match(r"^/home/amazon_aws/\w{20}/\d{3}$", url.path) is not None:
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
    url = soup.find("form").get("action")

    encoded_xml = codecs.encode(saml_xml.encode("utf-8"), "base64")
    aws_response = None
    try:
        aws_response = requests.Session().post(url, data={"SAMLResponse": encoded_xml})
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
    print(
        f"tokendito/{__version__} Python/{python_version} {system}/{release} "
        f"botocore/{__botocore_version__} bs4/{__bs4_version__} requests/{requests.__version__}"
    )


def process_ini_file(file, profile):
    """Process options from a ConfigParser ini file.

    :param file: filename
    :param profile: profile to read
    :return: Config object with configuration values
    """
    res = dict()
    pattern = re.compile(r"^(.*?)_(.*)")

    ini = configparser.ConfigParser(default_section=config.user["config_profile"])
    # Here, group(1) is the dictionary key, and group(2) the configuration element
    try:
        ini.read(file)
        for (key, val) in ini.items(profile):
            match = re.search(pattern, key.lower())
            if match:
                if match.group(1) not in res:
                    res[match.group(1)] = dict()
                res[match.group(1)][match.group(2)] = val
    except configparser.Error as err:
        logger.error(f"Could not load profile '{profile}': {str(err)}")
        sys.exit(2)

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

    for (key, val) in vars(args).items():
        match = re.search(pattern, key.lower())
        if match:
            if match.group(1) not in get_submodule_names():
                continue
            if match.group(1) not in res:
                res[match.group(1)] = dict()
            if val:
                res[match.group(1)][match.group(2)] = val

    try:
        config_args = Config(**res)

    except (AttributeError, KeyError, ValueError) as err:
        logger.critical(
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
    for (key, val) in os.environ.items():
        match = re.search(pattern, key.lower())
        if match:
            if match.group(2) not in res:
                res[match.group(2)] = dict()
            res[match.group(2)][match.group(3)] = val

    try:
        config_env = Config(**res)

    except (AttributeError, KeyError, ValueError) as err:
        logger.error(
            f"The environment variables are incorrectly set: {err}"
            ". Please check your settings and try again."
        )
        sys.exit(1)
    return config_env


def process_okta_app_url(config_obj):
    """
    Validate okta app url, and extract okta org url from it.

    :param config_obj: configuration object
    :returns: None
    """
    if not validate_okta_app_url(config_obj.okta["app_url"]):
        logger.error(
            "Okta Application URL not found, or invalid. Please check "
            "your configuration and try again."
        )
        sys.exit(2)

    url = urlparse(config_obj.okta["app_url"])
    okta_org = f"{url.scheme}://{url.netloc}"
    okta_aws_app_url = f"{okta_org}{url.path}"
    config_obj.okta["org"] = okta_org
    config_obj.okta["app_url"] = okta_aws_app_url


def user_configuration_input():
    """Obtain user input for the user.

    :return: tuple with (okta_app_url, username)
    """
    logger.debug("Obtain user input for the user.")
    url = ""
    username = ""
    config_details = []
    message = {
        "app_url": "\nOkta App URL. E.g https://acme.okta.com/home/"
        "amazon_aws/b07384d113edec49eaa6/123\n[none]: ",
        "username": "\nOrganization username. E.g jane.doe@acme.com\n[none]: ",
    }

    while url == "":
        user_data = input(message["app_url"])
        user_data = user_data.strip()
        if validate_okta_app_url(user_data):
            url = user_data
        else:
            print("Invalid input, try again.")
    config_details.append(url)

    while username == "":
        user_data = input(message["username"])
        user_data = user_data.strip()
        if user_data != "":
            username = user_data
        else:
            print("Invalid input, try again.")
    config_details.append(username)

    return (config_details[0], config_details[1])


def update_configuration(ini_file, profile):
    """Update configuration file on local system.

    :param ini_file: Configuration file
    :param profile: profile in which to write.
    :return: None
    """
    logger.debug("Update configuration file on local system.")

    ini = configparser.RawConfigParser()

    create_directory(config.user["config_dir"])

    if os.path.isfile(ini_file):
        logger.debug(f"Read config [{ini_file} {profile}]")
        ini.read(ini_file, encoding=config.user["encoding"])
    if not ini.has_section(profile):
        ini.add_section(profile)
        logger.debug(f"Added section {profile} to configuration")

    (app_url, username) = user_configuration_input()

    url = urlparse(app_url.strip())
    okta_username = username.strip()

    okta_app_url = f"{url.scheme}://{url.netloc}{url.path}"

    ini.set(profile, "okta_app_url", okta_app_url)
    ini.set(profile, "okta_username", okta_username)
    logger.debug(f"Final configuration: [{ini}]")

    with open(ini_file, "w+", encoding=config.user["encoding"]) as file:
        ini.write(file)
        logger.debug(f"Write new config [{ini_file} {config}]")


def set_local_credentials(assume_role_response, role_name, aws_region, aws_output):
    """Write to local files to insert credentials.

    :param assume_role_response AWS AssumeRoleWithSaml response:
    :param role_name the name of the assumed role, used for local profile:
    :param aws_region configured region for aws credential profile:
    :param aws output configured datatype for aws cli output:
    """
    expiration_time = assume_role_response["Credentials"]["Expiration"]
    aws_access_key = assume_role_response["Credentials"]["AccessKeyId"]
    aws_secret_key = assume_role_response["Credentials"]["SecretAccessKey"]
    aws_session_token = assume_role_response["Credentials"]["SessionToken"]

    if config.aws["profile"] is not None:
        role_name = config.aws["profile"]

    update_aws_credentials(role_name, aws_access_key, aws_secret_key, aws_session_token)
    update_aws_config(role_name, aws_output, aws_region)

    print_selected_role(role_name, expiration_time)


def update_aws_credentials(profile, aws_access_key, aws_secret_key, aws_session_token):
    """Update AWS credentials in ~/.aws/credentials default file.

    :param profile: AWS profile name
    :param aws_access_key: AWS access key
    :param aws_secret_key: AWS secret access key
    :param aws_session_token: Session token
    """
    cred_file = config.aws["shared_credentials_file"]
    cred_dir = os.path.dirname(cred_file)
    logger.debug(f"Update AWS credentials in: [{cred_file}]")

    create_directory(cred_dir)

    ini = configparser.RawConfigParser()
    if os.path.isfile(cred_file):
        ini.read(cred_file, encoding=config.user["encoding"])
    if not ini.has_section(profile):
        ini.add_section(profile)
    ini.set(profile, "aws_access_key_id", aws_access_key)
    ini.set(profile, "aws_secret_access_key", aws_secret_key)
    ini.set(profile, "aws_session_token", aws_session_token)
    with open(cred_file, "w+", encoding=config.user["encoding"]) as file:
        ini.write(file)


def update_aws_config(profile, output, region):
    """Update AWS config file in ~/.aws/config file.

    :param profile: tokendito profile
    :param output: aws output
    :param region: aws region
    :return:

    """
    config_file = config.aws["config_file"]
    config_dir = os.path.dirname(config_file)
    logger.debug(f"Update AWS config to file: [{config_file}]")

    create_directory(config_dir)

    # Prepend the word profile the the profile name
    profile = f"profile {profile}"
    ini = configparser.RawConfigParser()
    if os.path.isfile(config_file):
        ini.read(config_file, encoding=config.user["encoding"])
    if not ini.has_section(profile):
        ini.add_section(profile)
    ini.set(profile, "output", output)
    ini.set(profile, "region", region)

    with open(config_file, "w+", encoding=config.user["encoding"]) as file:
        ini.write(file)


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


def get_input(prompt="-> "):
    """Collect user input for TOTP.

    :return user_input: raw from user.
    """
    user_input = input(prompt)
    logger.debug(f"User input [{user_input}]")

    return user_input


def collect_integer(valid_range):
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
    args = parse_cli_args(args)

    if args.version:
        display_version()
        sys.exit(0)

    if args.configure:
        update_configuration(args.user_config_file, args.user_config_profile)
        sys.exit(0)

    # 1: read ini file (if it exists)
    config_ini = process_ini_file(args.user_config_file, args.user_config_profile)

    # 2: override with ENV
    config_env = process_environment()

    # 3: override with args
    config_args = process_arguments(args)

    config.update(config_ini)
    config.update(config_env)
    config.update(config_args)


def process_okta_org_url(config_obj):
    """
    Extract okta org url from app url, or request it from user.

    :param config_obj: configuration object
    :returns: None
    """
    message = "Okta Org URL. E.g. https://acme.okta.com/: "
    if not config_obj.okta["app_url"] and not config_obj.okta["org"]:
        while not config_obj.okta["org"]:
            user_input = input(message)
            user_input = user_input.strip()
            if validate_okta_org_url(user_input):
                config_obj.okta["org"] = user_input
            else:
                print("Invalid input, try again")

    elif config_obj.okta["app_url"] and not config_obj.okta["org"]:
        process_okta_app_url(config_obj)

    url = urlparse(config_obj.okta["org"])
    logger.debug(f"Cleaning up {config_obj.okta['org']}")
    if url.path and not url.netloc:
        config_obj.okta["org"] = f"https://{url.path.split('/')[0]}"
    else:
        config_obj.okta["org"] = f"https://{url.netloc}"
    logger.debug(f"Connection string is {config_obj.okta['org']}")


def request_cookies(url, session_token):
    """
    Request session cookie.

    :param url: okta org url, str
    :param session_token: session token, str
    :returns: cookies object
    """
    url = f"{url}/api/v1/sessions"
    data = json.dumps({"sessionToken": f"{session_token}"})

    response_with_cookie = make_request(method="POST", url=url, data=data)
    sesh_id = response_with_cookie.json()["id"]

    cookies = response_with_cookie.cookies
    cookies.update({"sid": f"{sesh_id}"})

    return cookies


def discover_app_url(url, cookies):
    """
    Discover aws app url on user's okta dashboard.

    :param url: okta org url
    :param cookies: HTML cookies
    :returns: aws app url. str
    """
    url = f"{url}/api/v1/users/me/home/tabs"
    params = {
        "type": "all",
        "expand": ["items", "items.resource"],
    }
    logger.debug(f"Performing auto-discovery on {url}.")
    response_with_tabs = make_request(method="GET", url=url, cookies=cookies, params=params)
    tabs = response_with_tabs.json()

    aws_apps = []
    for tab in tabs:
        for app in tab["_embedded"]["items"]:
            if "amazon_aws" in app["_embedded"]["resource"]["linkUrl"]:
                aws_apps.append(app["_embedded"]["resource"])

    if not aws_apps:
        logger.error("AWS app url not found please set url and try again")
        sys.exit(2)

    app_url = (
        {(url["linkUrl"], url["label"]) for url in aws_apps}
        if len(aws_apps) > 1
        else (aws_apps[0]["linkUrl"], aws_apps[0]["label"])
    )
    logger.debug(f"Discovered {len(app_url)} URLs.")

    if len(app_url) >= 5:
        logger.warning(f"Discovering roles in {len(app_url)} tiles, this may take some time.")

    return app_url


def make_request(method, url, headers=None, **kwargs):
    """
    Wrap 'requests.request' and perform response checks.

    :param method: request method
    :param url: request URL
    :param headers: request headers
    :param kwargs: additional parameters passed to request
    :returns: response object
    """
    if headers is None:
        headers = {"content-type": "application/json", "accept": "application/json"}

    response = requests.request(method=method, url=url, headers=headers, **kwargs)

    if response.status_code != 200:
        logger.error(
            f"Your {method} request failed with status_code {response.status_code}.\n"
            f"{response.content}\n"
        )

    return response
