# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Helper module for AWS and Okta configuration, management and data flow."""
from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
from builtins import (  # noqa: F401
    ascii,
    bytes,
    chr,
    dict,
    filter,
    hex,
    input,
    int,
    list,
    map,
    next,
    object,
    oct,
    open,
    pow,
    range,
    round,
    str,
    super,
    zip,
)
import codecs
import configparser
import getpass
import json
import logging
import os
import platform
import re
import sys
from urllib.parse import urlparse

from botocore import __version__ as __botocore_version__
from bs4 import __version__ as __bs4_version__
from bs4 import BeautifulSoup
from future import standard_library
import pytz
import requests
from tokendito import settings
from tokendito.__version__ import __version__
from tzlocal import get_localzone


standard_library.install_aliases()


def setup(args):
    """Parse command line arguments.

    :return: args parse object
    """
    parser = argparse.ArgumentParser(
        prog="tokendito", description="Gets a STS token to use with the AWS CLI"
    )
    parser.add_argument(
        "--version", "-v", action="store_true", help="Displays version and exit"
    )
    parser.add_argument(
        "--configure",
        "-c",
        action="store_true",
        help="Prompt user for " "configuration parameters",
    )
    parser.add_argument(
        "--username",
        "-u",
        type=to_unicode,
        dest="okta_username",
        help="username to login to Okta. You can "
        "also use the OKTA_USERNAME environment variable.",
    )
    parser.add_argument(
        "--password",
        "-p",
        type=to_unicode,
        dest="okta_password",
        help="password to login to Okta. You "
        "can also user the OKTA_PASSWORD environment variable.",
    )
    parser.add_argument(
        "--config-file",
        "-C",
        type=to_unicode,
        default=settings.config_file,
        help="Use an alternative configuration file",
    )
    parser.add_argument(
        "--okta-aws-app-url", "-ou", type=to_unicode, help="Okta App URL to use."
    )
    parser.add_argument(
        "--okta-profile",
        "-op",
        type=to_unicode,
        default=settings.okta_profile,
        help="Okta configuration profile to use.",
    )
    parser.add_argument(
        "--aws-region",
        "-r",
        type=to_unicode,
        help="Sets the AWS region for the profile",
    )
    parser.add_argument(
        "--aws-output",
        "-ao",
        type=to_unicode,
        help="Sets the AWS output type for the profile",
    )
    parser.add_argument(
        "--aws-profile",
        "-ap",
        type=to_unicode,
        help="Override AWS profile to save as in the credentials file.",
    )
    parser.add_argument(
        "--mfa-method", "-mm", type=to_unicode, help="Sets the MFA method"
    )
    parser.add_argument(
        "--mfa-response",
        "-mr",
        type=to_unicode,
        help="Sets the MFA response to a challenge",
    )
    parser.add_argument("--role-arn", "-R", type=to_unicode, help="Sets the IAM role")
    parser.add_argument(
        "--output-file", "-o", type=to_unicode, help="Log output to filename"
    )
    parser.add_argument(
        "--loglevel",
        "-l",
        type=lambda s: s.upper(),
        default="WARNING",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        help="[DEBUG|INFO|WARN|ERROR], default loglevel is WARNING."
        " Note: DEBUG level may display credentials",
    )

    parsed_args = parser.parse_args(args)
    set_logging(parsed_args)
    logging.debug("Parse command line arguments [{}]".format(parsed_args))

    return parsed_args


def utc_to_local(utc_dt):
    """Convert UTC time into local time.

    :param:utc_str:datetime
    :return:local_time:string
    """
    local_time = utc_dt.replace(tzinfo=pytz.utc).astimezone(tz=get_localzone())
    local_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z")

    return local_time


def to_unicode(bytestring):
    """Convert a string into a Unicode compliant object.

    The `unicode()` method is only available in Python 2. Python 3
    generates a `NameError`, and the same string is returned unmodified.

    :param bytestring:
    :return: unicode-compliant string
    """
    if type(bytestring) == bytes:
        bytestring = bytestring.decode(settings.encoding)
    unicode_string = bytestring
    try:
        unicode_string = unicode(bytestring, settings.encoding)
    except (NameError, TypeError):
        # If a TypeError is raised, we are in Python 3, this is a no-op.
        pass
    return unicode_string


def create_directory(dir_name):
    """Create directories on the local machine."""
    if os.path.isdir(dir_name) is False:
        try:
            os.mkdir(dir_name)
        except OSError as error:
            logging.error(
                "Cannot continue creating directory '{}': {}".format(
                    settings.config_dir, error.strerror
                )
            )
            sys.exit(1)


def set_okta_username():
    """Set okta username in a constant settings variable.

    :return: okta_username

    """
    logging.debug("Set okta username in a constant settings variable.")

    if settings.okta_username == "":
        okta_username = input("Username: ")
        setattr(settings, "okta_username", to_unicode(okta_username))
        logging.debug("username set to {} interactively".format(settings.okta_username))

    return settings.okta_username


def set_okta_password():
    """Set okta password in a constant settings variable.

    :param args: command line arguments
    :return: okta_password

    """
    logging.debug("Set okta password in a constant settings variable.")

    while settings.okta_password == "":
        okta_password = getpass.getpass()
        setattr(settings, "okta_password", to_unicode(okta_password))

    logging.debug("password set interactively")
    return settings.okta_password


def set_logging(args):
    """Set logging level.

    :param args: Arguments provided by a user
    :return:

    """
    logger = logging.getLogger()
    logger.setLevel(args.loglevel)
    log_level_int = getattr(logging, args.loglevel)

    # increment boto logs to not print api keys
    logging.getLogger("botocore").setLevel(log_level_int + 10)

    log_format = (
        "%(levelname)s " "[%(filename)s:%(funcName)s():%(lineno)i]: %(message)s"
    )
    date_format = "%m/%d/%Y %I:%M:%S %p"

    formatter = logging.Formatter(log_format, date_format)

    if args.output_file:
        handler = logging.FileHandler(args.output_file)
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(formatter)
    logger.addHandler(handler)


def select_role_arn(role_arns, saml_xml, saml_response_string):
    """Select the role user wants to pick.

    :param role_arns: IAM roles ARN list assigned for the user
    :param saml_xml: Decoded saml response from Okta
    :param saml_response_string: http response from saml assertion to AWS
    :return: User input index selected by the user, the arn of selected role

    """
    logging.debug("Select the role user wants to pick [{}]".format(role_arns))

    role_names = dict((role.split("/")[-1], role) for role in role_arns)
    roles = [role.split("/")[-1] for role in role_arns]

    if roles.count(settings.aws_profile) > 1:
        logging.error(
            "There are multiple matches for the profile selected, "
            "please use the --role-arn option to select one"
        )
        sys.exit(2)

    if settings.aws_profile in role_names.keys():
        selected_role = role_names[settings.aws_profile]
        logging.debug(
            "Using aws_profile env var for role: [{}]".format(settings.aws_profile)
        )
    elif settings.role_arn is None:
        selected_role = prompt_role_choices(role_arns, saml_xml, saml_response_string)
    elif settings.role_arn in role_arns:
        selected_role = settings.role_arn
    else:
        logging.error(
            "User provided rolename does not exist [{}]".format(settings.role_arn)
        )
        sys.exit(2)

    logging.debug("Selected role: [{}]".format(selected_role))

    return selected_role


def factor_type_info(factor_type, mfa_option):
    """Get factor info from okta reply.

    :param factor_type: mfa_method
    :param mfa_option: mfa_option
    :return: info about mfa_method
    """
    logging.debug("Choose factor info depending on factor type.")
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
    logging.debug("Building info for: {}".format(json.dumps(mfa_option)))

    if "factorType" in mfa_option:
        factor_type = mfa_option["factorType"]
        factor_info = factor_type_info(factor_type, mfa_option)

    if not factor_info:
        factor_info = "Not Presented"
    return factor_info


def select_preferred_mfa_index(
    mfa_options, factor_key="provider", subfactor_key="factorType"
):
    """Show all the MFA options to the users.

    :param mfa_options: List of available MFA options
    :return: MFA option selected index by the user from the output
    """
    logging.debug("Show all the MFA options to the users.")
    logging.debug(json.dumps(mfa_options))
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
            "[{: >{}}]  {: <{}}  {: <{}} {: <{}} Id: {}".format(
                i,
                longest_index,
                provider,
                longest_factor_name,
                mfa_method,
                longest_subfactor_name,
                factor_info,
                factor_info_indent,
                factor_id,
            ),
        )

    user_input = collect_integer(len(mfa_options))

    return user_input


def prompt_role_choices(role_arns, saml_xml, saml_response_string):
    """Ask user to select role.

    :param role_arns: IAM Role list
    :return: user input of AWS Role
    """
    if len(role_arns) == 1:
        account_id = role_arns[0].split(":")[4]
        alias_table = {account_id: account_id}
    else:
        alias_table = get_account_aliases(saml_xml, saml_response_string)

    logging.debug("Ask user to select role")
    print("Please select one of the following:\n")

    longest_alias = max([len(d) for d in alias_table.values()])
    longest_index = len(str(len(role_arns)))
    sorted_role_arns = sorted(role_arns)

    for (i, arn) in enumerate(sorted_role_arns):
        padding_index = longest_index - len(str(i))
        account_alias = alias_table[arn.split(":")[4]]
        print(
            "[{}] {}{: <{}}    {}".format(
                i, padding_index * " ", account_alias, longest_alias, arn
            )
        )

    user_input = collect_integer(len(role_arns))
    selected_role = sorted_role_arns[user_input]
    logging.debug("Selected role [{}]".format(user_input))

    return selected_role


def print_selected_role(profile_name, expiration_time):
    """Print details about how to assume role.

    :param profile_name: AWS profile name
    :param expiration_time: Credentials expiration time
    :return:

    """
    expiration_time_local = utc_to_local(expiration_time)
    msg = (
        "\nGenerated profile '{}' in {}.\n"
        "\nUse profile to authenticate to AWS:\n\t"
        "aws --profile '{}' sts get-caller-identity"
        "\nOR\n\t"
        "export AWS_PROFILE='{}'\n\n"
        "Credentials are valid until {} ({})."
    ).format(
        profile_name,
        settings.aws_shared_credentials_file,
        profile_name,
        profile_name,
        expiration_time,
        expiration_time_local,
    )

    return print(msg)


def extract_arns(saml):
    """Extract arns from SAML decoded xml.

    :param saml: results saml decoded
    :return: Principle ARNs, Role ARNs
    """
    logging.debug("Decode response string as a SAML decoded value.")

    soup = BeautifulSoup(saml, "xml")
    arns = soup.find_all(text=re.compile("arn:aws:iam::"))
    if len(arns) == 0:
        logging.error("No IAM roles found in SAML response.")
        logging.debug(arns)
        sys.exit(2)

    roles_and_providers = {i.split(",")[1]: i.split(",")[0] for i in arns}

    logging.debug("Collected ARNs: {}".format(json.dumps(roles_and_providers)))

    return roles_and_providers


def validate_saml_response(html):
    """Parse html to validate that saml a saml response was returned."""
    soup = BeautifulSoup(html, "html.parser")

    xml = None
    for elem in soup.find_all("input", attrs={"name": "SAMLResponse"}):
        saml_base64 = elem.get("value")
        xml = codecs.decode(saml_base64.encode("ascii"), "base64").decode("utf-8")

    if xml is None:
        logging.error(
            "Invalid data detected in SAML response."
            " View the response with the DEBUG loglevel."
        )
        logging.debug(html)
        sys.exit(1)

    return xml


def validate_okta_aws_app_url(input_url=None):
    """Validate whether a given URL is a valid AWS app URL in Okta.

    :param input_url: string
    :return: bool. True if valid, False otherwise
    """
    logging.debug("Will try to match '{}' to a valid URL".format(input_url))

    url = urlparse(input_url)
    # Here, we could also check url.netloc against r'.*\.okta(preview)?\.com$'
    # but Okta allows the usage of custome URLs such as login.acme.com
    if (
        url.scheme == "https"
        and re.match(r"^/home/amazon_aws/\w{20}/\d{3}$", url.path) is not None
    ):
        return True

    logging.debug("{} does not look like a valid match.".format(url))
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
        logging.error(
            "There was an error retrieving the AWS SAML page: \n{}".format(
                request_error
            )
        )
        logging.debug(json.dumps(aws_response))
        sys.exit(1)

    if "Account: " not in aws_response.text:
        logging.error("There were no accounts returned in the AWS SAML page.")
        logging.debug(json.dumps(aws_response.text))
        sys.exit(2)

    soup = BeautifulSoup(aws_response.text, "html.parser")
    account_names = soup.find_all(text=re.compile("Account:"))
    alias_table = {
        str(i.split(" ")[-1]).strip("()"): i.split(" ")[1] for i in account_names
    }

    return alias_table


def display_version():
    """Print program version and exit."""
    python_version = platform.python_version()
    (system, _, release, _, _, _) = platform.uname()
    print(
        "tokendito/{} Python/{} {}/{} botocore/{} bs4/{} requests/{}".format(
            __version__,
            python_version,
            system,
            release,
            __botocore_version__,
            __bs4_version__,
            requests.__version__,
        )
    )


def process_ini_file(file, profile):
    """Process options from a ConfigParser ini file.

    :param file: filename
    :param profile: profile to read
    :return: None
    """
    config = configparser.ConfigParser(default_section=settings.okta_profile)
    if config.read(file) == []:
        return

    try:
        for (key, val) in config.items(profile):
            if hasattr(settings, key):
                logging.debug("Set option {}={} from ini file".format(key, val))
                setattr(settings, key, val)
    except configparser.Error as err:
        logging.error("Could not load profile '{}': {}".format(profile, str(err)))
        sys.exit(2)


def process_arguments(args):
    """Process command-line arguments.

    :param args: argparse object
    :return: None
    """
    for (key, val) in vars(args).items():
        if hasattr(settings, key) and val is not None:
            logging.debug("Set option {}={} from command line".format(key, val))
            setattr(settings, key, val)


def process_environment():
    """Process environment variables.

    :return: None
    """
    for (key, val) in os.environ.items():
        key = key.lower()
        if hasattr(settings, key):
            logging.debug("Set option {}={} from environment".format(key, val))
            setattr(settings, key, os.getenv(key.upper()))


def process_okta_aws_app_url():
    """Process Okta app url.

    :param app_url: string with okta tile URL.
    :return: None.
    """
    if not validate_okta_aws_app_url(settings.okta_aws_app_url):
        logging.error(
            "Okta Application URL not found, or invalid. Please check "
            "your configuration and try again."
        )
        sys.exit(2)

    url = urlparse(settings.okta_aws_app_url)
    okta_org = "{}://{}".format(url.scheme, url.netloc)
    okta_aws_app_url = "{}{}".format(okta_org, url.path)
    setattr(settings, "okta_org", okta_org)
    setattr(settings, "okta_aws_app_url", okta_aws_app_url)


def user_configuration_input():
    """Obtain user input for the user.

    :return: (okta app url, organization username)
    """
    logging.debug("Obtain user input for the user.")
    url = ""
    username = ""
    config_details = []
    message = {
        "app_url": "\nOkta App URL. E.g https://acme.okta.com/home/"
        "amazon_aws/b07384d113edec49eaa6/123\n[none]: ",
        "username": "\nOrganization username. E.g jane.doe@acme.com" "\n[none]: ",
    }

    while url == "":
        user_data = to_unicode(input(message["app_url"]))
        user_data = user_data.strip()
        if validate_okta_aws_app_url(user_data):
            url = user_data
        else:
            print("Invalid input, try again.")
    config_details.append(url)

    while username == "":
        user_data = to_unicode(input(message["username"]))
        user_data = user_data.strip()
        if user_data != "":
            username = user_data
        else:
            print("Invalid input, try again.")
    config_details.append(username)

    return (config_details[0], config_details[1])


def update_configuration(okta_file, profile):
    """Update okta configuration file on local system.

    :param okta_file: Default configuration system file
    :param profile: profile of the okta user
    :return:
    """
    logging.debug("Update okta configuration file on local system.")

    config = configparser.RawConfigParser()

    create_directory(settings.config_dir)

    if os.path.isfile(okta_file):
        logging.debug("Read Okta config [{} {}]".format(okta_file, profile))
        config.read(okta_file, encoding=settings.encoding)
    if not config.has_section(profile):
        config.add_section(profile)
        logging.debug("Add section to Okta config [{}]".format(profile))

    (app_url, username) = user_configuration_input()

    url = urlparse(app_url.strip())
    okta_username = username.strip()

    okta_aws_app_url = "{}://{}{}".format(url.scheme, url.netloc, url.path)

    config.set(profile, "okta_aws_app_url", okta_aws_app_url)
    config.set(profile, "okta_username", okta_username)
    logging.debug("Config Okta [{}]".format(config))

    with open(okta_file, "w+", encoding=settings.encoding) as file:
        config.write(file)
        logging.debug("Write new section Okta config [{} {}]".format(okta_file, config))


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

    if settings.aws_profile is not None:
        role_name = settings.aws_profile

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
    cred_file = settings.aws_shared_credentials_file
    cred_dir = os.path.dirname(cred_file)
    logging.debug("Update AWS credentials in: [{}]".format(cred_file))

    create_directory(cred_dir)

    config = configparser.RawConfigParser()
    if os.path.isfile(cred_file):
        config.read(cred_file, encoding=settings.encoding)
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, "aws_access_key_id", aws_access_key)
    config.set(profile, "aws_secret_access_key", aws_secret_key)
    config.set(profile, "aws_session_token", aws_session_token)
    with open(cred_file, "w+", encoding=settings.encoding) as file:
        config.write(file)


def update_aws_config(profile, output, region):
    """Update AWS config file in ~/.aws/config file.

    :param profile: tokendito profile
    :param output: aws output
    :param region: aws region
    :return:

    """
    config_file = settings.aws_config_file
    config_dir = os.path.dirname(config_file)
    logging.debug("Update AWS config to file: [{}]".format(config_file))

    create_directory(config_dir)

    # Prepend the word profile the the profile name
    profile = "profile {}".format(profile)
    config = configparser.RawConfigParser()
    if os.path.isfile(config_file):
        config.read(config_file, encoding=settings.encoding)
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, "output", output)
    config.set(profile, "region", region)

    with open(config_file, "w+", encoding=settings.encoding) as file:
        config.write(file)


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
        logging.debug("Valid range is {}".format(valid_range))
        logging.error("Value is not in within the selection range.")
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
        logging.error("Please enter a valid integer.")

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
    user_input = to_unicode(input(prompt))
    logging.debug("User input [{}]".format(user_input))

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
        logging.debug("User input validation status is {}".format(valid_input))
        if valid_input:
            user_input = int(user_input)
            break
    return user_input


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

            if key != "password":
                logging.debug("Prepare payload [{} {}]".format(key, value))

    return payload_dict


def process_options(args):
    """Collect all user-specific credentials and config params."""
    if args.version:
        display_version()
        sys.exit(0)

    if args.configure:
        update_configuration(args.config_file, args.okta_profile)
        sys.exit(0)

    # 1: read ini file (if it exists)
    process_ini_file(args.config_file, args.okta_profile)
    # 2: override with args
    process_arguments(args)
    # 3: override with ENV
    process_environment()

    process_okta_aws_app_url()
    # Set username and password for Okta Authentication
    logging.debug("Set Okta credentials.")
    set_okta_username()
    set_okta_password()
