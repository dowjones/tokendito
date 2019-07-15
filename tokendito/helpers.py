# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Helper module for AWS and Okta configuration, management and data flow."""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import argparse
from builtins import (ascii, bytes, chr, dict, filter, hex, input,  # noqa: F401
                      int, list, map, next, object, oct, open, pow, range,
                      round, str, super, zip)
import codecs
import configparser
import getpass
import json
import logging
import os
import re
import sys
from urllib.parse import urlparse

from botocore import __version__ as __botocore_version__
from bs4 import BeautifulSoup
from future import standard_library
import requests
from tokendito import settings
from tokendito.__version__ import __version__

standard_library.install_aliases()


def setup():
    """Parse command line arguments.

    :return: args parse object
    """
    parser = argparse.ArgumentParser(
        description='Gets a STS token to use with the AWS CLI')
    parser.add_argument('--version', '-v', action='version',
                        version='{}/{} botocore/{}'.format(
                            parser.prog, __version__, __botocore_version__),
                        help='Displays version and exit')
    parser.add_argument('--configure', '-c', action='store_true', help='Prompt user for '
                        'configuration parameters')

    parser.add_argument('--username', '-u', type=to_unicode, dest='okta_username',
                        help='username to login to Okta. You can '
                        'also use the OKTA_USERNAME environment variable.')
    parser.add_argument('--password', '-p', type=to_unicode, dest='okta_password',
                        help='password to login to Okta. You '
                        'can also user the OKTA_PASSWORD environment variable.')

    parser.add_argument('--config-file', '-C', type=to_unicode,
                        help='Use an alternative configuration file')
    parser.add_argument('--okta-aws-app-url', '-ou', type=to_unicode,
                        help='Okta App URL to use.')
    parser.add_argument('--okta-profile', '-op', type=to_unicode,
                        help='Okta configuration profile to use.')
    parser.add_argument('--aws-region', '-r', type=to_unicode,
                        help='Sets the AWS region for the profile')
    parser.add_argument('--aws-output', '-ao', type=to_unicode,
                        help='Sets the AWS output type for the profile')
    parser.add_argument('--aws-profile', '-ap', type=to_unicode,
                        help='Override AWS profile to save as in the credentials file.')
    parser.add_argument('--mfa-method', '-mm', type=to_unicode,
                        help='Sets the MFA method')
    parser.add_argument('--mfa-response', '-mr', type=to_unicode,
                        help='Sets the MFA response to a challenge')
    parser.add_argument('--role-arn', '-R', type=to_unicode,
                        help='Sets the IAM role')
    parser.add_argument('--output-file', '-o', type=to_unicode,
                        help="Log output to filename")
    parser.add_argument('--loglevel', '-l', type=lambda s: s.upper(), default='ERROR',
                        choices=["DEBUG", "INFO", "WARN", "ERROR"],
                        help='[DEBUG|INFO|WARN|ERROR], default loglevel is ERROR.'
                        ' Note: DEBUG level may display credentials')

    args = parser.parse_args()
    set_logging(args)
    logging.debug("Parse command line arguments [{}]".format(args))

    return args


def to_unicode(bytestring):
    """Convert a str into a Unicode object.

    The `unicode()` method is only available in Python 2. Python 3
    generates a `NameError`, and the same string is returned unmodified.

    :param bytestring:
    :return: unicode-escaped string
    """
    unicode_string = bytestring
    try:
        unicode_string = unicode(bytestring, settings.encoding)
    except (NameError, TypeError):
        pass
    return unicode_string


def create_directory(dir_name):
    """Create directories on the local machine."""
    if os.path.isdir(dir_name) is False:
        try:
            os.mkdir(dir_name)
        except OSError as error:
            logging.error("Cannot continue creating directory \'{}\': {}".format(
                settings.config_dir, error.strerror))
            sys.exit(1)


def set_okta_user_name():
    """Set okta username in a constant settings variable.

    :return: okta_username

    """
    logging.debug("Set okta username in a constant settings variable.")

    if settings.okta_username == '':
        okta_username = input('Username: ')
        setattr(settings, 'okta_username', to_unicode(okta_username))
        logging.debug('username set to {} interactively'.format(
            settings.okta_username))

    return settings.okta_username


def set_okta_password():
    """Set okta password in a constant settings variable.

    :param args: command line arguments
    :return: okta_password

    """
    logging.debug("Set okta password in a constant settings variable.")

    while settings.okta_password == '':
        okta_password = getpass.getpass()
        setattr(settings, 'okta_password', to_unicode(okta_password))

    logging.debug('password set interactively')
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
    logging.getLogger('botocore').setLevel(
        log_level_int + 10)

    log_format = (
        '%(levelname)s '
        '[%(filename)s:%(funcName)s():%(lineno)i]: %(message)s'
    )
    date_format = '%m/%d/%Y %I:%M:%S %p'

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
    if settings.role_arn is None:
        selected_role = prompt_role_choices(
            role_arns, saml_xml, saml_response_string)
    elif settings.role_arn in role_arns:
        selected_role = settings.role_arn
    else:
        logging.error(
            "User provided rolename does not exist [{}]".format(settings.role_arn))
        sys.exit(2)

    logging.debug("Selected role: [{}]".format(selected_role))

    return selected_role


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
        print('[{}] {}{: <{}}    {}'.format(
            i, padding_index*' ', account_alias, longest_alias, arn))

    while True:
        user_input = to_unicode(input('-> '))

        try:
            user_input = int(user_input)
        except ValueError as error:
            print('Invalid input, try again.' + str(error))
            logging.warning("Invalid input [{}]".format(error))
            continue
        if user_input in range(0, len(role_arns)):
            logging.debug("User selected item {}.".format(user_input))
            break
        continue

    selected_role = sorted_role_arns[user_input]

    logging.debug("Selected role [{}]".format(user_input))

    return selected_role


def print_selected_role(profile_name, expiration_time):
    """Print details about how to assume role.

    :param profile_name: AWS profile name
    :param expiration_time: Credentials expiration time
    :return:

    """
    msg = (
        '\nGenerated profile \'{}\' in {}.\n'
        '\nUse profile to authenticate to AWS:\n\t'
        'aws --profile \'{}\' sts get-caller-identity'
        '\nOR\n\t'
        'export AWS_PROFILE=\'{}\'\n\n'
        'Credentials are valid until {}.'
        ).format(profile_name, settings.aws_shared_credentials_file,
                 profile_name, profile_name, expiration_time)

    return print(msg)


def extract_arns(saml):
    """Extract arns from SAML decoded xml.

    :param saml: results saml decoded
    :return: Principle ARNs, Role ARNs
    """
    logging.debug("Decode response string as a SAML decoded value.")

    soup = BeautifulSoup(saml, 'xml')
    arns = soup.find_all(text=re.compile('arn:aws:iam::'))
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
    for elem in soup.find_all('input', attrs={'name': 'SAMLResponse'}):
        saml_base64 = elem.get('value')
        xml = codecs.decode(saml_base64.encode(
            'ascii'), 'base64').decode('utf-8')

    if xml is None:
        logging.error("Invalid data detected in SAML response."
                      " View the response with the DEBUG loglevel.")
        logging.debug(html)
        sys.exit(1)

    return xml


def get_account_aliases(saml_xml, saml_response_string):
    """Parse AWS SAML page for account aliases.

    :param saml_xml: Decoded saml response from Okta
    :param saml_response_string response from Okta with saml data:
    :return: mapping table of account ids to their aliases
    """
    soup = BeautifulSoup(saml_response_string, "html.parser")
    url = soup.find('form').get('action')

    encoded_xml = codecs.encode(saml_xml.encode('utf-8'), 'base64')
    aws_response = None
    try:
        aws_response = requests.Session().post(
            url, data={'SAMLResponse': encoded_xml})
    except Exception as request_error:
        logging.error(
            "There was an error retrieving the AWS SAML page: \n{}".format(request_error))
        logging.debug(json.dumps(aws_response))
        sys.exit(1)

    if "Account: " not in aws_response.text:
        logging.error(
            "There were no accounts returned in the AWS SAML page.")
        logging.debug(json.dumps(aws_response.text))
        sys.exit(2)

    soup = BeautifulSoup(aws_response.text, "html.parser")
    account_names = soup.find_all(text=re.compile('Account:'))
    alias_table = {str(i.split(" ")[-1]).strip("()"): i.split(" ")[1] for i in account_names}

    return alias_table


def process_init_file(config):
    """Process options from a ConfigParser init file.

    :param config: ConfigParser object
    :return: None
    """
    # Read defaults from config
    if 'default' in config.sections():
        for (key, val) in config.items('default'):
            logging.debug(
                'Set option {}={} from config default'.format(key, val))
            setattr(settings, key, val)
    # Override with local profile config
    if settings.okta_profile in config.sections():
        for (key, val) in config.items(settings.okta_profile):
            logging.debug('Set option {}={} from {}'.format(
                key, val, settings.okta_profile))
            setattr(settings, key, val)
    else:
        logging.warning('Profile \'{}\' does not exist.'.format(settings.okta_profile))


def process_arguments(args):
    """Process command-line arguments.

    :param args: argparse object
    :return: None
    """
    for (key, val) in vars(args).items():
        if val is not None:
            logging.debug(
                'Set option {}={} from command line'.format(key, val))
            setattr(settings, key, val)


def process_environment():
    """Process environment variables.

    :return: None
    """
    for (key, val) in os.environ.items():
        if key.startswith('OKTA_') or \
           key == 'AWS_CONFIG_FILE' or \
           key == 'AWS_SHARED_CREDENTIALS_FILE':
            logging.debug(
                'Set option {}={} from environment'.format(key.lower(), val))
            setattr(settings, key.lower(), val)


def user_configuration_input():
    """Obtain user input for the user.

    :return: (okta app url, organization username)

    """
    logging.debug("Obtain user input for the user.")

    all_config_msgs = ['Okta App URL. E.g https://acme.okta.com/home/'
                       'amazon_aws/b07384d113edec49eaa6/123: ',
                       'Organization username. E.g jane.doe@acme.com: ']
    config_details = []
    for config_msg in all_config_msgs:
        user_input = to_unicode(input(config_msg))
        config_details.append(user_input)

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
    (app_url, user_name) = user_configuration_input()

    url = urlparse(app_url.strip())
    okta_username = user_name.strip()

    if url.scheme == '' or url.netloc == '' or url.path == '':
        sys.exit('Okta Application URL invalid or not found. Please reconfigure.')

    okta_aws_app_url = '{}://{}{}'.format(url.scheme, url.netloc, url.path)

    config.set(profile, 'okta_aws_app_url', okta_aws_app_url)
    config.set(profile, 'okta_username', okta_username)
    logging.debug("Config Okta [{}]".format(config))

    with open(okta_file, 'w+', encoding=settings.encoding) as file:
        config.write(file)
        logging.debug(
            "Write new section Okta config [{} {}]".format(okta_file, config))


def set_local_credentials(assume_role_response, role_name, aws_region, aws_output):
    """Write to local files to insert credentials.

    :param assume_role_response AWS AssumeRoleWithSaml response:
    :param role_name the name of the assumed role, used for local profile:
    :param aws_region configured region for aws credential profile:
    :param aws output configured datatype for aws cli output:
    """
    expiration_time = assume_role_response['Credentials']['Expiration']
    aws_access_key = assume_role_response['Credentials']['AccessKeyId']
    aws_secret_key = assume_role_response['Credentials']['SecretAccessKey']
    aws_session_token = assume_role_response['Credentials']['SessionToken']

    if settings.aws_profile is not None:
        role_name = settings.aws_profile

    update_aws_credentials(role_name, aws_access_key, aws_secret_key,
                           aws_session_token)
    update_aws_config(role_name, aws_output, aws_region)

    print_selected_role(role_name, expiration_time)


def update_aws_credentials(profile, aws_access_key, aws_secret_key, aws_session_token):
    """Update AWS credentials in ~/.aws/credentials default file.

    :param profile: AWS profile name
    :param aws_access_key: AWS access key
    :param aws_secret_key: AWS secret access key
    :param aws_session_token: Session token
    :return:

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
    config.set(profile, 'aws_access_key_id', aws_access_key)
    config.set(profile, 'aws_secret_access_key', aws_secret_key)
    config.set(profile, 'aws_session_token', aws_session_token)
    with open(cred_file, 'w+', encoding=settings.encoding) as file:
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
    profile = 'profile {}'.format(profile)
    config = configparser.RawConfigParser()
    if os.path.isfile(config_file):
        config.read(config_file, encoding=settings.encoding)
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, 'output', output)
    config.set(profile, 'region', region)

    with open(config_file, 'w+', encoding=settings.encoding) as file:
        config.write(file)


def initialize_okta_credentials():
    """Set Okta credentials.

    :return: Success or error message

    """
    logging.debug("Set Okta credentials.")
    set_okta_user_name()
    set_okta_password()


def process_options(args):
    """Collect all user-specific credentials and config params."""
    # Point to the correct profile
    if args.okta_profile is not None:
        logging.debug('okta_profile={}'.format(settings.okta_profile))
        settings.okta_profile = args.okta_profile

    if args.configure:
        update_configuration(
            settings.config_file, settings.okta_profile)
        sys.exit(0)

    config = configparser.ConfigParser()
    config.read(settings.config_file)

    # 1: read init file (if it exists)
    process_init_file(config)
    # 2: override with args
    process_arguments(args)
    # 3: override with ENV
    process_environment()

    if settings.okta_aws_app_url is None:
        logging.error(
            "Okta Application URL not found in profile '{}'.\nPlease verify your options"
            " or re-run this application with the --configure flag".format(settings.okta_profile))
        sys.exit(2)
    # Prepare final Okta and AWS app Url
    url = urlparse(settings.okta_aws_app_url)

    if url.scheme == '' or url.netloc == '' or url.path == '':
        logging.error("Okta Application URL invalid. Please check your configuration"
                      " and try again.")
        sys.exit(2)

    okta_org = '{}://{}'.format(url.scheme, url.netloc)
    okta_aws_app_url = '{}{}'.format(okta_org, url.path)
    setattr(settings, 'okta_org', okta_org)
    setattr(settings, 'okta_aws_app_url', okta_aws_app_url)

    # Set username and password for Okta Authentication
    initialize_okta_credentials()
