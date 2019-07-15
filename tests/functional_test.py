"""
Functional tests for tokendito cli tool.

Usage:
python tests/functional_test.py --role <role-arn> --mfa <mfa-option>

Requirements:
1) the push mfa option enabled for your Okta user.
2) AWS CLI installed.
"""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)


import argparse
import logging
from os import path
import re
import subprocess
import sys

from future import standard_library


standard_library.install_aliases()

logfile = "tokendito_functional_test.log"
logging.basicConfig(filename=logfile, level=logging.DEBUG,
                    format='%(asctime)s :: %(levelname)s :: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')


def setup():
    """Parse command line arguments.

    :return: args parse object

    """
    parser = \
        argparse.ArgumentParser(
            description='Functional tests for tokendito.')
    parser.add_argument('--role-arn', '-R', required=True, type=helpers.to_unicode,
                        help='a role arn for an assignment within'
                        'your default ~/.okta_auth profile to continue this test.')
    parser.add_argument('--mfa-method', '-mm', required=True, type=helpers.to_unicode,
                        help='Please supply an MFA option to continue this test.')
    parser.add_argument('--okta-profile', '-op', type=helpers.to_unicode,
                        default='default',
                        help='Okta configuration profile to use.')
    args = parser.parse_args()
    return args


def collect_args():
    """Reconcile args required for this test with args for tool."""
    test_args = setup()
    tool_args = helpers.setup()
    for arg in test_args.__dict__:
        if test_args.__dict__[arg]:
            tool_args.__dict__[arg] = test_args.__dict__[arg]
    validate_role(tool_args.role_arn)
    return tool_args


def validate_role(role):
    """Validate provided role arn."""
    regex = re.compile('arn:aws:iam::*:')
    if len(re.findall(regex, role)) == 0:
        print("Error: invalid role ARN syntax.")
        exit(1)


def get_pip_version():
    """Identify running version of python and select pip version accordingly."""
    pip_version = 'pip '
    if sys.version_info.major == 3:
        pip_version = 'pip3 '
    return pip_version


def check_tokendito_installed():
    """Uninstall tokendito if it is already installed.

    This ensures you are testing your current state and not a previous version.
    """
    pip_version = get_pip_version()
    proc = pip_version + 'show tokendito'
    list_packages = run_process(proc)

    if list_packages["stdout"]:
        print("Deleting a preexisting installation of tokendito.")
        proc = pip_version + 'uninstall tokendito --yes'
        return run_process(proc)


def run_process(proc):
    """Spawn a child process, pipe and format stdout to logfile.

    Returns a dict with stdout log, exit status, and command executed.
    """
    short_proc = proc.split("--password")[0]
    logging.debug("Running proc $ {}".format(short_proc))

    process = subprocess.Popen(
        [proc], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    op, err = process.communicate()
    rc = process.returncode

    if rc == 1 and proc == "pip show tokendito":
        logging.info("tokendito installation not found.")
    elif rc != 0:
        print(rc)
        print(proc)
        logging.error(
            "There was an error running command \n$ {}\n{}".format(
                short_proc, err))
        exit(1)
    else:
        logging.debug(op)

    result = {
        "stdout": op,
        "exit_status": rc,
        "process": short_proc
    }
    return result


def test_pip_install():
    """Uninstall and install tokendito as a python package."""
    repo_root = path.dirname(path.dirname(path.abspath(__file__)))
    pip_version = get_pip_version()
    proc = pip_version + 'install -e ' + repo_root
    return run_process(proc)


def test_as_package(arg_string):
    """Test tokendito execution as a python package."""
    proc = ('tokendito' + arg_string)
    print("Contacting MFA device...")
    return run_process(proc)


def test_as_script(arg_string):
    """Test tokendito execution as a script."""
    proc = ('python tokendito/tokendito.py' + arg_string)
    print("Contacting MFA device...")
    return run_process(proc)


def test_as_module(arg_string):
    """Test tokendito execution as a module."""
    proc = ('python -m tokendito' + arg_string)
    print("Contacting MFA device...")
    return run_process(proc)


def test_aws_cli(args):
    """Validate that tokendito writes working api keys to the environment."""
    aws_role_name = args.role_arn.split("/")[-1]
    proc = 'aws --profile ' + aws_role_name + ' sts get-caller-identity'
    return run_process(proc)


def calculate_results(test_results):
    """Compile test results into passed vs failed."""
    failed_tests = [d for d in test_results if d["exit_status"]]

    if len(failed_tests) == 0:
        print("All " + str(len(test_results)) + " tests passed.")
        exit(0)

    print(str(len(failed_tests)) + " out of " +
          str(len(test_results)) + " tests failed.")

    for test in failed_tests:
        print("Test failed: \n" + test["process"].split("--password")[0])
        print(test["stdout"])


def main():
    """Test installation and execution of tokendito tool."""
    tool_args = collect_args()
    check_tokendito_installed()
    helpers.process_options(tool_args)

    arg_string = (' --role-arn ' + tool_args.role_arn +
                  ' --mfa-method ' + tool_args.mfa_method +
                  " --password='{}'".format(settings.okta_password))

    if "profile" in tool_args:
        arg_string += ' --okta-profile={}'.format(tool_args.okta_profile)

    test_results = []
    test_results.append(test_pip_install())
    test_results.append(test_as_module(arg_string))
    test_results.append(test_aws_cli(tool_args))
    test_results.append(test_as_script(arg_string))
    test_results.append(test_aws_cli(tool_args))
    test_results.append(test_as_package(arg_string))
    test_results.append(test_aws_cli(tool_args))
    calculate_results(test_results)


if __name__ == '__main__' and __package__ is None:
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
    from tokendito import helpers, settings
    main()
