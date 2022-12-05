## Table of Contents

* [Usage Examples](#usage-examples)
    * [Default usage](#default-usage)
    * [Multi-tile-Guide](#multi-tile-guide) 
    * [Single-command usage](#single-command-usage)
* [Additional Usage Reference](#additional-usage=reference)
    * [Supported MFA Options](#supported-mfa-options)
    * [To upgrade](#to-upgrade)
    * [Installing from github](#installing-from-github) 
* [Troubleshooting](#troubleshooting)
* [Design and Limitations](#design-and-limitations)
* [Configuration settings and precedence](#configuration-settings-and-precedence)



# Usage Examples  

## Default usage

Configure your profile by running tokendito with the `--configure` flag, or by populating your `tokendito.ini` file as [here](tokendito.ini.md).

Then execute: `tokendito` in your command line.

## Multi-tile Guide

If you have multiple AWS-type Okta tiles assigned to you, please update
your local [tokendito.ini](tokendito.ini.md) file with the links to
your AWS tiles in Okta. You can get the link to your tile by right
clicking on the tile in Okta and selecting \"Copy Link URL.\" This file
supports multiple profiles, in case there is a need to connect with
different Okta Orgs and tiles. tokendito can access the profiles by
name, by passing in the `--profile` parameter.

ex: `tokendito --profile my_prod_okta_tile`

Without specifying a specific profile, tokendito will look for a default
profile within that file.

## Single-command usage

tokendito accepts all of the necessary parameters to be able to generate
your STS tokens with a single command. There are a couple of ways to do
this!

You can just pass in your information at runtime:

``` sh
tokendito --username prod_service_user@company.com \
--role-arn arn:aws:iam::123456789000:role/dowjones-hammer-engineer \
--mfa push \
--okta-aws-tile https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123 \
```

Or you can put your parameters into a single [profile](tokendito.ini.md) and reference that profile.

``` txt
[hammer-engineer]
okta_aws_tile = https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123
okta_username = jane.doe@acme.com
mfa = push
role_arn = arn:aws:iam::123456789000:role/dowjones-hammer-engineer
```

And execute:

``` sh
tokendito -op hammer-engineer
```

Regarding the Okta password, we are fans of automation but do not
recommend passing in the password to tokendito via plaintext or storing
it in your environment locally.


# Additional Usage Reference

``` txt
usage: tokendito  [-h] [--version] [--configure] [--username USERNAME]
                  [--password PASSWORD] [--config-file CONFIG_FILE]
                  [--okta-aws-tile OKTA_AWS_APP_URL]
                  [--profile OKTA_PROFILE] [--aws-region AWS_REGION]
                  [--aws-output AWS_OUTPUT] [--aws-profile AWS_PROFILE]
                  [--mfa MFA_METHOD] [--mfa-response MFA_RESPONSE]
                  [--role-arn ROLE_ARN] [--output-file OUTPUT_FILE]
                  [--loglevel {DEBUG,INFO,WARN,ERROR}]

Gets a STS token to use with the AWS CLI

optional arguments:
  -h, --help            show this help message and exit
  --version, -v         Displays version and exit
  --configure, -c       Prompt user for configuration parameters
  --username USERNAME, -u USERNAME
                        username to login to Okta. You can also use the
                        OKTA_USERNAME environment variable.
  --password PASSWORD, -p PASSWORD
                        password to login to Okta. You can also user the
                        OKTA_PASSWORD environment variable.
  --profile OKTA_PROFILE, -op OKTA_PROFILE
                        User profile to use.
  --config-file CONFIG_FILE, -C CONFIG_FILE
                        Use an alternative configuration file
  --okta-aws-tile OKTA_AWS_APP_URL, -ou OKTA_AWS_APP_URL
                        Okta App URL to use.
  --aws-region AWS_REGION, -r AWS_REGION
                        Sets the AWS region for the profile
  --aws-output AWS_OUTPUT, -ao AWS_OUTPUT
                        Sets the AWS output type for the profile
  --aws-profile AWS_PROFILE, -ap AWS_PROFILE
                        Override AWS profile to save as in the credentials
                        file.
  --mfa MFA_METHOD, -mm MFA_METHOD
                        Sets the MFA method
  --mfa-response MFA_RESPONSE, -mr MFA_RESPONSE
                        Sets the MFA response to a challenge
  --role-arn ROLE_ARN, -R ROLE_ARN
                        Sets the IAM role
  --output-file OUTPUT_FILE, -o OUTPUT_FILE
                        Log output to filename
  --loglevel {DEBUG,INFO,WARN,ERROR}, -l {DEBUG,INFO,WARN,ERROR}
                        [DEBUG|INFO|WARN|ERROR], default loglevel is WARNING.
                        Note: DEBUG level may display credentials
```

## Supported MFA Options

-   Native Okta factors (push, call, sms, TOTP) except Biometrics (FIDO
    webauthn)
-   Google Authenticator TOTP
-   Duo (push, call, sms, TOTP)

## To upgrade

`pip install --upgrade tokendito`

## Installing from github

`pip install git+ssh://git@github.com/dowjones/tokendito.git@<version>`

For instance,
`pip install git+ssh://git@github.com/dowjones/tokendito.git@2.0.0`

# Troubleshooting

Configuration issues with tokendito can usually be addressed by
validating your environment\'s AWS configuration profile(s) located at:

[\$HOME/.aws/config](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

[\$HOME/.aws/credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

[tokendito.ini](tokendito.ini.md)

# Design and Limitations

-   This tool does not cache and reuse Okta session IDs


# Configuration settings and precedence

tokendito uses credentials and configuration settings located in
multiple places, such as the system or user environment variables, local
configuration files, or explicitly declared on the command line as a
parameter. Certain locations take precedence over others. The AWS CLI
credentials and configuration settings take precedence in the following
order:

1)  Command line options -- Overrides settings in any other location. You can specify \--username, \--role-arn, \--okta-aws-tile, and \--mfa as parameters on the command line.
2)  Environment variables -- You can store values in your system\'s environment variables.
3)  User configuration file -- The user configuration file is updated when you run the command tokendito \--configure. tokendito uses [platformdirs](https://github.com/platformdirs/platformdirs) to store user configuration in the [tokendito.ini](tokendito.ini.md)file. This file can contain the credential details for the default profile and any named profiles.

[Pull requests welcome](CONTRIBUTING.md)!
