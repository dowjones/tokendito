# Tokendito Documentation

## Table of Contents

- [Command line Usage](#command-line-usage)
  - [Default usage](#default-usage)
  - [Multi-tile-Guide](#multi-tile-guide)
  - [Single-command usage](#single-command-usage)
  - [Multi-profile usage](#multi-profile-usage)
  - [Automatic credential renewal](#automatic-credential-renewal)
  - [Listing current configuration](#listing-current-configuration)
  - [Additional command line reference](#additional-command-line-reference)
- [Environment variables and user configuration](#environment-variables-and-user-configuration)
  - [Precedence](#precedence)
  - [Environment variables and user configuration table](#environment-variables-and-user-configuration-table)
- [Configuration file location](#configuration-file-location)
- [AWS Roles Discovery](#aws-roles-discovery)
- [Supported MFA methods](#supported-mfa-methods)
- [Installation](#installation)
- [Upgrading](#upgrading)
- [Installing from GitHub](#installing-from-github)
- [Troubleshooting](#troubleshooting)
- [Design and Limitations](#design-and-limitations)

## Command line Usage

### Default usage

Configure your profile by running tokendito with the `--configure` flag, or by populating your `tokendito.ini` file as [here](tokendito.ini.md).
Using --configure will only set the okta_username, okta_todo

Then execute: `tokendito` in your command line.

### Multi-tile Guide

If you have multiple AWS-type Okta tiles assigned to you, please update
your local [tokendito.ini](tokendito.ini.md) file with the links to
your AWS tiles in Okta. You can get the link to your tile by right-clicking on the tile in Okta and selecting \"Copy Link URL.\" This file
supports multiple profiles, in case there is a need to connect with
different Okta Orgs and tiles. tokendito can access the profiles by
name, by passing in the `--profile` parameter.

Without specifying a specific profile, tokendito will look for a default
profile within that file.

### Single-command usage

Tokendito accepts all of the necessary parameters to be able to generate
your STS tokens with a single command. There are a couple of ways to do
this!

You can just pass in your information at runtime:

``` txt
tokendito --username prod_service_user@company.com \
--role-arn arn:aws:iam::123456789000:role/dowjones-engineer \
--okta-mfa push \
--okta-tile https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123 \
```

Or you can put your parameters into a single [profile](tokendito.ini.md) and reference that profile.

``` ini
[engineer]
okta_tile = https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123
okta_username = jane.doe@acme.com
okta_mfa = push
aws_role_arn = arn:aws:iam::123456789000:role/engineer
```

And execute:

``` txt
tokendito --profile engineer
```

### Multi-profile usage

If you need to authenticate to multiple AWS accounts or roles in a single invocation, use `--multi-profiles`. This is useful when you regularly work across several environments (e.g. dev, staging, production) and want to refresh all credentials at once.

`--multi-profiles` can be specified multiple times, with each value referencing a profile section in your [tokendito.ini](tokendito.ini.md) file. Tokendito will authenticate once and then iterate through each profile, assuming the corresponding role and writing credentials to `~/.aws/credentials`. **The tokendito profile name is used as the AWS profile name** — for example, `--multi-profiles dev` will write credentials under the `[dev]` profile in your AWS credentials file.

#### INI file setup

Define each profile in your `tokendito.ini` with its own tile and role:

``` ini
[default]
okta_org = https://acme.okta.com/
okta_username = jane.doe@acme.com
okta_mfa = push

[dev]
okta_tile = https://acme.okta.com/home/amazon_aws/0123456789abcdef/123
aws_role_arn = arn:aws:iam::111111111111:role/dev-engineer

[staging]
okta_tile = https://acme.okta.com/home/amazon_aws/abcdef0123456789/456
aws_role_arn = arn:aws:iam::222222222222:role/staging-engineer

[prod]
okta_tile = https://acme.okta.com/home/amazon_aws/fedcba9876543210/789
aws_role_arn = arn:aws:iam::333333333333:role/prod-readonly
```

Note that values from the `[default]` section (such as `okta_org`, `okta_username`, and `okta_mfa`) are inherited by the other profiles, so you only need to specify what differs in each one.

#### Running with multi-profiles

Refresh credentials for all three environments at once:

``` txt
tokendito --multi-profiles dev --multi-profiles staging --multi-profiles prod
```

This will:

1. Authenticate to Okta once (you are prompted for your password and MFA only on the first profile).
2. For each profile, read its configuration from the INI file, assume the AWS role, and write credentials.
3. Save each set of credentials to `~/.aws/credentials` using the tokendito profile name as the AWS profile name (i.e. `[dev]`, `[staging]`, `[prod]`).

Afterwards you can use the credentials directly with the AWS CLI:

``` txt
aws --profile dev s3 ls
aws --profile staging sts get-caller-identity
aws --profile prod ec2 describe-instances
```

#### Behavior notes

- **Overrides `--profile`**: When `--multi-profiles` is used, any `--profile` argument is ignored.
- **Overrides `--aws-profile`**: The `--aws-profile` flag and the `TOKENDITO_AWS_PROFILE` environment variable are ignored. Instead, the tokendito INI profile name (e.g. `dev`, `staging`) is always used as the AWS profile name in `~/.aws/credentials`.
- **Authentication is shared**: Okta authentication happens only once. Subsequent profiles reuse the session, so you will only see a single MFA prompt.
- **Configuration inheritance**: Each profile inherits values from the `[default]` section of the INI file, so common settings only need to be specified once.

### Automatic credential renewal

Tokendito can automatically renew your AWS credentials before they expire, eliminating the need to manually re-authenticate throughout your workday.

#### Quick start

Enable auto-renewal for your profiles:

``` txt
tokendito --auto-renew-enable \
    --auto-renew-profiles default \
    --auto-renew-profiles dev \
    --auto-renew-profiles prod
```

Check the status:

``` txt
tokendito --auto-renew-status
```

Disable auto-renewal:

``` txt
tokendito --auto-renew-disable
```

#### How it works

1. **Background service**: On macOS, a launchd service monitors your credentials in the background
2. **Smart scheduling**: The daemon calculates when credentials expire and sleeps until renewal is needed (no constant polling)
3. **Batch renewal**: Multiple profiles expiring around the same time are renewed together with a single Okta authentication
4. **Automatic recovery**: The service automatically restarts after system sleep/wake

#### Configuration

Settings are stored in your `tokendito.ini` file:

``` ini
[auto-renewal]
enabled = true
profiles = default, dev, prod
renewal_threshold_minutes = 30    # Renew 30 minutes before expiration
check_interval_minutes = 10       # Fallback check interval
max_sleep_minutes = 60            # Check config at least every 60 minutes
```

#### Platform support

- **macOS**: Full support with automatic launchd service
- **Linux/Windows**: Manual daemon execution required (or use systemd/Task Scheduler)

For complete documentation, see [AUTO_RENEWAL.md](AUTO_RENEWAL.md).

### Listing current configuration

To view your current configuration values and where they are set from, use:

``` txt
tokendito --configure list
```

This displays a table showing each setting's name, current value, source type (default, ini-file, or env-var), and location:

``` txt
                        Name    Value                             Source          Location
                        ----    -----                             ------          --------
  [user]
                  config_dir    /Users/you/.config/tokendito      default
                 config_file    /Users/you/.config/tokendito...   default
              config_profile    default                           default
               login_timeout    0                                 default
                    loglevel    INFO                              default
  [aws]
                     profile    <not set>                         default
                      region    us-east-1                         default
  [okta]
                    username    jane.doe@acme.com                 ini-file        /Users/you/.config/tokendito/tokendito.ini
                    password    ****                              ini-file        /Users/you/.config/tokendito/tokendito.ini
                         org    https://acme.okta.com             env-var         TOKENDITO_OKTA_ORG
```

You can combine it with `--profile` to inspect a specific profile:

``` txt
tokendito --profile engineer --configure list
```

### Additional command line reference

``` txt
usage: tokendito [-h] [--version] [--configure] [--username OKTA_USERNAME] [--password OKTA_PASSWORD] [--profile USER_CONFIG_PROFILE] [--config-file USER_CONFIG_FILE]
                 [--loglevel {DEBUG,INFO,WARN,ERROR}] [--log-output-file USER_LOG_OUTPUT_FILE] [--aws-config-file AWS_CONFIG_FILE] [--aws-output AWS_OUTPUT]
                 [--aws-profile AWS_PROFILE] [--aws-region AWS_REGION] [--aws-role-arn AWS_ROLE_ARN] [--aws-shared-credentials-file AWS_SHARED_CREDENTIALS_FILE]
                 [--okta-org OKTA_ORG | --okta-tile OKTA_TILE] [--okta-client-id OKTA_CLIENT_ID] [--okta-mfa OKTA_MFA] [--okta-mfa-response OKTA_MFA_RESPONSE]
                 [--use-device-token] [--quiet]

Gets an STS token to use with the AWS CLI and SDK.

options:
  -h, --help            show this help message and exit.
  --version             Displays version and exit.
  --configure [list]    Prompt user for configuration parameters.
                        Use '--configure list' to display current settings and their sources.
  --username OKTA_USERNAME
                        username to log in to Okta. You can also use the TOKENDITO_OKTA_USERNAME environment variable.
  --password OKTA_PASSWORD
                        password to log in to Okta. You can also use the TOKENDITO_OKTA_PASSWORD environment variable.
  --profile USER_CONFIG_PROFILE
                        Tokendito configuration profile to use.
  --multi-profiles USER_CONFIG_PROFILE
                        Similar to --profile, but can be specified multiple times.
                        Note: Using this will override --profile and cause --aws-profile to be ignored and replaced with this value.
  --config-file USER_CONFIG_FILE
                        Use an alternative configuration file. Defaults to tokendito.ini with location depending on the OS.
  --loglevel {DEBUG,INFO,WARN,ERROR}, -l {DEBUG,INFO,WARN,ERROR}
                        [DEBUG|INFO|WARN|ERROR], default loglevel is WARNING.
  --log-output-file USER_LOG_OUTPUT_FILE
                        Optional file to log output to.
  --aws-config-file AWS_CONFIG_FILE
                        AWS Configuration file to write to.
  --aws-output AWS_OUTPUT
                        Sets the output type for the AWS profile.
  --aws-profile AWS_PROFILE
                        AWS profile to save as in the credentials file.
  --aws-region AWS_REGION
                        Sets the region for the AWS profile.
  --aws-role-arn AWS_ROLE_ARN
                        Sets the IAM role.
  --aws-shared-credentials-file AWS_SHARED_CREDENTIALS_FILE
                        AWS credentials file to write to.
  --okta-org OKTA_ORG   Set the Okta Org base URL. This enables role auto-discovery.
  --okta-tile OKTA_TILE
                        Okta tile URL to use.
  --okta-client-id OKTA_CLIENT_ID
                        For OIE enabled Orgs this sets the Okta client ID to replace the value found by tokendito. It is used in the authorize code flow.
  --okta-mfa OKTA_MFA   Sets the MFA method. You can also use the TOKENDITO_OKTA_MFA environment variable.
  --okta-mfa-response OKTA_MFA_RESPONSE
                        Sets the MFA response to a challenge. You can also use the TOKENDITO_OKTA_MFA_RESPONSE environment variable.
  --use-device-token    Use device token across sessions.
  --quiet               Suppress output.
  --login-timeout TIMEOUT     
                        Login timeout in seconds (default: 0 for disabled). You can also use the TOKENDITO_LOGIN_TIMEOUT environment variable.
```

Regarding the storage of the Okta password, we are fans of automation but do not recommend passing in the password to tokendito via plaintext or storing
it in your environment locally.

## Environment variables and user configuration

Tokendito supports the use of environment variables and user configuration equivalents to specify the default values for most options.

### Precedence

Credentials and configuration settings take precedence in the following order:

1. Command line options -- Overrides settings in any other location. You can specify `--username`, `--role-arn`, `--okta-tile`, and `--okta-mfa` as parameters on the command line.
1. Environment variables -- You can store values in your system\'s environment variables. It overrides the configuration file.
1. User configuration file -- The user configuration file is updated when you run the command tokendito \--configure. Tokendito uses [platformdirs](https://github.com/platformdirs/platformdirs) to store user configuration in the [tokendito.ini](tokendito.ini.md) file. This file can contain the credential details for the default profile and any named profiles.

### Environment variables and user configuration table

The following table lists the environment variable and user configuration entry equivalent for the given command line option.

| Command line option | Environment variable | User configuration |
| ------------------- | -------------------- | ------------------ |
| `--username` | `TOKENDITO_OKTA_USERNAME`        | `okta_username` |
| `--password` | `TOKENDITO_OKTA_PASSWORD` |   |
| `--profile`  | `TOKENDITO_USER_CONFIG_PROFILE` | `profile` |
| `--multi-profiles` | | |
| `--config-file` | `TOKENDITO_USER_CONFIG_FILE` | |
| `--loglevel` | `TOKENDITO_USER_LOGLEVEL` | `loglevel` |
| `--log-output-file` | `TOKENDITO_USER_LOG_OUTPUT_FILE`        | `log_output_file` |
| `--aws-config-file` | `TOKENDITO_AWS_CONFIG_FILE`        | `aws_config_file` |
| `--aws-output` | `TOKENDITO_AWS_OUTPUT`        | `aws_output` |
| `--aws-profile` | `TOKENDITO_AWS_PROFILE`        | `aws_profile` |
| `--aws-region` | `TOKENDITO_AWS_REGION`       | `aws_region` |
| `--aws-role-arn` | `TOKENDITO_AWS_ROLE_ARN`       | `aws_role_arn` |
| `--aws-shared-credentials-file` | `TOKENDITO_AWS_SHARED_CREDENTIALS_FILE`        | `aws_shared_credentials_file` |
| `--okta-org` | `TOKENDITO_OKTA_ORG`        | `okta_org` |
| `--okta-tile` | `TOKENDITO_OKTA_TILE`        | `okta_tile` |
| `--okta-mfa` | `TOKENDITO_OKTA_MFA`        | `okta_mfa` |
| `--okta-mfa-response` | `TOKENDITO_OKTA_MFA_RESPONSE`        | `okta_mfa_response` |
| `--use-device-token` | `TOKENDITO_USER_USE_DEVICE_TOKEN`        | `user_use_device_token` |
| `--quiet` | `TOKENDITO_USER_QUIET`        | `quiet` |
| `--login-timeout` | `TOKENDITO_USER_LOGIN_TIMEOUT`        | `login_timeout` |

## Configuration file location

With Tokendito version 2.0 we changed the location of the configuration file from `$HOME/.aws/okta_auth` to be platform-independent, and following the standard location for configuration files in each supported platform. `tokendito --help` will show the exact location on your system.

- On Linux: `/home/<username>/.config/tokendito/tokendito.ini`
- On MacOS: `/Users/<username>/Library/Preferences/tokendito/tokendito.ini`
- On Windows: `%USERPROFILE%\AppData\Local\tokendito\tokendito.ini`

## AWS Roles Discovery

Tokendito will discover all your available AWS Roles configured in Okta, returning a list for you to select from, simply by calling:
`tokendito --okta-org ${YOUR ORG OKTA URL}`. For instance, `tokendito --okta-org https://acme.oktapreview.com`

## Supported MFA methods

- Native Okta factors (Push, phone call, SMS, TOTP) except Biometrics (FIDO WebAuthn) and Number Challenge
- Google Authenticator TOTP
- Duo Push, phone call, SMS, and TOTP

## Installation

### Standard Installation

```bash
pip install tokendito
```

### System-wide Installation (Multiple Users)

For enterprise Linux systems (RHEL, Amazon Linux, CentOS, etc.), use a shared virtual environment:

```bash
# Create and set up the virtual environment
sudo python3 -m venv /opt/tokendito
sudo /opt/tokendito/bin/pip install tokendito

# Make it accessible to all users
sudo chmod -R a+rX /opt/tokendito
sudo ln -s /opt/tokendito/bin/tokendito /usr/bin/tokendito

# Verify installation
tokendito --version
```

**Note:** The system-wide installation approach using a virtual environment ensures:
- All users can access tokendito
- No conflicts with system Python packages
- Clean upgrades and dependency management
- Works reliably across different Linux distributions

## Upgrading

```bash
pip install --upgrade tokendito
```

For system-wide venv-based installations:
```bash
sudo /opt/tokendito/bin/pip install --upgrade tokendito
```

## Installing from GitHub

`pip install git+ssh://git@github.com/dowjones/tokendito.git@<version>`

For instance,
`pip install git+ssh://git@github.com/dowjones/tokendito.git@2.0.0`

## Troubleshooting

Configuration issues with tokendito can usually be addressed by
validating your environment\'s AWS configuration profile(s) located at:

[\$HOME/.aws/config](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

[\$HOME/.aws/credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

[tokendito.ini](tokendito.ini.md)

## Design and Limitations

- This tool does not cache and reuse Okta session IDs.

[Pull requests](CONTRIBUTING.md) welcome!
