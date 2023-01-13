<p align="center">
  <img src="https://raw.githubusercontent.com/dowjones/tokendito/main/docs/tokendito.png"/>
</p>

## Generate temporary AWS credentials via Okta.

[![image](https://img.shields.io/github/actions/workflow/status/dowjones/tokendito/test.yml)](https://github.com/dowjones/tokendito/actions)
[![image](https://img.shields.io/pypi/pyversions/tokendito?color=blueviolet)](https://pypi.org/project/tokendito/)
[![image](https://img.shields.io/github/actions/workflow/status/dowjones/tokendito/woke.yml?label=woke)](https://github.com/dowjones/tokendito/actions)
[![image](https://img.shields.io/badge/license-Apache%202.0-ff69b4)](https://github.com/dowjones/tokendito/blob/main/LICENSE.txt)
[![image](https://img.shields.io/badge/OS-Mac%2C%20Windows%2C%20Linux-9cf)](https://github.com/dowjones/tokendito/)
[![image](https://img.shields.io/coverallsCoverage/github/dowjones/tokendito)](https://coveralls.io/github/dowjones/tokendito) [![image](https://img.shields.io/pypi/dm/tokendito)](https://pypistats.org/packages/tokendito)

#

![image](https://raw.githubusercontent.com/dowjones/tokendito/main/docs/tokendito-scaled.gif)

Use `tokendito` to generate temporary AWS credentials via Okta for
programmatic authentication to AWS. Tokendito signs you into Okta and
uses your existing AWS integration to broker a SAML assertion into
your AWS accounts, returning
[STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
tokens into your local `~/.aws/credentials` file.

## What's new
With the release of tokendito 2.0, many changes and fixes were introduced. It is a breaking release: your configuration needs to be updated, the command line arguments have changed, and support for python < 3.7 has been removed.
The following changes are part of this release:
- Set the config file to be platform dependent, and follow the XDG standard.
- Extend configuration capabilities.
- Modernize output.
- Change the MFA method from strict match to partial match.
- Mask secrets from output logs.
- Automatically discover AWS URLs.
- Fix authentication with DUO.
- Add support for setting the logging level via both the INI file and ENV vars.
- Add support for Python 3.9 and 3.10.
- And many fixes.

Consult [additional notes](docs/README.md) for how to use tokendito. 

## Requirements

-   Python 3.7+
-   AWS account(s) federated with Okta

Tokendito is compatible with Python 3 and can be installed with either
pip or pip3.

## Getting started

1.  Install (via PyPi): `pip install tokendito`
2.  Run `tokendito --configure`.
3.  Run `tokendito`.

**NOTE**: Advanced users may shorten the `tokendito` interaction to a [single
command](docs/README.md#single-command-usage).

Have multiple Okta tiles to switch between? View our [multi-tile
guide](docs/README.md#multi-tile-guide).

### Tips, tricks, troubleshooting, examples, and more docs are [here](docs/README.md)! Also, [contributions are welcome](docs/CONTRIBUTING.md)!
