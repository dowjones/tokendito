<p align="center">
  <img src="https://raw.githubusercontent.com/dowjones/tokendito/master/docs/tokendito.png"/>
</p>

Generate temporary AWS credentials via Okta.

[![image](https://github.com/dowjones/tokendito/workflows/Lint%20and%20Test/badge.svg)](https://github.com/dowjones/tokendito/actions)
[![image](https://img.shields.io/badge/python-3.7%2C%203.8%2C%203.9%2C%203.10%2C%203.11-blueviolet)](https://pypi.org/project/tokendito/)
[![image](https://github.com/dowjones/tokendito/workflows/Woke/badge.svg)](https://github.com/dowjones/tokendito/actions)
[![image](https://img.shields.io/badge/license-Apache%202.0-ff69b4)](https://github.com/dowjones/tokendito/blob/master/LICENSE.txt)
[![image](https://img.shields.io/badge/OS-Mac%2C%20Windows%2C%20Linux-9cf)](https://github.com/dowjones/tokendito/)
[![image](https://coveralls.io/repos/github/dowjones/tokendito/badge.svg)](https://coveralls.io/github/dowjones/tokendito)

# \|

![image](https://raw.githubusercontent.com/dowjones/tokendito/master/docs/tokendito-scaled.gif)

NOTE: Advanced users may shorten the tokendito interaction to a [single
command](docs/README.md#single-command-usage).

Use tokendito to generate temporary AWS credentials via Okta for
programmatic authentication to AWS. Tokendito signs you in to Okta and
uses your existing AWS integration to broker your SAML assertion into
your AWS accounts, returning
[STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
tokens into your local `~/.aws/credentials` file.

## What's new
With the release of tokendito 2.0, we are introcucing many changes and fixes. It is a breaking release, your configuration needs to be updated and support for python < 3.7 is dropped. Consult the [release notes](releases/latest) page for a list of changes, and [additional notes](docs/README.md) for details.  

## Requirements

-   Python 3.7+
-   Your AWS account is federated in Okta

tokendito is compatible with python 3, and can be installed with either
pip or pip3.

## Getting started

1.  Install (via PyPi): `pip install tokendito`
2.  Run `tokendito --configure`.
3.  Run `tokendito`.

Have multiple Okta tiles to switch between? View our [multi-tile
guide](docs/README.md#multi-tile-guide).

### Tips, tricks, troubleshooting, examples, and more docs are [here](docs/README.md)! Also, [contributions are welcome](docs/CONTRIBUTING.md)!
