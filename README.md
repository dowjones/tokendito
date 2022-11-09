![image](https://raw.githubusercontent.com/dowjones/tokendito/master/docs/tokendito.png){.align-center}

Generate temporary AWS credentials via Okta.

[![image](https://github.com/dowjones/tokendito/workflows/Lint%20and%20Test/badge.svg)](https://github.com/dowjones/tokendito/actions)

[![image](https://img.shields.io/badge/python-3.6%2C%203.7%2C%203.8%2C%203.9%2C%203.10-blueviolet)](https://pypi.org/project/tokendito/)

[![image](https://github.com/dowjones/tokendito/workflows/Woke/badge.svg)](https://github.com/dowjones/tokendito/actions)

[![image](https://img.shields.io/badge/license-Apache%202.0-ff69b4)](https://github.com/dowjones/tokendito/blob/master/LICENSE.txt)

[![image](https://img.shields.io/badge/OS-Mac%2C%20Windows%2C%20Linux-9cf)](https://github.com/dowjones/tokendito/)

[![image](https://coveralls.io/repos/github/dowjones/tokendito/badge.svg)](https://coveralls.io/github/dowjones/tokendito)

# \|

![image](https://raw.githubusercontent.com/dowjones/tokendito/master/docs/tokendito-scaled.gif)

NOTE: Advanced users may shorten the tokendito interaction to a [single
command](https://github.com/dowjones/tokendito/tree/master/docs#single-command-usage).

Use tokendito to generate temporary AWS credentials via Okta for
programmatic authentication to AWS. Tokendito signs you in to Okta and
uses your existing AWS integration to broker your SAML assertion into
your AWS accounts, returning
[STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
tokens into your local `~/.aws/credentials` file.

## Requirements

-   Python 3.6+
-   Your AWS account is federated in Okta

tokendito is compatible with python 3, and can be installed with either
pip or pip3.

## Getting started

1.  Install (via PyPi): `pip install tokendito`
2.  Run `tokendito --configure`.
3.  Run `tokendito`.

Have multiple Okta tiles to switch between? View our [multi-tile
guide](https://github.com/dowjones/tokendito/tree/master/docs#multi-tile-guide).

### Tips, tricks, troubleshooting, examples, and more docs are [here](https://github.com/dowjones/tokendito/blob/master/docs/README.md)! Also, [contributions are welcome](https://github.com/dowjones/tokendito/blob/master/docs/CONTRIBUTING.md)!
