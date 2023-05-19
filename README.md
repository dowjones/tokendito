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
With the release of tokendito 2.0, many changes and fixes were introduced. It is a breaking release: your configuration needs to be updated, the command line arguments have changed, and support for Python < 3.7 has been removed.
The following changes are part of this release:
- Set the config file to be platform dependent, and follow the XDG standard.
- Extend configuration capabilities.
- Modernize output.
- Change the MFA method from strict match to partial match.
- Mask secrets from output logs.
- Automatically discover AWS URLs.
- Fix authentication with DUO.
- Add support for setting the logging level via both the INI file and ENV vars.
- Add support for Python 3.9, 3.10, and 3.11.
- And many fixes.

Consult [additional notes](https://github.com/dowjones/tokendito/blob/main/docs/README.md) for how to use tokendito.

## Requirements

-   Python 3.7+, or a working Docker environment
-   AWS account(s) federated with Okta

Tokendito is compatible with Python 3 and can be installed with either
pip or pip3.

## Getting started

1.  Install (via PyPi): `pip install tokendito`
2.  Run `tokendito --configure`.
3.  Run `tokendito`.

**NOTE**: Advanced users may shorten the `tokendito` interaction to a [single
command](https://github.com/dowjones/tokendito/blob/main/docs/README.md#single-command-usage).

Have multiple Okta tiles to switch between? View our [multi-tile
guide](https://github.com/dowjones/tokendito/blob/main/docs/README.md#multi-tile-guide).


## Docker

Using Docker eliminates the need to install tokendito and its requirements. We are providing experimental Docker image support in [Dockerhub](https://hub.docker.com/r/tokendito/tokendito)

### Running the container image

Run tokendito with the `docker run` command. Tokendito supports [DCT](https://docs.docker.com/engine/security/trust/), and we encourage you to enforce image signature validation before running any containers.

``` shell
export DOCKER_CONTENT_TRUST=1
```

then

``` shell
docker run --rm -it tokendito/tokendito  --version
```

You must map a volume in the Docker command to allow tokendito to write AWS credentials to your local filesystem for use.  This is done with the `-v` flag.  See [Docker documentation](https://docs.docker.com/engine/reference/commandline/run/#-mount-volume--v---read-only) for help setting the syntax.  The following directories are used by tokendito and should be considered when mapping volumes:

- `/app/.aws/` (AWS credential storage)
- `/app/.config/tokendito/` (tokendito profile storage)

These can be covered by mapping a single volume to both the host and container users' home directories (`/app` is the home directory in the container and must be explicitly defined).  You may also map multiple volumes if you have custom configuration locations and require granularity.

Be sure to set the `-it` flags to enable an interactive terminal session.

On Windows, you can do the following:
``` powershell
docker run --rm -it -v "%USERPROFILE%\.aws":/app/.aws  -v "%USERPROFILE%\.config":/app/.config tokendito/tokendito
```

In a Mac OS system, you can run:
``` shell
docker run --rm -it -v "$HOME/.aws":/app/.aws  -v "$HOME/.config":/app/.config tokendito/tokendito
```

On a Linux system, however, you must specify the user and group IDs for the mount mappings to work as expected.
Additionally the mount points within the container move to a different location:

``` shell
docker run --user $(id -u):$(id -g) --rm -it -v "$HOME/.aws":/.aws  -v "$HOME/.config":/.config tokendito/tokendito
```

Tokendito command line arguments are supported as well.

**NOTE**: In the following examples the entire home directory is exported for simplicity. This is not recommended as it exposes too much data to the running container:

``` shell
docker run --rm -it -v "$HOME":/ tokendito/tokendito \
  --okta-tile https://acme.okta.com/home/amazon_aws/000000000000000000x0/123 \
  --username username@example.com \
  --okta-mfa push \
  --aws-output json \
  --aws-region us-east-1 \
  --aws-profile my-profile-name \
  --aws-role-arn arn:aws:iam::000000000000:role/role-name \
```

Tokendito profiles are supported while using containers provided the proper volume mapping exists.

``` shell
docker run --rm -ti -v "$HOME":/app tokendito/tokendito \
  --profile my-profile-name
```

## Tips, tricks, troubleshooting, examples, and more docs are [here](https://github.com/dowjones/tokendito/blob/main/docs/README.md)

[Contributions are welcome](https://github.com/dowjones/tokendito/blob/main/docs/CONTRIBUTING.md)!
