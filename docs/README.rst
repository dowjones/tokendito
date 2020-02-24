==========
More Docs!
==========

.. contents:: Table of contents
.. section-numbering::

Usage Examples:
---------------

Default usage
"""""""""""""
Configure your profile by running tokendito with the ``--configure`` flag, or by populating your ``$HOME/.aws/okta_auth`` according to the `example <okta_auth.example>`_ .

Then execute: ``tokendito`` in your command line.


Multi-tile Guide!
"""""""""""""""""
If you have multiple AWS-type Okta tiles assigned to you, please update your local `$HOME/.aws/okta_auth <okta_auth.example>`_ with the links to your AWS tiles in Okta. You can get the link to your tile by right clicking on the tile in Okta and selecting "Copy Link URL."
This file supports multiple profiles, in case there is a need to connect with different Okta Orgs and tiles. tokendito can access the profiles by name, by passing in the ``--okta-profile`` parameter.

ex:
``tokendito --okta-profile my_prod_okta_tile``

Without specifying a specific profile, tokendito will look for a default profile within that file.


Single-command usage
""""""""""""""""""""
tokendito accepts all of the necessary parameters to be able to generate your STS tokens with a single command. There are a couple of ways to do this!

You can just pass in your information at runtime:

.. code-block:: sh

    tokendito --username prod_service_user@company.com \
    --role-arn arn:aws:iam::123456789000:role/dowjones-hammer-engineer \
    --mfa-method push \
    --okta-aws-app-url https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123 \


Or you can put your parameters into a single `profile <okta_auth.example>`_ in ``$HOME/.aws/okta_auth`` and reference that profile.

.. code-block:: txt

    [hammer-engineer]
    okta_aws_app_url = https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123
    okta_username = jane.doe@acme.com
    mfa_method = push
    role_arn = arn:aws:iam::123456789000:role/dowjones-hammer-engineer


And execute:

.. code-block:: sh

    tokendito -op hammer-engineer

Regarding the Okta password, we are fans of automation but do not recommend passing in the password to tokendito via plaintext or storing it in your environment locally.

Additional Usage Reference
--------------------------

.. code-block:: txt

    usage: tokendito  [-h] [--version] [--configure] [--username USERNAME]
                      [--password PASSWORD] [--config-file CONFIG_FILE]
                      [--okta-aws-app-url OKTA_AWS_APP_URL]
                      [--okta-profile OKTA_PROFILE] [--aws-region AWS_REGION]
                      [--aws-output AWS_OUTPUT] [--aws-profile AWS_PROFILE]
                      [--mfa-method MFA_METHOD] [--mfa-response MFA_RESPONSE]
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
      --config-file CONFIG_FILE, -C CONFIG_FILE
                            Use an alternative configuration file
      --okta-aws-app-url OKTA_AWS_APP_URL, -ou OKTA_AWS_APP_URL
                            Okta App URL to use.
      --okta-profile OKTA_PROFILE, -op OKTA_PROFILE
                            Okta configuration profile to use.
      --aws-region AWS_REGION, -r AWS_REGION
                            Sets the AWS region for the profile
      --aws-output AWS_OUTPUT, -ao AWS_OUTPUT
                            Sets the AWS output type for the profile
      --aws-profile AWS_PROFILE, -ap AWS_PROFILE
                            Override AWS profile to save as in the credentials
                            file.
      --mfa-method MFA_METHOD, -mm MFA_METHOD
                            Sets the MFA method
      --mfa-response MFA_RESPONSE, -mr MFA_RESPONSE
                            Sets the MFA response to a challenge
      --role-arn ROLE_ARN, -R ROLE_ARN
                            Sets the IAM role
      --output-file OUTPUT_FILE, -o OUTPUT_FILE
                            Log output to filename
      --loglevel {DEBUG,INFO,WARN,ERROR}, -l {DEBUG,INFO,WARN,ERROR}
                            [DEBUG|INFO|WARN|ERROR], default loglevel is ERROR.
                            Note: DEBUG level may display credentials


Supported MFA Options:
""""""""""""""""""""""
- Native Okta factors (push, call, sms, TOTP) *except Biometrics (FIDO webauthn)*
- Google Authenticator TOTP
- Duo (push, call, sms, TOTP) NOTE: These methods are currently *not* pre-configurable in tokendito settings and have to be selected during runtime.


To upgrade:
"""""""""""
``pip install --upgrade tokendito``


Installing from github:
"""""""""""""""""""""""

``pip install git+ssh://git@github.com/dowjones/tokendito.git@<version>``

For instance, ``pip install git+ssh://git@github.com/dowjones/tokendito.git@1.0.1``

Troubleshooting:
----------------

Configuration issues with tokendito can usually be addressed by validating your environment's AWS configuration profile(s) located at:

`$HOME/.aws/config <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html>`_

`$HOME/.aws/credentials <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html>`_

`$HOME/.aws/okta_auth <okta_auth.example>`_


Design & Limitations
--------------------

* This tool does not cache and reuse Okta session IDs

`Pull requests welcome <CONTRIBUTING.rst>`_!
