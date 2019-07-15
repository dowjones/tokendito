==========
More Docs!
==========

.. contents:: Table of contents
.. section-numbering::

Additional Usage Reference
--------------------------

.. code-block:: sh

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

To upgrade:
"""""""""""
``pip install tokendito --upgrade``


Installing from github:
"""""""""""""""""""""""

``pip install git+ssh://git@github.com/dowjones/tokendito.git@<version>``

For instance, ``pip install git+ssh://git@github.com/dowjones/tokendito.git@1.0.0``

Troubleshooting:
""""""""""""""""
Validate your environment's AWS configuration profile(s) located at:

``$HOME/.aws/config``

``$HOME/.aws/credentials``

``$HOME/.aws/okta_auth``


Multi-tile Guide!
-----------------
If you have multiple AWS-type Okta tiles assigned to you, please update your local `$HOME/.aws/okta_auth <okta_auth.example>`_ with the links to your AWS tiles in Okta. You can get the link to your tile by right clicking on the tile in Okta and selecting "Copy Link URL." 
This file supports multiple profiles, in case there is a need to connect with different Okta Orgs and tiles. tokendito can access the profiles by name, by passing in the ``--okta-profile`` parameter.

ex:
``tokendito --okta-profile my_prod_okta_tile``

Without specifying a specific profile, tokendito will look for a default profile within that file.


Design & Limitations
--------------------

* This tool does not cache and reuse Okta session IDs

`Pull requests welcome <CONTRIBUTING.rst>`_!
