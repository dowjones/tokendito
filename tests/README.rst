=======
Testing
=======

To run basic tests, execute:

``py.test -v -rA -k 'not tests/functional' -s tests``. This will skip functional (end to end)
testing.

To run end to end tests, use ``py.test -v -rA -k 'tests/functional' -s tests`` instead. Several
other arguments can be provided so that the tool can run in non-interactive mode. Currently,
config file, arguments, and environment variables (mix and match) are supported. The syntax is
the same as for ``tokendito``.

If all of username, password, mfa method, app url, and role ARN are passed to ``py.test``, then
two other tests are kicked off. The first will execute ``tokendito`` and try to obtain STS
tokens the same way that a normal user would. The second will run ``sts get-caller-identity``
and validate the credentials.

Example 1
----------
.. code-block:: sh

  py.test -v -rA -s tests --config-file=/tmp/my-tokendito-config.ini

Where the config file has valid configuration items for the tool.

Example 2
---------

.. code-block:: sh

  py.test -v -rA -k 'tests/functional' -s tests \
    --username=jane.doe \
    --password=mysecretpass \
    --mfa-method=push \
    --okta-aws-app-url='https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123' \
    --role-arn=arn:aws:iam::123456789000:role/dowjones-hammer-engineer

This triggers the tests ``test_generate_credentials`` and ``test_aws_credentials`` that are
normally skipped.

Example 3
---------

.. code-block:: sh

  MFA_METHOD=push py.test -v -rA -k 'tests/functional' -s tests --username=...

This shows how to mix environment variables with ``py.test`` and arguments.
