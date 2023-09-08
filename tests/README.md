# Testing

To run basic tests, execute:

`py.test -v -rA -k 'unit' -s tests`. This will run unit tests, and skip
functional (end-to-end) testing.

To run end-to-end tests, use `py.test -v -rA -k 'functional' -s tests`
instead. Several other arguments can be provided so that the tool can
run in non-interactive mode. Currently, the config file, arguments, and
environment variables (mix and match) are supported. The syntax is as close as
possible as for `tokendito`, with the exception of `--tool-config-file`. Pytest
version 7.4.0 introduced a similarly named variable, and options defined in 
`conftest.py` cannot collide with command-line arguments to `pytest`.

If all of the username, password, MFA, tile URL, and role ARN are passed to
`py.test`, then two other tests are kicked off. The first will execute
`tokendito` and try to obtain STS tokens the same way that a normal user
would. The second will run `sts get-caller-identity` and validate the
credentials.

# Example 1

``` txt
py.test -v -rA -s tests --tool-config-file=/tmp/my-tokendito-config.ini
```

Where the config file has valid configuration items for the tool.

## Example 2

``` txt
py.test -v -rA -k 'functional' -s tests \
  --username=jane.doe@mycompany.com \
  --password=mysecretpass \
  --okta-mfa=push \
  --okta-tile='https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123' \
  --aws-role-arn=arn:aws:iam::123456789000:role/dowjones-engineer
```

This triggers the tests `test_generate_credentials` and
`test_aws_credentials` that are normally skipped.

## Example 3

``` txt
TOKENDITO_OKTA_MFA_METHOD=push py.test -v -rA -k 'functional' -s tests --username=...
```

This shows how to mix environment variables with `py.test` and
arguments.

## Example 4

``` txt
TOKENDITO_OKTA_PASSWORD='mysecretpass' tox -e auth -- --username='jane.doe@mycompany.com'
```

This shows how to pass credentials through Tox.
