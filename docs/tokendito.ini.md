Tokendito uses [platformdirs](https://github.com/platformdirs/platformdirs) to manage the location of the user configuration file `tokendito.ini`. That file may contain different profiles, as:

```
[default]
okta_org = https://acme.okta.com/
okta_username = jane.doe@acme.com
okta_mfa = push
login_timeout = 0

[my_prod_okta_tile]
okta_tile = https://acme.okta.com/home/amazon_aws/b07384d113edec49f00d/272?fromHome=true

[my_dev_okta_tile]
okta_tile = https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123
okta_username = jane.doe@acme.com
login_timeout = 0
```

To select a given profile, use the `--profile $name` option, otherwise the default profile will be selected. In the above tokendito.ini file, using `--profile my_dev_okta_tile` would select the configuration values for the `[my_dev_okta_tile]` profile.

To authenticate to multiple profiles in a single invocation, use `--multi-profiles` (can be repeated):

```
tokendito --multi-profiles my_prod_okta_tile --multi-profiles my_dev_okta_tile
```

This will authenticate once and then iterate through each profile, writing AWS credentials to `~/.aws/credentials` using the tokendito profile name as the AWS profile name (e.g. `my_prod_okta_tile`, `my_dev_okta_tile`). See the [multi-profile usage](README.md#multi-profile-usage) section for more details.

The `login_timeout` option controls how long tokendito will wait for username and password input before timing out. Once the user starts typing, the timeout is disabled. The default is 0 (disabled). Set to a positive value (in seconds) to enable timeout.
