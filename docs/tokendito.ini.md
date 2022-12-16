tokendito uses [platformdirs](https://github.com/platformdirs/platformdirs) to manage the location of the user configuration file tokendito.ini. That file may contain different configuration for different profiles, as:
```
[default]
okta_org = https://acme.okta.com/
okta_username = jane.doe@acme.com
mfa = push

[my_prod_okta_tile]
okta_tile = https://acme.okta.com/home/amazon_aws/b07384d113edec49f00d/272?fromHome=true

[my_dev_okta_tile]
okta_tile = https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123
okta_username = jane.doe@acme.com
```
to select a given profile, use the `--profile $name` option, otherwise the default profile will be selected. In the above tokendito.ini file, using `--profile my_dev_okta_tile` would select the configuration values for the [my_dev_okta_tile] profile.
