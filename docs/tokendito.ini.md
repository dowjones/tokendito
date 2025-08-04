Tokendito uses [platformdirs](https://github.com/platformdirs/platformdirs) to manage the location of the user configuration file `tokendito.ini`. That file may contain different profiles, as:

```
[default]
okta_org = https://acme.okta.com/
okta_username = jane.doe@acme.com
okta_mfa = push
login_timeout = 60

[my_prod_okta_tile]
okta_tile = https://acme.okta.com/home/amazon_aws/b07384d113edec49f00d/272?fromHome=true

[my_dev_okta_tile]
okta_tile = https://acme.oktapreview.com/home/amazon_aws/b07384d113edec49eaa6/123
okta_username = jane.doe@acme.com
login_timeout = 0
```

to select a given profile, use the `--profile $name` option, otherwise the default profile will be selected. In the above tokendito.ini file, using `--profile my_dev_okta_tile` would select the configuration values for the `[my_dev_okta_tile]` profile.

The `login_timeout` option controls how long tokendito will wait for username and password input before timing out. Once the user starts typing, the timeout is disabled. The default is 10 seconds. Set to 0 to disable timeout.
