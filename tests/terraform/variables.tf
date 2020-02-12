variable idp {
  type    = list(string)
  default = ["acme-okta"]
}

variable duration {
  type = map
  default = {
    "1h"  = "3600"
    "8h"  = "28800"
    "12h" = "43200"
  }
}

variable region {
  default = "us-east-1"
}
