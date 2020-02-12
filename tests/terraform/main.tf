terraform {
  required_version = "~> 0.12.0"
}

provider "aws" {
  region  = var.region
  version = "~> 2.0"
}

provider "local" {
  version = "~> 1.4"
}

provider "null" {
  version = "~> 2.1"
}

provider "template" {
  version = "~> 2.1"
}
