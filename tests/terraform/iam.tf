data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "perm" {
  statement {
    sid       = "AllowGetCallerIdentity"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "OktaTrust"
    actions = ["sts:AssumeRoleWithSAML"]

    principals {
      type = "Federated"
      identifiers = [
        for idp in var.idp :
        format("arn:aws:iam::%s:saml-provider/%s", data.aws_caller_identity.current.account_id, idp)
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values   = ["https://signin.aws.amazon.com/saml"]
    }
  }
}

resource "aws_iam_role" "role" {
  for_each             = var.duration
  name                 = "tokendito_${each.key}"
  path                 = "/"
  max_session_duration = each.value
  description          = "Tokendito Access Role (${each.key})"

  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_iam_policy" "policy" {
  name        = "get-caller-identity"
  description = "Allow a role to execute sts:GetCallerIdentity"

  policy = data.aws_iam_policy_document.perm.json
}

resource "aws_iam_role_policy_attachment" "attach" {
  for_each   = var.duration
  role       = aws_iam_role.role[each.key].name
  policy_arn = aws_iam_policy.policy.arn
}
