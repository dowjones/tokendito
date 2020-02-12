output "role_arns" {
  value = {
    for role in aws_iam_role.role :
    role.name => role.arn
  }
}
