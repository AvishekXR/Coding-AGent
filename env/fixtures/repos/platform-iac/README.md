# platform-iac

Shared Terraform. `modules/iam` generates the IAM policy for **every** service.

A change to a resource ARN in this module is applied to all 14 consuming services listed in
`environments/prod/main.tf`. Review accordingly.

**On-call:** #platform-oncall
