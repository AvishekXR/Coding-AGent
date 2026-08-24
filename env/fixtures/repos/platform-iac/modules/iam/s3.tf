data "aws_iam_policy_document" "reports_s3" {
  statement {
    sid    = "ReportsBucketWrite"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::acme-reports-prod/*",
    ]
  }
}
