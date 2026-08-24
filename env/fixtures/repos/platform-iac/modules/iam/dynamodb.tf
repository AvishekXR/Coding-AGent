# IAM policy documents for services that talk to DynamoDB.
#
# Each service gets a policy scoped to exactly the tables it owns. Keep the resource ARNs
# tight: these roles hold production credentials.

data "aws_iam_policy_document" "orders_dynamodb" {
  statement {
    sid    = "OrdersTableAccess"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]
    resources = [
      "arn:aws:dynamodb:*:*:table/orders-prod",
    ]
  }
}

data "aws_iam_policy_document" "analytics_dynamodb" {
  statement {
    sid    = "AnalyticsReadOrders"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    resources = [
      "arn:aws:dynamodb:*:*:table/orders-prod",
    ]
  }
}

# Legacy nightly/streaming importer. Predates the orders-api service and writes to the
# production table directly; reads no ConfigMap, so it is unaffected by config changes.
data "aws_iam_policy_document" "batch_importer_dynamodb" {
  statement {
    sid    = "BatchImporterWrite"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:BatchWriteItem",
    ]
    resources = [
      "arn:aws:dynamodb:*:*:table/orders-prod",
    ]
  }
}
