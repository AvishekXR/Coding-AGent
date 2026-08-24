# Production environment. Every service role is built from the shared iam module, which is
# why a change in modules/iam lands on every consumer at once.

module "iam" {
  source = "../../modules/iam"
}

# Services consuming the shared IAM module. Adding a service here is a one-line change;
# widening a policy in the module affects every entry in this list.
locals {
  services = [
    "orders-api", "analytics-etl", "billing-api", "inventory-api",
    "shipping-api", "returns-api", "pricing-api", "catalog-api",
    "search-api", "recommendations-api", "notifications-api",
    "fraud-api", "reporting-api", "audit-api",
  ]
}
