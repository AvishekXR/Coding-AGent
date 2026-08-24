# orders-api

Accepts customer orders and writes them to DynamoDB.

The destination table is read from the `ORDERS_TABLE` environment variable, which is
projected into the pod from the shared `orders-config` ConfigMap owned by Team Platform
(see the `platform-config` repository, `overlays/prod/orders.yaml`).

**On-call:** #orders-oncall
