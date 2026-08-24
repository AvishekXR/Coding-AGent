# analytics-etl

Reads the orders table and emits reporting metrics, including `orders_created`, which is
the business metric on the executive dashboard.

Source table comes from `SOURCE_TABLE` in the shared `analytics-config` ConfigMap.

**On-call:** #data-oncall
