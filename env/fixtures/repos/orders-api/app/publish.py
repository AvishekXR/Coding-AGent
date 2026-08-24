"""Publishes an event per accepted order to the orders event stream.

The destination stream is named by ORDERS_EVENT_STREAM in the shared ConfigMap; it is
`orders-queue` in production.

Consumers parse these by field name. Renaming a field here is an API change for every
consumer, even though nothing about this repository's own behaviour changes.
"""


def build_event(order):
    """Return the event body published for one accepted order."""
    return {
        "order_id": order["order_id"],
        "amount_cents": order["amount_cents"],
        "items": order.get("items", 1),
        "schema": "orders.v1",
    }
