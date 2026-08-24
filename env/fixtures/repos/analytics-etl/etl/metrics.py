"""Emits the business metrics the company actually watches.

`orders_created` is the metric on the executive dashboard. It is derived from rows landing
in the source table, not from orders-api response codes -- which is why a silent redirect
shows up here and nowhere else.
"""
from .extract import extract_since


def orders_created(client, window_start, window_end, env=None):
    rows = extract_since(client, window_start, env=env)
    return sum(1 for r in rows if r["_written_at"] < window_end.isoformat())
