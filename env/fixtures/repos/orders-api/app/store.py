"""Persistence layer. Writes each accepted order to DynamoDB."""
from .config import resolve_table_name, resolve_region


class OrderStore:
    def __init__(self, client, env=None):
        self._client = client
        self.table_name = resolve_table_name(env)
        self.region = resolve_region(env)

    def put(self, order, at):
        """Persist one order. Returns the table it landed in."""
        self._client.put_item(
            principal="orders-api",
            table=self.table_name,
            item=order,
            at=at,
        )
        return self.table_name
