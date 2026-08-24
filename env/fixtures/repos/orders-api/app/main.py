"""orders-api -- accepts customer orders and persists them.

POST /orders  -> 201 with the order id.
"""
from .store import OrderStore


class OrdersAPI:
    def __init__(self, client, env=None):
        self.store = OrderStore(client, env=env)

    def create_order(self, order, at):
        table = self.store.put(order, at)
        return {"status": 201, "id": order["order_id"], "table": table}
