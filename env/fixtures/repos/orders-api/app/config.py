"""Runtime configuration for orders-api.

Values come from the environment, which in production is projected from the shared
platform-config ConfigMap. Defaults exist so that a developer can run the service locally
without a cluster.
"""
import os

# Historical default from the original 2023 bring-up, when every environment ran against
# the staging table and prod did not exist yet.
# TODO(orders, 2023-06): drop this default once every environment sets ORDERS_TABLE
# explicitly. Leaving it means a missing ORDERS_TABLE fails silently instead of loudly.
DEFAULT_ORDERS_TABLE = "orders-staging"

DEFAULT_REGION = "us-east-1"


def resolve_table_name(env=None):
    """Return the DynamoDB table this process will write orders to.

    Falls back to DEFAULT_ORDERS_TABLE when ORDERS_TABLE is absent from the environment.
    """
    env = os.environ if env is None else env
    return env.get("ORDERS_TABLE", DEFAULT_ORDERS_TABLE)


def resolve_region(env=None):
    env = os.environ if env is None else env
    return env.get("AWS_REGION", DEFAULT_REGION)
