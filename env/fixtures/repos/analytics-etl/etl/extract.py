"""Pulls orders from the source table for the reporting pipeline."""
import os

DEFAULT_SOURCE_TABLE = "orders-prod"


def source_table(env=None):
    env = os.environ if env is None else env
    return env.get("SOURCE_TABLE", DEFAULT_SOURCE_TABLE)


def extract_since(client, since, env=None):
    """Return every order written to the source table at or after `since`."""
    table = source_table(env)
    return client.scan_since(table, since)
