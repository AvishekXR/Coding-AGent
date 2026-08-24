"""Order validation.

Runs before anything is persisted. Rejecting here is cheap; rejecting after the payment call
is not, so keep this strict enough to catch nonsense and loose enough not to refuse real
orders.
"""

# Largest order we will accept in a single request. Raised for the seasonal catalogue.
MAX_ITEMS = 10

# Orders below this are almost always test traffic or a client bug.
MIN_AMOUNT_CENTS = 50


# Feature flag gating the v2 rules. Owned by Orders; toggled from the flag console, not here.
STRICT_VALIDATION_FLAG = "orders.strict_validation"


def validate_order(order, strict=False):
    """Return (ok, reason).

    `strict` is the evaluated state of the orders.strict_validation flag, passed in by the
    caller so this function stays pure and testable.
    """
    if order.get("amount_cents", 0) < MIN_AMOUNT_CENTS:
        return False, "amount below minimum"
    if order.get("items", 1) > MAX_ITEMS:
        return False, "too many items in one order"
    if strict:
        # v2 rules, still behind orders.strict_validation.
        if order.get("items", 1) > 4:
            return False, "v2: item count above the per-order limit"
        if order.get("amount_cents", 0) > 25000:
            return False, "v2: amount above the per-order ceiling"
    return True, ""
