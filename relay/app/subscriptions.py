"""Stripe subscription management for Automaite Terminal.

Handles checkout session creation, webhook processing, and subscription
status tracking per user (email).
"""

import json
import logging
import os
from pathlib import Path

import stripe

logger = logging.getLogger("relay.subscriptions")

# Initialize Stripe
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")

# Persistent storage for subscription data
SUBS_FILE = Path("/data/subscriptions.json")


def _load_subs() -> dict:
    if not SUBS_FILE.exists():
        return {}
    try:
        return json.loads(SUBS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_subs(subs: dict):
    SUBS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUBS_FILE.write_text(json.dumps(subs, indent=2))


def is_subscribed(email: str) -> bool:
    """Check if a user has an active subscription."""
    subs = _load_subs()
    user = subs.get(email.lower(), {})
    return user.get("active", False)


def get_subscription_info(email: str) -> dict:
    """Get subscription info for a user."""
    subs = _load_subs()
    return subs.get(email.lower(), {})


def activate_subscription(email: str, customer_id: str, subscription_id: str):
    """Mark a user as having an active subscription."""
    subs = _load_subs()
    subs[email.lower()] = {
        "active": True,
        "stripe_customer_id": customer_id,
        "stripe_subscription_id": subscription_id,
    }
    _save_subs(subs)
    logger.info("Subscription activated for %s", email)


def deactivate_subscription(email: str):
    """Deactivate a user's subscription."""
    subs = _load_subs()
    user = subs.get(email.lower(), {})
    if user:
        user["active"] = False
        subs[email.lower()] = user
        _save_subs(subs)
        logger.info("Subscription deactivated for %s", email)


def find_email_by_customer(customer_id: str) -> str | None:
    """Look up email by Stripe customer ID."""
    subs = _load_subs()
    for email, info in subs.items():
        if info.get("stripe_customer_id") == customer_id:
            return email
    return None


def create_checkout_session(email: str, success_url: str, cancel_url: str) -> str:
    """Create a Stripe Checkout session. Returns the checkout URL."""
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer_email=email,
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        allow_promotion_codes=True,
        success_url=success_url,
        cancel_url=cancel_url,
    )
    return session.url


def verify_checkout_session(session_id: str, email: str) -> bool:
    """Directly verify a Stripe Checkout session and activate subscription.

    Used as a fallback when the webhook hasn't fired yet (race condition).
    """
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status != "paid":
            logger.info("Checkout session %s not paid (status: %s)", session_id, session.payment_status)
            return False
        session_email = (session.customer_email or "").lower()
        if session_email != email.lower():
            logger.warning("Email mismatch: session=%s, user=%s", session_email, email)
            return False
        customer_id = session.customer or ""
        subscription_id = session.subscription or ""
        if not is_subscribed(email):
            activate_subscription(email, customer_id, subscription_id)
            logger.info("Subscription activated via direct verify for %s", email)
        return True
    except stripe.StripeError as e:
        logger.error("Failed to verify checkout session %s: %s", session_id, e)
        return False


def handle_webhook(payload: bytes, sig_header: str) -> dict:
    """Process a Stripe webhook event. Returns event data."""
    # Webhook secret is mandatory — reject unsigned payloads
    if not STRIPE_WEBHOOK_SECRET:
        raise ValueError("STRIPE_WEBHOOK_SECRET not configured — refusing unsigned webhook")

    event = stripe.Webhook.construct_event(
        payload, sig_header, STRIPE_WEBHOOK_SECRET
    )

    event_type = event["type"]
    logger.info("Stripe webhook: %s", event_type)

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        email = session.get("customer_email", "")
        customer_id = session.get("customer", "")
        subscription_id = session.get("subscription", "")
        if email:
            activate_subscription(email, customer_id, subscription_id)

    elif event_type == "customer.subscription.deleted":
        sub = event["data"]["object"]
        customer_id = sub.get("customer", "")
        email = find_email_by_customer(customer_id)
        if email:
            deactivate_subscription(email)

    elif event_type == "customer.subscription.updated":
        sub = event["data"]["object"]
        customer_id = sub.get("customer", "")
        status = sub.get("status", "")
        email = find_email_by_customer(customer_id)
        if email:
            if status in ("active", "trialing"):
                activate_subscription(email, customer_id, sub.get("id", ""))
            elif status in ("canceled", "unpaid", "past_due"):
                deactivate_subscription(email)

    return {"type": event_type}
