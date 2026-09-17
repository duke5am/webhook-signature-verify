# webhook-signature-verify

Verify webhook signatures correctly, and process each event exactly once.
Python and Node. No dependencies.

```bash
python3 demo.py          # 22/22 checks behave as expected
```

## The two bugs this prevents

**1. Your endpoint trusts anyone who knows the URL.** A webhook URL is not a
secret — it leaks in logs, in a screenshot, in a browser history. Without
signature verification, anyone can POST a fake `payment.succeeded` and your
handler will act on it.

**2. You processed the same event twice.** Providers guarantee *at-least-once*
delivery, not exactly-once. A duplicate delivery double-charges a customer, sends
a second email, or creates a second record.

## The blog-post version is subtly wrong

Almost every snippet online does one of these:

- verifies against `JSON.stringify(JSON.parse(body))` instead of the **raw bytes**,
  so a perfectly valid webhook fails after any whitespace change
- compares with `==` instead of a **constant-time** comparison
- verifies the signature but **never checks the timestamp**, so a captured
  request replays forever
- checks idempotency with `SELECT` then `INSERT`, which has a race window and
  fails exactly when two deliveries arrive together

This kit does none of those. `demo.py` proves it:

```
=== stripe ===
  PASS  valid                  accepted=True  ok
  PASS  tampered_body          accepted=False signature_mismatch
  PASS  wrong_secret           accepted=False timestamp_expired
  PASS  missing_header         accepted=False missing_header
  PASS  malformed_header       accepted=False timestamp_not_integer
  PASS  scheme_downgrade_v0    accepted=False malformed_header
  PASS  replay_1_day_old       accepted=False timestamp_expired
```

Note `tampered_body → signature_mismatch`: the payload was signed with the real
secret and then altered, so only the content differs. That is the test most
snippets accidentally make vacuous.

## Included providers

| Provider | Scheme | Replay check |
|---|---|---|
| **Stripe** | `t=…,v1=…` HMAC-SHA256 over `t.body` | 300s |
| **GitHub** | `sha256=` HMAC-SHA256 over raw body | none sent |
| **Shopify** | base64 HMAC-SHA256 | none sent |

GitHub and Shopify send no timestamp, so a captured request **can** be replayed —
the verifier returns `ok_no_replay_check` rather than a bare `ok`, so you cannot
mistake it for a full pass. Manage that with the idempotency table instead.

## Idempotency that actually holds

`idempotency/schema.sql` and `idempotency/middleware.py` implement the only
race-free approach: **insert the event id first and let the unique constraint
detect the duplicate**, rather than checking and then inserting. The middleware
distinguishes *already succeeded* (return the stored result), *in progress*
(leased by another worker — respond 409, do not duplicate), and *previously
failed and retryable*.

## Use it

```python
from verify import verify

result = verify("stripe", raw_body_bytes, request.headers, STRIPE_WEBHOOK_SECRET)
if not result:
    return 401, result.reason      # reason is a machine-readable string
```

`raw_body_bytes` means the bytes exactly as received — read the body as bytes and
do not re-serialise it.

Node is the same shape: `node/verify.mjs`.

## What this is not

- It verifies signatures and provides idempotency. It does **not** make your
  handler's business logic correct.
- Providers change schemes; confirm against current docs (`PROVIDER-SCHEMES.md`
  records exactly which were verified against published test vectors and which
  were not).
- Not affiliated with Stripe, GitHub, Shopify or any other provider.

## The full pack

The paid kit adds **six more providers** (Slack, Twilio, Svix, Paddle, Lemon
Squeezy, Linear), signed fixtures with valid/tampered/wrong-secret/expired/
malformed cases for every one, the Node and Python test suites (258 tests total),
and the failure-modes and idempotency guides.

→ **Webhook Verification + Idempotency Kit**: <!-- GUMROAD-LINK -->
