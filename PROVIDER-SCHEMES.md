# Provider signature schemes — exactly what is signed, and how each one was checked

Verification date: **2026-09-17**. Every page below was fetched live on that date
and read; nothing in this table is quoted from memory, and nothing is inferred
from a third-party blog post.

## The one-line summary

The single question that costs people an afternoon is *"which byte string is
HMACed?"*. It differs per provider, the differences are not cosmetic, and a
verifier that computes the wrong string is **worse than no verifier at all**,
because it returns "invalid" for every genuine delivery and tempts you to
"fix" it by loosening the check. This document is the answer key.

## The table

| Provider | Header(s) read | Algorithm & encoding | Exact signed string | Replay tolerance in this pack | Verified against |
|---|---|---|---|---|---|
| **stripe** | `Stripe-Signature` — `t=<unix>,v1=<hex>[,v1=<hex>…]` (`v0` is a test-only scheme and is **never** accepted) | HMAC-SHA256, lowercase **hex** | `f"{t}.{raw_body}"` — the decimal timestamp as ASCII, a literal `.`, then the raw body bytes. Compare against **each** `v1` value (endpoint-secret roll sends several). | **300 s** (`t` is in the signed string, so it is authenticated) | [docs.stripe.com/webhooks.md — "Verify webhook signatures manually"](https://docs.stripe.com/webhooks/signature.md) and the full page [docs.stripe.com/webhooks](https://docs.stripe.com/webhooks) ("Step 2: Prepare the `signed_payload` string"). Official libraries default to 5 minutes; the same page warns that a tolerance of `0` *disables* the recency check. |
| **github** | `X-Hub-Signature-256` — `sha256=<hex>`; the legacy `X-Hub-Signature` (`sha1=`) is rejected | HMAC-SHA256, lowercase **hex**, prefixed with `sha256=` in the header only | the **raw body bytes**, nothing else | **none possible** — GitHub sends no timestamp. Deduplicate on `X-GitHub-Delivery` | [Validating webhook deliveries](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries). This page publishes a full test vector and **it reproduces exactly here**: secret `It's a Secret to Everybody`, payload `Hello, World!` → `757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17`. The page also explicitly says "Never use a plain `==` operator" — the same advice this pack implements. |
| **shopify** | `X-Shopify-Hmac-Sha256` — **base64** of the digest (not hex); `X-Shopify-Webhook-Id`, `X-Shopify-Event-Id`, `X-Shopify-Topic` are read for metadata/dedup | HMAC-SHA256, **base64** | the **raw request body** bytes, keyed with the app's **client secret** | **none possible** — no timestamp header exists. Deduplicate on `X-Shopify-Webhook-Id` | [Verify webhook deliveries](https://shopify.dev/docs/apps/build/webhooks/verify-deliveries): "a base64-encoded HMAC signature in the `X-Shopify-Hmac-SHA256` header, generated using your app's client secret and the raw request body", and the manual instructions say to "compare it to the decoded header value". The same page confirms the dedup guidance and the `X-Shopify-Webhook-Id` vs `X-Shopify-Event-Id` distinction, and states that **HMAC verification applies to HTTPS deliveries only** — Google Pub/Sub and EventBridge deliveries carry no HMAC, so that header being absent there is expected, not an attack. |
| **slack** | `X-Slack-Signature` — `v0=<hex>`; `X-Slack-Request-Timestamp` (unix seconds, in its own header) | HMAC-SHA256, lowercase **hex** | `f"v0:{timestamp}:{raw_body}"` — the literal `v0:`, the timestamp **as it appeared in the header**, another `:`, then the raw body | **300 s** | [Verifying requests from Slack](https://docs.slack.dev/authentication/verifying-requests-from-slack/). The page publishes the basestring, the secret and the expected digest, and **all three reproduce exactly**: secret `8f742231b10e8888abcd99yyyzzz85a5`, ts `1531420618` → `v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503`. The page says "we verify that the timestamp does not differ from local time by more than five minutes". |
| **twilio** | `X-Twilio-Signature` — **base64** of a SHA-1 digest | HMAC-**SHA1** (yes, SHA-1 — it is HMAC, not a bare hash), **base64** | `url + concat(name + value)` over POST params sorted by name (Unix case-sensitive), values for a repeated name sorted and de-duplicated, **no delimiters anywhere**. No body, no timestamp. For `application/json` bodies Twilio instead appends `bodySHA256=<hex sha256 of raw body>` to the URL and signs the URL alone — this pack verifies both hash and signature. | **none possible** — the signature contains no timestamp, so a captured request is valid **forever**; deduplicate on `MessageSid`/`CallSid` | [Validate requests to your application](https://www.twilio.com/docs/usage/security) states the algorithm and a worked example that **reproduces exactly here**: url `https://example.com/myapp.php?foo=1&bar=2`, token `12345`, params `CallSid/Caller/Digits/From/To` → `L/OH5YylLD5NRKLltdqwSvS0BnU=`. Also [Webhooks security](https://www.twilio.com/docs/usage/webhooks/webhooks-security) for the `bodySHA256` rule, and the official [twilio-python `request_validator.py`](https://github.com/twilio/twilio-python/blob/main/twilio/request_validator.py) for the two rules the prose omits: a signature is accepted with **or without** an explicit port (`add_port`/`remove_port`), and repeated values are `sorted(set(values))`. |
| **paddle** | `Paddle-Signature` — `ts=<unix>;h1=<hex>[;h1=<hex>…]` | HMAC-SHA256, lowercase **hex**, keyed with the **raw** secret string (not base64- or hex-decoded) | `f"{ts}:{raw_body}"` — the decimal timestamp, a literal `:`, then the raw body | **5 s** — Paddle's SDK default, and deliberately tight | [Verify webhook signatures](https://developer.paddle.com/webhooks/about/signature-verification/): "concatenating the timestamp (`ts`) + a colon (`:`) + the raw body of the request", "the timestamp… is five seconds", "the key must be the raw secret key string". Paddle's own SDK unit tests publish a vector and **it reproduces exactly here**: ts `1710498758` → `h1=558bf93944dbeb4790c7a8af6cb2ea435c8ca9c8396aafc1a4e37424ac132744`. |
| **svix** (and every Standard Webhooks sender) | `svix-id`, `svix-timestamp`, `svix-signature` — white-labelled customers get the `webhook-*` prefix, and both are accepted | key = **base64-decode the part of the secret after `testsec_`** (a secret without the prefix is used as literal UTF-8 bytes); HMAC-SHA256, **base64**; header is a **space-separated** list of `v1,<base64>` entries | `f"{svix_id}.{svix_timestamp}.{raw_body}"` — id, literal `.`, timestamp, literal `.`, then the raw body | **300 s** (`svix-timestamp` *is* inside the signed content, so it is authenticated) | [Verifying Webhooks Manually](https://docs.svix.com/receiving/verifying-payloads/how-manual): the concatenation, the base64-decoded `testsec_` key, "space delimited" signature list, "remove the version prefix and delimiter (e.g. `v1,`) before verifying", and an example that **reproduces exactly here**: secret `testsec_plJ3nmyCDGBKInavdOK15jsl`, id `msg_loFOjxBNrRLzqYUf`, ts `1731705121` → `v1,rAvfW3dJ/X/qxhsaXPOyyCGmRKsaKWcsNccKXlIktD0=`. The page also notes the `svix-id` is "the same when the same webhook is being resent". |
| **linear** | `Linear-Signature` — **hex**; `Linear-Delivery`, `Linear-Event`, `Linear-Timestamp` are read for metadata | HMAC-SHA256, lowercase **hex** | the **raw body bytes**, nothing else. The `webhookTimestamp` field lives *inside* the JSON body, so it is **not** part of the signed string — a timestamp cannot be *authenticated* here, only *bounded*. | **60 s**, measured against the body's `webhookTimestamp` (milliseconds) | [Webhooks — Securing Webhooks](https://linear.app/developers/webhooks): "a hex-encoded HMAC-SHA256 signature of the raw body contents, signed using the webhook's signing secret", plus "`webhookTimestamp`… in milliseconds… verify it's within a minute", and Linear's own sample does `Math.abs(Date.now() - req.body.webhookTimestamp) > 60 * 1000`. |
| **lemonsqueezy** | `X-Signature`; `X-Event-Name` is read for metadata | HMAC-SHA256, **hex** digest compared as a hex **string** | the **raw request body** bytes, keyed with the webhook's signing secret | **none possible** — no timestamp header exists | **Partially verified — see below.** [Signing Requests](https://docs.lemonsqueezy.com/help/webhooks/signing-requests) states "Lemon Squeezy generates the hash using an HMAC hex digest" and that it is sent in the `X-Signature` header. The page publishes **no secret + payload test vector**, so the packing of the digest could not be confirmed against an official value. |

## Which of the nine were verified, and how strongly

**None of the nine schemes in this pack was guessed.** But "verified" is not one
strength, and pretending otherwise is how a buyer ends up trusting a string
comparison nobody ever checked. Three tiers:

### Tier 1 — algorithm stated *and* an official test vector reproduced end to end (5)

`github`, `slack`, `svix`, `paddle`, `twilio`.

For these, a value published by the provider (or its official SDK test suite)
was fed through this verifier and it **matched byte for byte**. That is a real
check: if the signed string were built even slightly differently, the vector
could not match. The vectors are asserted in three places —
`python/verify.py::selftest`, `node/selftest.mjs`, and
`tests_python/test_verify.py::TestOfficialProviderVectors` /
`tests_node/verify.test.mjs::"official provider vectors"` — so a future change
that breaks a scheme fails the suite rather than quietly weakening it.

### Tier 2 — algorithm stated in prose *and* shown in first-party sample code, but no published vector (3)

`stripe`, `shopify`, `linear`.

Stripe spells out the `signed_payload` construction step by step and publishes a
real-looking header, but not a secret+payload pair you can check a digest
against. Shopify and Linear likewise state the algorithm precisely and ship
sample code, but no vector. For these three, the tests can only assert
**round-trip behaviour** (a digest this pack computes is accepted, and a
one-byte change to the body, the wrong secret, a missing header and a malformed
header are all rejected). That is a weaker claim than Tier 1 and is labelled as
such on purpose: round-tripping proves internal consistency, not that the
construction matches the provider.

### Tier 3 — prose only, no vector (1)

`lemonsqueezy`. **Partially verified.** The docs say the header is `X-Signature`
and the digest is "an HMAC hex digest", and that is what this pack computes.
There is no published vector and no unambiguous sample, so the digest value
itself has never been checked against a Lemon Squeezy-produced signature. It is
the one provider here where a wrong *encoding* (hex vs base64) could survive
testing. If you take money through Lemon Squeezy, treat the very first live
delivery as the test: log `signing_string_preview`/`signingStringPreview` output
and the header, and confirm before you trust it.

If you only read one paragraph of this file: **re-check the scheme for a
provider before you trust it in production.** Providers change schemes, docs get
rewritten, and every one of these pages could differ tomorrow.

## Corrections to earlier commentary in this pack

Two explanatory comments that shipped in `python/verify.py` and `node/verify.mjs`
were **wrong**, and have been corrected in place. They are recorded here because
a pack about correctness should not quietly rewrite its own history.

1. **Twilio — "the worked example is not reproducible".** False. Twilio's page
   does label the example "for illustrative purposes only", but its numbers
   reproduce *exactly*: HMAC-SHA1 keyed with `12345` over the documented signing
   string gives `L/OH5YylLD5NRKLltdqwSvS0BnU=`. It is a real Tier 1 vector. The
   old comment claimed the opposite, which would have led a buyer to distrust a
   vector that is in fact sound. The port-variant and repeated-parameter rules
   still come from the official SDK source, and that part of the comment stands.
2. **Lemon Squeezy — "the docs' Node sample cannot work as written".** False.
   The sample does `Buffer.from(hmac.update(body).digest('hex'), 'utf8')` and
   compares that with `timingSafeEqual` against `Buffer.from(header, 'utf8')`.
   That is 64 ASCII bytes against 64 ASCII bytes — it works, and it is a
   comparison of **hex text**, not of raw digest bytes. The sample is
   needlessly convoluted, not broken. The old comment also mentioned a
   `s`/`signature` typo that is no longer on the page. The *conclusion* the
   comment drew — compare hex strings — is still correct, and is what the code
   does; only its reasoning was wrong.

## Things the verifier deliberately does not do

* **No timestamp where the provider sends none.** `github`, `shopify`, `twilio`
  and `lemonsqueezy` deliveries are accepted with reason
  `ok_no_replay_check`. That reason code exists so this is visible at the call
  site instead of looking like full protection. For those four, idempotency is
  the *only* defence against replay — see `docs/IDEMPOTENCY.md`.
* **Linear's `Linear-Timestamp` header is ignored.** Linear sends the send-time
  in milliseconds as a header *and* as `webhookTimestamp` in the body. The
  header is not covered by the signature, so the verifier uses the
  authenticated body value (or an explicit `webhook_timestamp_ms=` /
  `webhookTimestampMs`), at the cost of requiring the JSON to parse. If you want
  to bound replay even for a body you cannot parse, read `Linear-Timestamp`
  yourself — but understand you are trusting an unauthenticated header.
* **GitHub's legacy `sha1` header is rejected, not accepted "for
  compatibility".** Comparing a SHA-1 HMAC because a client sent one is a
  downgrade; that is exactly how signature checks get weakened over time.
* **`v0` on Stripe, and non-`v1` entries on Svix, are ignored.** Stripe's `v0`
  is a test-only scheme; accepting it would accept signatures nobody in
  production can verify.

## Providers people ask for that are deliberately absent

| Provider | Why it is not here |
|---|---|
| **SendGrid** (Event Webhook) | It is not HMAC. It uses **ECDSA over SHA-256(ts + raw body)** with an ASN.1 DER signature and a public key you generate in the dashboard. It does not fit an HMAC verifier and would need a real ECDSA implementation. Verified 2026-09-17 at <https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features>. |
| **Mailgun** | It signs `timestamp + token` and **not the payload**, and carries the token, timestamp and signature *inside the JSON body* rather than in headers. You must parse the body before you can verify anything about it — the exact parse-then-verify order this pack warns about. Verified 2026-09-17 at <https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/securing-webhooks>. |
| **Standard Webhooks** | Use the `svix` verifier: identical construction, same `svix-*` headers. Verified at <https://docs.svix.com/receiving/verifying-payloads/how-manual>. |

## How to reproduce this verification

The pages were fetched with plain HTTP (no browser, no scraping service) and the
key sentences quoted above were read in the fetched text. To re-do it:

```bash
# Stripe and Svix publish machine-readable plain-text versions
curl -s https://docs.stripe.com/webhooks/signature.md
curl -s https://docs.svix.com/receiving/verifying-payloads/how-manual.md

# GitHub's docs live in a public repo, so the source markdown is authoritative
curl -s https://raw.githubusercontent.com/github/docs/main/content/webhooks/using-webhooks/validating-webhook-deliveries.md

# The rest are HTML pages; grep the fetched body for the header name
curl -s https://docs.slack.dev/authentication/verifying-requests-from-slack/ | grep -i "X-Slack-Signature"
curl -s https://developer.paddle.com/webhooks/about/signature-verification/ | grep -i "h1"
curl -s https://linear.app/developers/webhooks | grep -i "Linear-Signature"
curl -s https://shopify.dev/docs/apps/build/webhooks/verify-deliveries | grep -i "X-Shopify-Hmac"
curl -s https://docs.lemonsqueezy.com/help/webhooks/signing-requests | grep -i "X-Signature"
curl -s https://www.twilio.com/docs/usage/security | grep -i "X-Twilio-Signature"
```

Then run the vectors:

```bash
python3 python/verify.py        # selftest: 58/58 checks passed
node node/selftest.mjs          # selftest: 64/64 checks passed
python3 -m unittest discover -s tests_python -v
node --test
```

**Not affiliated with any provider.** All provider names and headers are used
only to describe an interoperable implementation.
