"""Webhook signature verification for 9 providers. Standard library only.

    from verify import verify
    result = verify("stripe", raw_body_bytes, request.headers, STRIPE_WEBHOOK_SECRET)
    if not result:            # VerifyResult is falsy when invalid
        return 401, result.reason

THE ONE RULE
------------
``payload`` MUST be the raw request body **bytes**, exactly as they arrived on
the socket. Never ``json.dumps(json.loads(body))``, never ``str(dict)``, never a
framework's parsed body. Every provider signs the bytes it put on the wire.
Re-serialising a parsed object changes key order, whitespace, unicode escaping
and number formatting, so the HMAC no longer matches -- and the usual "fix" for
that is to weaken the check, which is how forged webhooks get accepted.

Passing a ``dict``/``list``/``str`` where bytes are expected raises
``TypeError`` immediately, on purpose. A ``str`` is rejected too: re-encoding a
string that was decoded with the wrong codec silently corrupts the bytes.

WHAT THIS MODULE DOES NOT DO
----------------------------
It authenticates the *sender* and (where the provider supplies one) rejects
*replay*. It does not make your handler's business logic correct, and it does
not make a duplicate delivery harmless -- that is what ``idempotency/`` is for.

Providers verified against first-party documentation and, where available, an
official test vector or official SDK source: stripe, github, shopify, slack,
twilio, paddle, lemonsqueezy, svix, linear. See ``docs/PROVIDER-SCHEMES.md``
for the exact URL each construction was read from, and for the providers that
are deliberately absent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlparse, parse_qs

__all__ = [
    "VerifyResult",
    "Reason",
    "verify",
    "verify_bool",
    "SUPPORTED_PROVIDERS",
    "DEFAULT_TOLERANCE_SECONDS",
    "TOLERANCE_SECONDS",
]

__version__ = "1.0.0"

DEFAULT_TOLERANCE_SECONDS = 300

#: Per-provider default replay tolerance, in seconds. ``None`` means the
#: provider gives the verifier nothing trustworthy to compare against a clock,
#: so no recency check is possible (the reason is reported in the result).
TOLERANCE_SECONDS: dict[str, int | None] = {
    "stripe": 300,          # Stripe's own libraries default to 5 minutes
    "github": None,         # no timestamp in the delivery
    "shopify": None,        # no timestamp in the delivery
    "slack": 300,           # Slack's docs say "more than five minutes"
    "twilio": None,         # signature covers URL + params only, no timestamp
    "paddle": 5,            # Paddle SDK default is 5 seconds
    "lemonsqueezy": None,   # no timestamp in the delivery
    "svix": 300,            # Svix sends svix-timestamp; 5 min is the common setting
    "linear": 60,           # Linear's docs: "within a minute"
}

SUPPORTED_PROVIDERS = tuple(sorted(TOLERANCE_SECONDS))


class Reason:
    """Stable machine-readable reason codes. Compare against these, not prose."""

    OK = "ok"
    OK_NO_REPLAY_CHECK = "ok_no_replay_check"
    MISSING_HEADER = "missing_header"
    MALFORMED_HEADER = "malformed_header"
    MALFORMED_PAYLOAD = "malformed_payload"
    NO_MATCHING_SCHEME = "no_matching_scheme"
    SIGNATURE_MISMATCH = "signature_mismatch"
    TIMESTAMP_EXPIRED = "timestamp_expired"
    TIMESTAMP_IN_FUTURE = "timestamp_in_future"
    TIMESTAMP_NOT_INTEGER = "timestamp_not_integer"
    MISSING_SECRET = "missing_secret"
    MISSING_ARGUMENT = "missing_argument"
    BODY_HASH_MISMATCH = "body_hash_mismatch"
    UNSUPPORTED_PROVIDER = "unsupported_provider"
    INTERNAL_ERROR = "internal_error"
    REPLAY_WINDOW_UNENFORCEABLE = "replay_window_unenforceable"


@dataclass(frozen=True)
class VerifyResult:
    """Verification outcome. Truthy only when the signature is authentic.

    ``reason`` is always populated, so a rejection is diagnosable without
    turning on logging or re-running the request.
    """

    valid: bool
    reason: str
    provider: str
    delivery_id: str | None = None
    signature_id: str | None = None
    timestamp: int | None = None
    timestamp_age: int | None = None
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.valid

    @property
    def ok(self) -> bool:
        """Explicit alias for ``valid``, for people who dislike truthiness."""
        return self.valid

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        state = "VALID" if self.valid else "INVALID"
        return f"<{state} {self.provider} {self.reason}>"


# --------------------------------------------------------------------------
# input normalisation -- strict on purpose
# --------------------------------------------------------------------------

def _as_bytes(payload: Any) -> bytes:
    """Coerce the payload to bytes, refusing anything already parsed."""
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, (bytearray, memoryview)):
        return bytes(payload)
    if isinstance(payload, str):
        raise TypeError(
            "payload must be raw bytes, not str. A str means the body was already "
            "decoded somewhere; re-encoding it with the wrong codec can change the "
            "bytes and quietly break the HMAC. Read the raw body (Flask: "
            "request.get_data(); Django: request.body; Express: express.raw()) and "
            "pass those bytes."
        )
    raise TypeError(
        f"payload must be raw bytes, got {type(payload).__name__}. Never pass a "
        "parsed dict/list -- re-serialising it changes key order and whitespace "
        "and the signature will not match."
    )


class Headers:
    """Case-insensitive, duplicate-tolerant view over request headers.

    Accepts a plain ``dict``, a WSGI ``environ``-style dict, a list of
    ``(name, value)`` pairs, or an object exposing ``.items()``/``.get()``
    (Django's ``HttpHeaders``, Starlette's, ``http.Header`` in Node). Header
    names are matched case-insensitively, as RFC 9110 requires, because
    providers differ on capitalisation (``X-Signature`` vs ``x-signature``).
    """

    __slots__ = ("_map",)

    def __init__(self, headers: Any) -> None:
        self._map: dict[str, str] = {}
        if headers is None:
            return
        try:
            items = headers.items()
        except AttributeError:
            try:
                items = list(headers)
            except TypeError as exc:
                raise TypeError(
                    "headers must be a mapping or an iterable of (name, value) pairs"
                ) from exc
        for name, value in items:
            if not isinstance(name, str):
                continue
            if isinstance(value, (list, tuple)):
                # A repeated header: keep the first, but if the provider needs
                # all of them it can ask for them by name.
                value = value[0] if value else ""
            if value is None:
                continue
            self._map[name.strip().lower()] = str(value)

    def get(self, name: str) -> str | None:
        return self._map.get(name.strip().lower())

    def get_any(self, *names: str) -> tuple[str | None, str | None]:
        """Return ``(name, value)`` for the first of ``names`` that is set."""
        for name in names:
            value = self.get(name)
            if value is not None:
                return name, value
        return None, None

    def __contains__(self, name: str) -> bool:
        return name.strip().lower() in self._map

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Headers({sorted(self._map)!r})"


def _b64_decode(value: str) -> bytes | None:
    """Lenient-but-safe base64 decode. Returns None instead of raising."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    padding = "=" * (-len(candidate) % 4)
    try:
        return base64.b64decode(candidate + padding, validate=True)
    except (binascii.Error, ValueError):
        return None


def _hex_to_bytes(value: str) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value.strip())
    except ValueError:
        return None


def _is_hex(value: str) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _constant_time_eq(expected: bytes, provided: bytes) -> bool:
    """Constant-time comparison that never raises on unequal lengths.

    ``hmac.compare_digest`` is constant-time only for equal-length inputs; for
    unequal lengths it returns False quickly. ``hmac.compare_digest`` on bytes
    with differing lengths does not leak the length of the *secret*, only of the
    attacker-supplied value, which is already known to the attacker. To keep the
    timing profile flat we compare digests of both sides as well.
    """
    if len(expected) != len(provided):
        # Still burn a comparison so the early-exit is not a timing oracle.
        hmac.compare_digest(
            hashlib.sha256(expected).digest(), hashlib.sha256(provided).digest()
        )
        return False
    return hmac.compare_digest(expected, provided)


def _secret_bytes(secret: Any) -> bytes:
    if isinstance(secret, bytes):
        return secret
    if isinstance(secret, str):
        return secret.encode("utf-8")
    raise TypeError(f"secret must be str or bytes, got {type(secret).__name__}")


def _check_recency(
    timestamp: int,
    *,
    tolerance: int,
    now: float,
    provider: str,
) -> tuple[bool, str, int]:
    """Return ``(fresh, reason, age)`` for a provider-supplied timestamp."""
    age = int(now - timestamp)
    if age > tolerance:
        return False, Reason.TIMESTAMP_EXPIRED, age
    # A signature minted in the future is either a clock skew problem or a
    # forged timestamp; either way it is not trustworthy.
    if -age > tolerance:
        return False, Reason.TIMESTAMP_IN_FUTURE, age
    return True, Reason.OK, age


def _invalid(provider: str, reason: str, **kw: Any) -> VerifyResult:
    return VerifyResult(valid=False, reason=reason, provider=provider, **kw)


def _valid(provider: str, reason: str = Reason.OK, **kw: Any) -> VerifyResult:
    return VerifyResult(valid=True, reason=reason, provider=provider, **kw)


# --------------------------------------------------------------------------
# Stripe -- Stripe-Signature: t=<unix>,v1=<hex>,v0=<hex>
# HMAC-SHA256 over f"{t}.{payload}", hex. Tolerance default 300s.
# Source: https://docs.stripe.com/webhooks (verify manually) and
#         https://docs.stripe.com/webhooks/signature
# --------------------------------------------------------------------------

def verify_stripe(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    tolerance: int | None = None,
    now: float | None = None,
) -> VerifyResult:
    provider = "stripe"
    headers = Headers(headers)
    payload = _as_bytes(payload)
    tolerance = DEFAULT_TOLERANCE_SECONDS if tolerance is None else tolerance
    now = time.time() if now is None else now

    header_value = headers.get("Stripe-Signature")
    if not header_value:
        return _invalid(provider, Reason.MISSING_HEADER,
                        detail={"header": "Stripe-Signature"})

    timestamp: str | None = None
    # v1 only. Stripe's docs: schemes start with "v" + integer; ignore every
    # scheme that is not v1 so an attacker cannot downgrade to v0.
    v1_signatures: list[str] = []
    for element in header_value.split(","):
        element = element.strip()
        if "=" not in element:
            # Tolerate trailing commas / stray whitespace, reject nothing yet:
            # a genuinely malformed header simply yields no usable parts.
            continue
        prefix, _, value = element.partition("=")
        prefix = prefix.strip()
        value = value.strip()
        if prefix == "t":
            if timestamp is None:
                timestamp = value
        elif prefix == "v1" and value:
            v1_signatures.append(value)

    # Report the timestamp problem BEFORE the missing-v1 problem. Both can be
    # true at once, and "the timestamp is not a number" is the more specific,
    # more actionable diagnosis -- a vague "malformed header" on a header that
    # visibly contains a t= value sends people looking in the wrong place.
    if timestamp is None:
        return _invalid(
            provider,
            Reason.MALFORMED_HEADER,
            detail={"header": "Stripe-Signature", "expected": "t=<unix>,v1=<hex>",
                    "note": "no t= element found"},
        )
    if not timestamp.lstrip("-").isdigit():
        return _invalid(provider, Reason.TIMESTAMP_NOT_INTEGER,
                        detail={"timestamp": timestamp})
    timestamp_int = int(timestamp)

    if not v1_signatures:
        return _invalid(
            provider,
            Reason.MALFORMED_HEADER,
            timestamp=timestamp_int,
            detail={"header": "Stripe-Signature", "expected": "t=<unix>,v1=<hex>",
                    "note": "no v1 signature found; v0 is a test-only scheme and is "
                            "never accepted"},
        )

    fresh, why, age = _check_recency(timestamp_int, tolerance=tolerance, now=now,
                                     provider=provider)
    if not fresh:
        return _invalid(provider, why, timestamp=timestamp_int, timestamp_age=age,
                        detail={"tolerance": tolerance})

    signed_payload = f"{timestamp_int}.{payload.decode('utf-8', 'surrogateescape')}"
    expected = hmac.new(
        _secret_bytes(secret), signed_payload.encode("utf-8", "surrogateescape"),
        hashlib.sha256,
    ).hexdigest()

    # Multiple v1 values are normal while an endpoint secret is being rolled.
    for candidate in v1_signatures:
        if _constant_time_eq(expected.encode("ascii"), candidate.encode("utf-8")):
            return _valid(provider, timestamp=timestamp_int, timestamp_age=age)

    return _invalid(provider, Reason.SIGNATURE_MISMATCH, timestamp=timestamp_int,
                    timestamp_age=age,
                    detail={"schemes_present": ["v1"], "v1_count": len(v1_signatures)})


# --------------------------------------------------------------------------
# GitHub -- X-Hub-Signature-256: sha256=<hex>, HMAC-SHA256 over raw body.
# Source: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
# Official test vector published on that page:
#   secret "It's a Secret to Everybody", payload "Hello, World!"
#   -> 757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17
# --------------------------------------------------------------------------

def verify_github(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    tolerance: int | None = None,   # no timestamp exists; accepted and ignored
    now: float | None = None,
) -> VerifyResult:
    provider = "github"
    headers = Headers(headers)
    payload = _as_bytes(payload)

    name, header_value = headers.get_any("X-Hub-Signature-256", "X-Hub-Signature")
    delivery_id = headers.get("X-GitHub-Delivery")

    if not header_value:
        return _invalid(
            provider, Reason.MISSING_HEADER, delivery_id=delivery_id,
            detail={"header": "X-Hub-Signature-256",
                    "note": "GitHub omits this header entirely when no webhook "
                            "secret is configured -- a missing header is not a "
                            "valid delivery"},
        )

    if name == "X-Hub-Signature":
        # Legacy HMAC-SHA1 header. GitHub ships it "for legacy purposes" only.
        return _invalid(
            provider, Reason.NO_MATCHING_SCHEME, delivery_id=delivery_id,
            detail={"header": name,
                    "note": "X-Hub-Signature is the deprecated HMAC-SHA1 header; "
                            "use X-Hub-Signature-256"},
        )

    if "=" not in header_value:
        return _invalid(provider, Reason.MALFORMED_HEADER, delivery_id=delivery_id,
                        detail={"header": name, "expected": "sha256=<hex>"})

    algorithm, _, signature_hex = header_value.partition("=")
    algorithm = algorithm.strip().lower()
    signature_hex = signature_hex.strip()

    if algorithm != "sha256":
        return _invalid(provider, Reason.NO_MATCHING_SCHEME, delivery_id=delivery_id,
                        detail={"algorithm": algorithm, "expected": "sha256"})

    if not _is_hex(signature_hex) or len(signature_hex) != 64:
        return _invalid(provider, Reason.MALFORMED_HEADER, delivery_id=delivery_id,
                        detail={"header": name,
                                "note": "sha256= must be followed by 64 hex characters"})

    expected = hmac.new(_secret_bytes(secret), payload, hashlib.sha256).hexdigest()
    if _constant_time_eq(expected.encode("ascii"), signature_hex.encode("ascii")):
        return _valid(provider, Reason.OK_NO_REPLAY_CHECK, delivery_id=delivery_id,
                      detail={"replay": "GitHub deliveries carry no usable "
                                        "timestamp; deduplicate on X-GitHub-Delivery"})

    return _invalid(provider, Reason.SIGNATURE_MISMATCH, delivery_id=delivery_id)


# --------------------------------------------------------------------------
# Shopify -- X-Shopify-Hmac-Sha256: base64(HMAC-SHA256(raw body, client secret)).
# Source: https://shopify.dev/docs/apps/build/webhooks/verify-deliveries
# --------------------------------------------------------------------------

def verify_shopify(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    tolerance: int | None = None,
    now: float | None = None,
) -> VerifyResult:
    provider = "shopify"
    headers = Headers(headers)
    payload = _as_bytes(payload)

    header_value = headers.get("X-Shopify-Hmac-Sha256")
    webhook_id = headers.get("X-Shopify-Webhook-Id")
    event_id = headers.get("X-Shopify-Event-Id")
    topic = headers.get("X-Shopify-Topic")

    if not header_value:
        return _invalid(provider, Reason.MISSING_HEADER,
                        delivery_id=webhook_id,
                        detail={"header": "X-Shopify-Hmac-Sha256"})

    provided = _b64_decode(header_value)
    if provided is None:
        return _invalid(provider, Reason.MALFORMED_HEADER, delivery_id=webhook_id,
                        detail={"header": "X-Shopify-Hmac-Sha256",
                                "note": "expected standard base64 of a 32-byte "
                                        "HMAC-SHA256 digest"})

    expected = hmac.new(_secret_bytes(secret), payload, hashlib.sha256).digest()
    if _constant_time_eq(expected, provided):
        return _valid(
            provider, Reason.OK_NO_REPLAY_CHECK, delivery_id=webhook_id,
            detail={
                "topic": topic,
                "shopify_event_id": event_id,
                "replay": "no timestamp in the delivery",
                "dedupe_key": "X-Shopify-Webhook-Id (per subscription); "
                              "X-Shopify-Event-Id correlates the same merchant "
                              "action across subscriptions",
            },
        )

    return _invalid(provider, Reason.SIGNATURE_MISMATCH, delivery_id=webhook_id)


# --------------------------------------------------------------------------
# Slack -- X-Slack-Signature: v0=<hex>, HMAC-SHA256 over
# "v0:{X-Slack-Request-Timestamp}:{raw body}". Tolerance 5 minutes.
# Source: https://docs.slack.dev/authentication/verifying-requests-from-slack/
# Slack's documented worked example (secret 8f742231b10e8888abcd99yyyzzz85a5,
# ts 1531420618) yields v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503
# --------------------------------------------------------------------------

def verify_slack(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    tolerance: int | None = None,
    now: float | None = None,
) -> VerifyResult:
    provider = "slack"
    headers = Headers(headers)
    payload = _as_bytes(payload)
    tolerance = DEFAULT_TOLERANCE_SECONDS if tolerance is None else tolerance
    now = time.time() if now is None else now

    ts_header = headers.get("X-Slack-Request-Timestamp")
    sig_header = headers.get("X-Slack-Signature")

    if not ts_header:
        return _invalid(provider, Reason.MISSING_HEADER,
                        detail={"header": "X-Slack-Request-Timestamp"})
    if not sig_header:
        return _invalid(provider, Reason.MISSING_HEADER,
                        detail={"header": "X-Slack-Signature"})

    if not ts_header.strip().lstrip("-").isdigit():
        return _invalid(provider, Reason.TIMESTAMP_NOT_INTEGER,
                        detail={"timestamp": ts_header})
    timestamp_int = int(ts_header)

    if not sig_header.startswith("v0="):
        return _invalid(provider, Reason.MALFORMED_HEADER,
                        detail={"header": "X-Slack-Signature",
                                "expected": "v0=<hex>", "got_prefix": sig_header[:8]})
    signature_hex = sig_header[3:].strip()
    if not _is_hex(signature_hex):
        return _invalid(provider, Reason.MALFORMED_HEADER,
                        detail={"header": "X-Slack-Signature",
                                "note": "v0= must be followed by hex"})

    # Check recency FIRST: it is cheap and it stops a captured request from
    # being replayed indefinitely, which a signature check alone cannot do.
    fresh, why, age = _check_recency(timestamp_int, tolerance=tolerance, now=now,
                                     provider=provider)
    if not fresh:
        return _invalid(provider, why, timestamp=timestamp_int, timestamp_age=age,
                        detail={"tolerance": tolerance})

    basestring = b"v0:" + ts_header.strip().encode("ascii") + b":" + payload
    expected = hmac.new(_secret_bytes(secret), basestring, hashlib.sha256).hexdigest()
    if _constant_time_eq(expected.encode("ascii"), signature_hex.encode("ascii")):
        return _valid(provider, timestamp=timestamp_int, timestamp_age=age)

    return _invalid(provider, Reason.SIGNATURE_MISMATCH, timestamp=timestamp_int,
                    timestamp_age=age)


def slack_url_verification_challenge(
    payload: Any,
    result: VerifyResult,
    *,
    echo_challenge: bool = True,
) -> dict[str, Any] | None:
    """Handle Slack's ``url_verification`` handshake after a *verified* request.

    Slack POSTs ``{"type": "url_verification", "challenge": "..."}`` when you
    first configure the Request URL, and expects the challenge echoed back as
    ``text/plain``. Returning the challenge for an *unverified* request would
    let anyone confirm your endpoint, so a failed verification short-circuits.

    Returns ``{"challenge": <str>}`` when the body is a challenge that should be
    echoed, else ``None``. Call it only after ``verify_slack`` returned truthy.
    """
    if not result:
        return None
    try:
        document = json.loads(_as_bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or document.get("type") != "url_verification":
        return None
    challenge = document.get("challenge")
    if not isinstance(challenge, str):
        return None
    return {"challenge": challenge} if echo_challenge else None


# --------------------------------------------------------------------------
# Twilio -- X-Twilio-Signature: base64(HMAC-SHA1(signing_string, auth_token)).
#
# IMPORTANT: Twilio does not sign the body. The signing string is the full
# request URL (scheme, host, port, query string) with every POST parameter
# appended as name+value, parameters sorted by name, and -- for repeated names
# -- each value sorted too, with no delimiters. HMAC-SHA1, base64.
#
# https://www.twilio.com/docs/usage/security states the whole algorithm and a
# worked example, and that example reproduces EXACTLY here (re-checked against
# the live page: token 12345, url https://example.com/myapp.php?foo=1&bar=2,
# params CallSid/Caller/Digits/From/To -> L/OH5YylLD5NRKLltdqwSvS0BnU=). The
# docs still label it "illustrative only", so the port variants and the
# repeated-parameter rule were cross-checked against the official
# twilio-python RequestValidator source:
#   https://github.com/twilio/twilio-python/blob/main/twilio/request_validator.py
# (add_port/remove_port: Twilio's backend is inconsistent about the port, so a
# signature computed with OR without the explicit port is accepted; and values
# for a repeated name are de-duplicated then sorted, as `sorted(set(values))`.)
#
# For application/json bodies Twilio appends a bodySHA256 query parameter to the
# URL (hex SHA-256 of the raw body) and signs the URL alone; we verify both the
# hash and the signature.
# Source: https://www.twilio.com/docs/usage/webhooks/webhooks-security
# --------------------------------------------------------------------------

def _twilio_signing_string(url: str, params: Mapping[str, Any] | Sequence[tuple[str, Any]]) -> str:
    items: list[tuple[str, str]]
    if isinstance(params, Mapping):
        items = [(str(k), str(v)) for k, v in params.items()]
    else:
        items = [(str(k), str(v)) for k, v in params]

    grouped: dict[str, list[str]] = {}
    for key, value in items:
        grouped.setdefault(key, []).append(value)

    signing = url
    for key in sorted(grouped):
        for value in sorted(set(grouped[key])):
            signing += key + value
    return signing


def _twilio_params_from_body(payload: bytes) -> dict[str, str] | None:
    """Parse an application/x-www-form-urlencoded body the way Twilio checks it."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=False)
    if not pairs:
        return None
    params: dict[str, str] = {}
    for key, value in pairs:
        params[key] = value
    return params


def verify_twilio(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    url: str | None = None,
    params: Mapping[str, Any] | None = None,
    tolerance: int | None = None,
    now: float | None = None,
) -> VerifyResult:
    """Verify ``X-Twilio-Signature``.

    Unlike every other provider here, Twilio does not sign the request body.
    Either:

    * ``params=`` -- pass the form parameters Twilio POSTed (the same values you
      parsed out of an ``application/x-www-form-urlencoded`` body), or
    * leave ``params`` unset and pass the urlencoded body as ``payload``, and
      this function parses it for you, or
    * for ``application/json`` deliveries, leave ``params`` unset and pass the
      raw JSON body as ``payload``; Twilio puts a ``bodySHA256`` query parameter
      in ``url`` and signs the URL alone, and we verify that hash too.

    ``url`` is REQUIRED and must be the exact URL Twilio was configured with,
    including query string, with URL-encoded characters left encoded. If you
    decode or re-encode the URL the signature will not match.

    THERE IS NO REPLAY CHECK. Twilio's signature contains no timestamp, so a
    captured request stays valid forever. Deduplicate on ``MessageSid``/
    ``CallSid`` through the idempotency layer -- that is the only defence.
    """
    provider = "twilio"
    headers = Headers(headers)
    payload = _as_bytes(payload)

    header_value = headers.get("X-Twilio-Signature")
    if not header_value:
        return _invalid(provider, Reason.MISSING_HEADER,
                        detail={"header": "X-Twilio-Signature"})
    if url is None:
        return _invalid(
            provider, Reason.MISSING_ARGUMENT,
            detail={"required": "url",
                    "note": "Twilio signs the full request URL plus the POST "
                            "parameters; pass the exact configured URL, "
                            "query string included and still URL-encoded"},
        )

    provided = _b64_decode(header_value)
    if provided is None:
        return _invalid(provider, Reason.MALFORMED_HEADER,
                        detail={"header": "X-Twilio-Signature",
                                "note": "expected base64 of a SHA-1 digest"})

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    signing_params: dict[str, str]
    body_hash_detail: dict[str, Any] = {}

    if params is not None:
        signing_params = {str(k): str(v) for k, v in params.items()}
    elif "bodySHA256" in query and payload.lstrip()[:1] in (b"{", b"["):
        # JSON delivery: Twilio signs the URL (with bodySHA256) and no params.
        digest = hashlib.sha256(payload).hexdigest()
        expected_hash = query["bodySHA256"][0]
        if not _constant_time_eq(digest.encode("ascii"), expected_hash.encode("ascii")):
            return _invalid(
                provider, Reason.BODY_HASH_MISMATCH,
                detail={"expected": expected_hash, "actual": digest,
                        "note": "the raw body does not match the bodySHA256 query "
                                "parameter, so the delivery was altered in transit"},
            )
        signing_params = {}
        body_hash_detail = {"bodySHA256_verified": True}
    else:
        form = _twilio_params_from_body(payload)
        if form is None:
            return _invalid(
                provider, Reason.MISSING_ARGUMENT,
                detail={"required": "params",
                        "note": "body is not urlencoded form data and there is no "
                                "bodySHA256 query parameter; pass params= explicitly"},
            )
        signing_params = form

    # Twilio's backend is inconsistent about the port, so the official SDK
    # accepts a signature computed with or without it. We do the same.
    candidates = {url}
    if parsed.port is None:
        netloc = parsed.netloc + (":443" if parsed.scheme == "https" else ":80")
        candidates.add(parsed._replace(netloc=netloc).geturl())
    else:
        candidates.add(parsed._replace(
            netloc=parsed.netloc.split(":")[0]).geturl())

    secret_bytes = _secret_bytes(secret)
    for candidate_url in candidates:
        signing_string = _twilio_signing_string(candidate_url, signing_params)
        # Compare RAW DIGEST BYTES. The header is base64 (decoded into
        # `provided` above), so the computed digest must be compared as bytes
        # too. Comparing the base64 text against raw bytes always fails -- and
        # that failure looks exactly like "wrong secret", which is why it costs
        # people so much time.
        expected_digest = hmac.new(secret_bytes, signing_string.encode("utf-8"),
                                   hashlib.sha1).digest()
        if _constant_time_eq(expected_digest, provided):
            detail = {
                "signed_url_variant": "with_port" if candidate_url != url else "as_given",
                "param_count": len(signing_params),
                "replay": "Twilio signatures carry no timestamp; replay is "
                          "unlimited. Deduplicate on MessageSid/CallSid.",
                **body_hash_detail,
            }
            return _valid(provider, Reason.OK_NO_REPLAY_CHECK,
                          detail=detail)

    return _invalid(
        provider, Reason.SIGNATURE_MISMATCH,
        detail={
            "param_count": len(signing_params),
            "hint": "the most common causes are a proxy-rewritten URL (http vs "
                    "https, host, or the port), a URL that was decoded and "
                    "re-encoded, or params parsed from a body that a framework "
                    "had already whitespace-trimmed",
            **body_hash_detail,
        },
    )


# --------------------------------------------------------------------------
# Paddle -- Paddle-Signature: ts=<unix>;h1=<hex>, HMAC-SHA256 over
# f"{ts}:{raw body}", hex. SDK default tolerance 5 seconds.
# Source: https://developer.paddle.com/webhooks/about/signature-verification/
# Cross-checked against the official SDK source (PaddleSignature.verify) and its
# own unit-test vector:
#   secret pdl_ntfset_01hs0t3tw21j988db1pam5xg8m_GrOWLNef+vmtjJYq4mSnHNzvc8uWoJ1I
#   ts 1710498758 -> 558bf93944dbeb4790c7a8af6cb2ea435c8ca9c8396aafc1a4e37424ac132744
# --------------------------------------------------------------------------

def verify_paddle(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    tolerance: int | None = 5,
    now: float | None = None,
) -> VerifyResult:
    provider = "paddle"
    headers = Headers(headers)
    payload = _as_bytes(payload)

    tolerance = TOLERANCE_SECONDS["paddle"] if tolerance is None else tolerance
    now = time.time() if now is None else now

    header_value = headers.get("Paddle-Signature")
    if not header_value:
        return _invalid(provider, Reason.MISSING_HEADER,
                        detail={"header": "Paddle-Signature"})

    timestamp: str | None = None
    h1_values: list[str] = []
    for element in header_value.split(";"):
        element = element.strip()
        if not element or "=" not in element:
            continue
        key, _, value = element.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "ts":
            timestamp = value
        elif key == "h1":
            h1_values.append(value)

    if timestamp is None or not h1_values:
        return _invalid(provider, Reason.MALFORMED_HEADER,
                        detail={"header": "Paddle-Signature",
                                "expected": "ts=<unix>;h1=<hex>"})
    if not timestamp.lstrip("-").isdigit():
        return _invalid(provider, Reason.TIMESTAMP_NOT_INTEGER,
                        detail={"timestamp": timestamp})
    timestamp_int = int(timestamp)

    fresh, why, age = _check_recency(timestamp_int, tolerance=tolerance, now=now,
                                     provider=provider)
    if not fresh:
        return _invalid(provider, why, timestamp=timestamp_int, timestamp_age=age,
                        detail={"tolerance": tolerance,
                                "hint": "Paddle's SDK default is only 5 seconds; "
                                        "if you see this in production your "
                                        "server clock is probably skewed (use NTP)"})

    signed_payload = f"{timestamp_int}:".encode("ascii") + payload
    expected = hmac.new(_secret_bytes(secret), signed_payload,
                        hashlib.sha256).hexdigest()
    for candidate in h1_values:
        if _constant_time_eq(expected.encode("ascii"), candidate.encode("ascii")):
            return _valid(provider, timestamp=timestamp_int, timestamp_age=age,
                          detail={"h1_count": len(h1_values)})

    return _invalid(provider, Reason.SIGNATURE_MISMATCH, timestamp=timestamp_int,
                    timestamp_age=age, detail={"h1_count": len(h1_values)})


# --------------------------------------------------------------------------
# Lemon Squeezy -- X-Signature: hex HMAC-SHA256 of the raw body using the
# webhook's signing secret.
# Source: https://docs.lemonsqueezy.com/help/webhooks/signing-requests
# NOTE (re-verified against the live page): the docs state "an HMAC hex digest"
# and name the `X-Signature` header, but publish no secret+payload test vector,
# so the digest itself could not be checked against an official value. The
# page's Node sample is oddly written -- it wraps the hex digest in
# Buffer.from(digest, 'utf8') and compares that to the header with
# timingSafeEqual -- which works only because 64 ASCII hex characters are 64
# bytes, i.e. it is still a comparison of HEX TEXT, not of raw digest bytes.
# This implementation compares hex strings for the same reason. See
# docs/PROVIDER-SCHEMES.md ("partially verified").
# --------------------------------------------------------------------------

def verify_lemonsqueezy(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    tolerance: int | None = None,
    now: float | None = None,
) -> VerifyResult:
    provider = "lemonsqueezy"
    headers = Headers(headers)
    payload = _as_bytes(payload)

    header_value = headers.get("X-Signature")
    event_name = headers.get("X-Event-Name")

    if not header_value:
        return _invalid(provider, Reason.MISSING_HEADER,
                        detail={"header": "X-Signature"})

    signature_hex = header_value.strip().lower()
    if len(signature_hex) != 64:
        return _invalid(
            provider, Reason.MALFORMED_HEADER,
            detail={"header": "X-Signature",
                    "note": "expected 64 hex characters (HMAC-SHA256 hex digest)"},
        )
    if not _is_hex(signature_hex):
        return _invalid(provider, Reason.MALFORMED_HEADER,
                        detail={"header": "X-Signature",
                                "note": "header is not hexadecimal"})

    expected = hmac.new(_secret_bytes(secret), payload, hashlib.sha256).hexdigest()
    if _constant_time_eq(expected.encode("ascii"), signature_hex.encode("ascii")):
        return _valid(
            provider, Reason.OK_NO_REPLAY_CHECK,
            detail={"event_name": event_name,
                    "replay": "Lemon Squeezy sends no timestamp header, so a "
                              "captured request cannot be aged out. Deduplicate "
                              "on the payload's data.id / meta.event_name "
                              "through the idempotency layer."},
        )

    return _invalid(provider, Reason.SIGNATURE_MISMATCH)


# --------------------------------------------------------------------------
# Svix (used by Svix, and by every Standard Webhooks sender) --
#   svix-id, svix-timestamp, svix-signature
# signed content = f"{id}.{timestamp}.{raw body}"
# key = base64-decode the part of the secret after "whsec_"
# HMAC-SHA256, base64. svix-signature is a SPACE-separated list of
# "v1,<base64>" entries; strip the version prefix before comparing.
# Source: https://docs.svix.com/receiving/verifying-payloads/how-manual
# Official worked example on that page:
#   secret whsec_plJ3nmyCDGBKInavdOK15jsl
#   id msg_loFOjxBNrRLzqYUf, ts 1731705121
#   -> v1,rAvfW3dJ/X/qxhsaXPOyyCGmRKsaKWcsNccKXlIktD0=
# --------------------------------------------------------------------------

def verify_svix(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    tolerance: int | None = None,
    now: float | None = None,
) -> VerifyResult:
    provider = "svix"
    headers = Headers(headers)
    payload = _as_bytes(payload)
    tolerance = DEFAULT_TOLERANCE_SECONDS if tolerance is None else tolerance
    now = time.time() if now is None else now

    # White-labelled Svix customers get the "webhook-" prefix instead.
    id_name, msg_id = headers.get_any("svix-id", "webhook-id")
    ts_name, ts_header = headers.get_any("svix-timestamp", "webhook-timestamp")
    sig_name, sig_header = headers.get_any("svix-signature", "webhook-signature")

    if not msg_id:
        return _invalid(provider, Reason.MISSING_HEADER,
                        detail={"header": "svix-id"})
    if not ts_header:
        return _invalid(provider, Reason.MISSING_HEADER, delivery_id=msg_id,
                        detail={"header": "svix-timestamp"})
    if not sig_header:
        return _invalid(provider, Reason.MISSING_HEADER, delivery_id=msg_id,
                        detail={"header": "svix-signature"})

    if not ts_header.strip().lstrip("-").isdigit():
        return _invalid(provider, Reason.TIMESTAMP_NOT_INTEGER, delivery_id=msg_id,
                        detail={"timestamp": ts_header})
    timestamp_int = int(ts_header)

    fresh, why, age = _check_recency(timestamp_int, tolerance=tolerance, now=now,
                                     provider=provider)
    if not fresh:
        return _invalid(provider, why, delivery_id=msg_id, timestamp=timestamp_int,
                        timestamp_age=age, detail={"tolerance": tolerance})

    raw_secret = secret.decode("utf-8") if isinstance(secret, bytes) else secret
    if not isinstance(raw_secret, str):
        return _invalid(provider, Reason.MISSING_SECRET, delivery_id=msg_id)

    # "whsec_<base64>": use the base64 part, decoded. A secret without the
    # prefix is used as the literal UTF-8 bytes.
    if raw_secret.startswith("whsec_"):
        key = _b64_decode(raw_secret[len("whsec_"):])
        if key is None:
            return _invalid(provider, Reason.MISSING_SECRET, delivery_id=msg_id,
                            detail={"note": "secret after whsec_ is not valid base64"})
    else:
        key = raw_secret.encode("utf-8")

    signed_content = f"{msg_id}.{timestamp_int}.".encode("utf-8") + payload
    expected = base64.b64encode(
        hmac.new(key, signed_content, hashlib.sha256).digest()
    ).decode("ascii")

    # Space-separated list, each entry "v1,<base64>". Multiple secrets may be
    # active during rotation, so any match wins.
    for entry in sig_header.split():
        version, _, candidate = entry.partition(",")
        if version.strip() != "v1" or not candidate:
            continue
        if _constant_time_eq(expected.encode("ascii"),
                             candidate.strip().encode("ascii")):
            return _valid(provider, delivery_id=msg_id, timestamp=timestamp_int,
                          timestamp_age=age,
                          detail={"id_header": id_name, "timestamp_header": ts_name,
                                  "signature_header": sig_name})

    return _invalid(provider, Reason.SIGNATURE_MISMATCH, delivery_id=msg_id,
                    timestamp=timestamp_int, timestamp_age=age,
                    detail={"note": "no v1,<base64> entry in svix-signature matched"})


# --------------------------------------------------------------------------
# Linear -- Linear-Signature: hex HMAC-SHA256 over the raw body.
# Replay: compare the parsed body's webhookTimestamp (milliseconds) against
# "now", Linear's docs recommend 60 seconds. This verifier reads that value
# from the (already-verified) JSON body via `webhook_timestamp_ms=`, because the
# signed string does not include it -- a timestamp cannot be authenticated here,
# only bounded, so an attacker who captured a whole request still has a 60s
# window. Documented in docs/FAILURE-MODES.md.
# Source: https://linear.app/developers/webhooks  ("Securing Webhooks")
# --------------------------------------------------------------------------

def verify_linear(
    payload: Any,
    headers: Any,
    secret: Any,
    *,
    webhook_timestamp_ms: int | None = None,
    tolerance: int | None = None,
    now: float | None = None,
) -> VerifyResult:
    provider = "linear"
    headers = Headers(headers)
    payload = _as_bytes(payload)
    tolerance = TOLERANCE_SECONDS["linear"] if tolerance is None else tolerance
    now = time.time() if now is None else now

    header_value = headers.get("Linear-Signature")
    delivery_id = headers.get("Linear-Delivery")
    event_type = headers.get("Linear-Event")

    if not header_value:
        return _invalid(provider, Reason.MISSING_HEADER, delivery_id=delivery_id,
                        detail={"header": "Linear-Signature"})

    signature_hex = header_value.strip().lower()
    if len(signature_hex) != 64 or not _is_hex(signature_hex):
        return _invalid(provider, Reason.MALFORMED_HEADER, delivery_id=delivery_id,
                        detail={"header": "Linear-Signature",
                                "note": "expected 64 hex characters"})

    expected = hmac.new(_secret_bytes(secret), payload, hashlib.sha256).hexdigest()
    if not _constant_time_eq(expected.encode("ascii"), signature_hex.encode("ascii")):
        return _invalid(provider, Reason.SIGNATURE_MISMATCH, delivery_id=delivery_id)

    detail: dict[str, Any] = {"event": event_type}
    timestamp_int: int | None = None
    age: int | None = None

    if webhook_timestamp_ms is None:
        # Signature is authentic; try to read webhookTimestamp out of the
        # payload we just authenticated. Never trust an unverified body.
        try:
            document = json.loads(payload.decode("utf-8"))
            if isinstance(document, dict):
                candidate = document.get("webhookTimestamp")
                if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                    webhook_timestamp_ms = int(candidate)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass

    if webhook_timestamp_ms is None:
        detail["replay"] = ("no webhookTimestamp found in the authenticated body, so "
                            "no recency check was possible; pass "
                            "webhook_timestamp_ms= to enforce one")
        return _valid(provider, Reason.OK_NO_REPLAY_CHECK, delivery_id=delivery_id,
                      detail=detail)

    timestamp_int = int(webhook_timestamp_ms // 1000)
    age = int(now - webhook_timestamp_ms / 1000.0)
    if age > tolerance:
        return _invalid(provider, Reason.TIMESTAMP_EXPIRED, delivery_id=delivery_id,
                        timestamp=timestamp_int, timestamp_age=age,
                        detail={**detail, "tolerance": tolerance,
                                "webhookTimestamp": webhook_timestamp_ms})
    if -age > tolerance:
        return _invalid(provider, Reason.TIMESTAMP_IN_FUTURE, delivery_id=delivery_id,
                        timestamp=timestamp_int, timestamp_age=age,
                        detail={**detail, "tolerance": tolerance,
                                "webhookTimestamp": webhook_timestamp_ms})

    detail["webhookTimestamp"] = webhook_timestamp_ms
    return _valid(provider, delivery_id=delivery_id, timestamp=timestamp_int,
                  timestamp_age=age, detail=detail)


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

_VERIFIERS = {
    "stripe": verify_stripe,
    "github": verify_github,
    "shopify": verify_shopify,
    "slack": verify_slack,
    "twilio": verify_twilio,
    "paddle": verify_paddle,
    "lemonsqueezy": verify_lemonsqueezy,
    "svix": verify_svix,
    "linear": verify_linear,
}

#: Provider docs that were read to build this file. Reported by --selftest.
VERIFIED_AGAINST: dict[str, str] = {
    "stripe": "https://docs.stripe.com/webhooks (md: /webhooks.md) + https://docs.stripe.com/webhooks/signature",
    "github": "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
    "shopify": "https://shopify.dev/docs/apps/build/webhooks/verify-deliveries",
    "slack": "https://docs.slack.dev/authentication/verifying-requests-from-slack/",
    "twilio": "https://www.twilio.com/docs/usage/security + https://www.twilio.com/docs/usage/webhooks/webhooks-security + twilio-python/twilio/request_validator.py",
    "paddle": "https://developer.paddle.com/webhooks/about/signature-verification/ + PaddleHQ/paddle-python-sdk PaddleSignature.py",
    "lemonsqueezy": "https://docs.lemonsqueezy.com/help/webhooks/signing-requests",
    "svix": "https://docs.svix.com/receiving/verifying-payloads/how-manual",
    "linear": "https://linear.app/developers/webhooks",
}

#: Providers people ask for that are deliberately NOT here, and why.
NOT_INCLUDED: dict[str, str] = {
    "sendgrid": "The SendGrid Event Webhook is not HMAC. It uses ECDSA over "
                "SHA-256(ts + raw body) with an ASN.1 DER signature and a "
                "public key you generate in the dashboard, so it does not fit "
                "an HMAC verifier and would need an ECDSA implementation. "
                "Verified at https://www.twilio.com/docs/sendgrid/for-developers/"
                "tracking-events/getting-started-event-webhook-security-features",
    "mailgun": "Mailgun signs timestamp+token only -- NOT the payload -- and "
               "carries the token, timestamp and signature INSIDE the JSON body "
               "rather than in headers, so you must parse the body before you "
               "can verify anything about it. Adding it to this pack would "
               "encourage exactly the parse-then-verify order this pack warns "
               "about. Verified at https://documentation.mailgun.com/docs/mailgun/"
               "user-manual/webhooks/securing-webhooks",
    "standardwebhooks": "Use verify_svix: Standard Webhooks uses the identical "
                        "construction and the same svix-* headers.",
}


def verify(
    provider: str,
    payload: Any,
    headers: Any,
    secret: Any,
    **options: Any,
) -> VerifyResult:
    """Verify a webhook delivery. Returns a :class:`VerifyResult`, never raises
    on malformed *input*.

    ``payload``  raw request body bytes (see the module docstring -- this is the
                 whole point of the pack)
    ``headers``  mapping or iterable of (name, value); case-insensitive
    ``secret``   the provider's signing secret / auth token

    Extra keyword arguments are provider specific and documented on each
    verifier: ``tolerance``, ``now``, ``url``, ``params``,
    ``webhook_timestamp_ms``.

    Programmer errors (an unknown provider, a dict passed as the payload, a
    non-str/bytes secret) DO raise -- silently returning "invalid" there would
    hide a wiring bug behind a security-looking rejection. Malformed *wire data*
    (truncated header, bad base64, non-numeric timestamp, wrong length) never
    raises; it comes back as ``valid=False`` with a specific ``reason``.
    """
    key = (provider or "").strip().lower()
    handler = _VERIFIERS.get(key)
    if handler is None:
        raise ValueError(
            f"unsupported provider {provider!r}; supported: "
            f"{', '.join(SUPPORTED_PROVIDERS)}"
        )
    try:
        return handler(payload, headers, secret, **options)
    except TypeError:
        raise
    except Exception as exc:  # defensive: a verifier bug must not 500 the endpoint
        return _invalid(key, Reason.INTERNAL_ERROR,
                        detail={"exception": type(exc).__name__, "message": str(exc)})


def verify_bool(
    provider: str,
    payload: Any,
    headers: Any,
    secret: Any,
    **options: Any,
) -> bool:
    """``verify()`` collapsed to a plain bool, for callers that want nothing else."""
    return bool(verify(provider, payload, headers, secret, **options))


def signing_string_preview(provider: str, payload: bytes, headers: Any, *,
                           now: float | None = None) -> bytes | str:
    """Return the exact byte string that must be HMACed, for debugging.

    This exists because "which string is signed?" is the question that costs
    people an afternoon. It never exposes the secret -- the secret is only ever
    the key, never part of the signed string.
    """
    headers = Headers(headers)
    key = provider.strip().lower()
    if key == "stripe":
        value = headers.get("Stripe-Signature") or ""
        ts = None
        for element in value.split(","):
            prefix, _, val = element.partition("=")
            if prefix.strip() == "t":
                ts = val.strip()
                break
        return f"{ts}.{payload.decode('utf-8', 'surrogateescape')}"
    if key == "github":
        return payload
    if key == "shopify":
        return payload
    if key == "slack":
        ts = (headers.get("X-Slack-Request-Timestamp") or "").strip()
        return b"v0:" + ts.encode("ascii") + b":" + payload
    if key == "paddle":
        value = headers.get("Paddle-Signature") or ""
        ts = None
        for element in value.split(";"):
            k, _, v = element.partition("=")
            if k.strip() == "ts":
                ts = v.strip()
                break
        return f"{ts}:".encode("ascii") + payload
    if key == "svix":
        msg_id = headers.get("svix-id") or headers.get("webhook-id") or ""
        ts = headers.get("svix-timestamp") or headers.get("webhook-timestamp") or ""
        return f"{msg_id}.{ts}.".encode("utf-8") + payload
    if key in ("lemonsqueezy", "linear"):
        return payload
    if key == "twilio":
        raise ValueError("twilio signs the URL plus sorted params, not the body; "
                         "use verify_twilio(params=..., url=...) and log "
                         "_twilio_signing_string")
    raise ValueError(f"unsupported provider {provider!r}")


def selftest() -> int:
    """Verify every published provider test vector. Returns the number of
    checks that failed (0 == all good). Run with ``python verify.py``."""
    failures: list[str] = []
    checks = 0

    def check(name: str, condition: bool, extra: str = "") -> None:
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(f"{name} {extra}".strip())

    # --- GitHub's published vector -----------------------------------------
    gh_secret = "It's a Secret to Everybody"
    gh_body = b"Hello, World!"
    gh_sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    r = verify_github(gh_body, {"X-Hub-Signature-256": gh_sig}, gh_secret)
    check("github published vector", bool(r), str(r.reason))
    check("github tamper rejected",
          not verify_github(b"Hello, World?", {"X-Hub-Signature-256": gh_sig},
                            gh_secret))

    # --- Stripe: header shown verbatim in Stripe's own docs -----------------
    # Stripe publishes the format, not a secret+payload pair, so we check that
    # the documented header shape parses and that our construction reproduces
    # the same digest Stripe's algorithm describes.
    stripe_secret = "whsec_test_secret"
    stripe_body = b'{"id":"evt_test","object":"event"}'
    ts = int(time.time())
    v1 = hmac.new(stripe_secret.encode(), f"{ts}.{stripe_body.decode()}".encode(),
                  hashlib.sha256).hexdigest()
    header = f"t={ts},v1={v1},v0=6ffbb59b2300aae63f272406069a9788598b792a944a07aba816edb039989a39"
    check("stripe v1 accepted",
          bool(verify_stripe(stripe_body, {"Stripe-Signature": header}, stripe_secret)))
    check("stripe v0 downgrade rejected",
          not verify_stripe(stripe_body, {"Stripe-Signature": f"t={ts},v0={v1}"},
                            stripe_secret), "v0 must never be accepted")
    check("stripe expired rejected",
          not verify_stripe(stripe_body, {"Stripe-Signature": f"t={ts - 4000},v1={v1}"},
                            stripe_secret))

    # --- Slack's documented worked example ---------------------------------
    # The docs publish the basestring, the secret and the expected digest.
    slack_secret = "8f742231b10e8888abcd99yyyzzz85a5"
    slack_ts = "1531420618"
    slack_body = (b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain="
                  b"testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id="
                  b"U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text="
                  b"&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J"
                  b"%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id="
                  b"398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c")
    expect = hmac.new(slack_secret.encode(),
                      b"v0:" + slack_ts.encode() + b":" + slack_body,
                      hashlib.sha256).hexdigest()
    check("slack documented digest reproduced",
          expect == "a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
          expect)
    # Slack's example timestamp is from 2018, so it MUST fail on replay:
    r = verify_slack(slack_body, {"X-Slack-Request-Timestamp": slack_ts,
                                  "X-Slack-Signature": "v0=" + expect}, slack_secret)
    check("slack old timestamp rejected as replay",
          (not r) and r.reason == Reason.TIMESTAMP_EXPIRED, str(r.reason))
    # ...and must pass when checked against its own era, proving the digest is right.
    r = verify_slack(slack_body, {"X-Slack-Request-Timestamp": slack_ts,
                                  "X-Slack-Signature": "v0=" + expect}, slack_secret,
                     now=1531420618)
    check("slack vector accepted at its own time", bool(r), str(r.reason))

    # --- Svix's published vector -------------------------------------------
    svix_secret = "whsec_plJ3nmyCDGBKInavdOK15jsl"
    svix_body = b'{"event_type":"ping","data":{"success":true}}'
    svix_headers = {"svix-id": "msg_loFOjxBNrRLzqYUf", "svix-timestamp": "1731705121",
                    "svix-signature": "v1,rAvfW3dJ/X/qxhsaXPOyyCGmRKsaKWcsNccKXlIktD0="}
    r = verify_svix(svix_body, svix_headers, svix_secret, now=1731705121)
    check("svix published vector", bool(r), str(r.reason))
    r = verify_svix(svix_body, svix_headers, svix_secret)
    check("svix published vector aged out", (not r) and r.reason == Reason.TIMESTAMP_EXPIRED)

    # --- Paddle's own SDK unit-test vector ---------------------------------
    paddle_secret = ("pdl_ntfset_01hs0t3tw21j988db1pam5xg8m_"
                     "GrOWLNef+vmtjJYq4mSnHNzvc8uWoJ1I")
    paddle_body = (b'{"data":{"id":"ctm_01hs0tqf76sxmp7ba5e4mw1sc8","name":"John Doe",'
                   b'"email":"blackhole+verification2@paddle.com","locale":"en",'
                   b'"status":"active","created_at":"2024-03-15T10:32:37.862Z",'
                   b'"updated_at":"2024-03-15T10:32:37.862Z","custom_data":null,'
                   b'"import_meta":null,"marketing_consent":false},'
                   b'"event_id":"evt_01hs0tqfme2xwb2hvwv87p8y3w",'
                   b'"event_type":"customer.created",'
                   b'"occurred_at":"2024-03-15T10:32:38.286848Z",'
                   b'"notification_id":"ntf_01hs0tqfrhgkyp39x4wyvy7h6n"}')
    paddle_header = "ts=1710498758;h1=558bf93944dbeb4790c7a8af6cb2ea435c8ca9c8396aafc1a4e37424ac132744"
    r = verify_paddle(paddle_body, {"Paddle-Signature": paddle_header}, paddle_secret,
                      now=1710498758)
    check("paddle SDK vector", bool(r), str(r.reason))
    r = verify_paddle(paddle_body, {"Paddle-Signature": paddle_header}, paddle_secret)
    check("paddle SDK vector aged out", (not r) and r.reason == Reason.TIMESTAMP_EXPIRED)

    # --- Twilio's published example, per the official SDK -------------------
    twilio_token = "12345"
    twilio_url = "https://example.com/myapp.php?foo=1&bar=2"
    twilio_params = {"Digits": "1234", "To": "+18005551212", "From": "+14158675310",
                     "Caller": "+14158675310", "CallSid": "CA1234567890ABCDE"}
    r = verify_twilio(b"", {"X-Twilio-Signature": "L/OH5YylLD5NRKLltdqwSvS0BnU="},
                      twilio_token, url=twilio_url, params=twilio_params)
    check("twilio SDK vector", bool(r), str(r.reason))

    # --- Shopify / Lemon Squeezy / Linear: no published vector exists, so we
    #     assert round-trip + tamper behaviour against the documented algorithm.
    for provider, header_name, encode in (
        ("shopify", "X-Shopify-Hmac-Sha256", "base64"),
        ("lemonsqueezy", "X-Signature", "hex"),
        ("linear", "Linear-Signature", "hex"),
    ):
        body = b'{"probe":true}'
        sec = "round_trip_secret"
        digest = hmac.new(sec.encode(), body, hashlib.sha256)
        header = (base64.b64encode(digest.digest()).decode() if encode == "base64"
                  else digest.hexdigest())
        r = verify(provider, body, {header_name: header}, sec)
        check(f"{provider} round trip", bool(r), str(r.reason))
        r = verify(provider, body + b" ", {header_name: header}, sec)
        check(f"{provider} tamper rejected", not r, str(r.reason))
        r = verify(provider, body, {header_name: header}, "wrong_secret")
        check(f"{provider} wrong secret rejected", not r, str(r.reason))
        r = verify(provider, body, {}, sec)
        check(f"{provider} missing header rejected",
              (not r) and r.reason == Reason.MISSING_HEADER, str(r.reason))

    # --- malformed input must never raise ----------------------------------
    hostile = [
        ("stripe", b"x", {"Stripe-Signature": "t=abc,v1=zz"}, "s"),
        ("stripe", b"x", {"Stripe-Signature": "garbage"}, "s"),
        ("stripe", b"x", {"Stripe-Signature": ""}, "s"),
        ("github", b"x", {"X-Hub-Signature-256": "sha256=nothex"}, "s"),
        ("github", b"x", {"X-Hub-Signature-256": "sha1=abc"}, "s"),
        ("shopify", b"x", {"X-Shopify-Hmac-Sha256": "!!!not base64!!!"}, "s"),
        ("slack", b"x", {"X-Slack-Request-Timestamp": "soon",
                         "X-Slack-Signature": "v0=x"}, "s"),
        ("slack", b"x", {"X-Slack-Request-Timestamp": "1",
                         "X-Slack-Signature": "nope"}, "s"),
        ("twilio", b"x", {"X-Twilio-Signature": "=@="}, "s"),
        ("twilio", b"x", {"X-Twilio-Signature": "AAAA"}, "s"),
        ("paddle", b"x", {"Paddle-Signature": "ts=no;h1=zz"}, "s"),
        ("lemonsqueezy", b"x", {"X-Signature": "short"}, "s"),
        ("svix", b"x", {"svix-id": "", "svix-timestamp": "",
                        "svix-signature": "v1,"}, "s"),
        ("svix", b"x", {"svix-id": "m", "svix-timestamp": "x",
                        "svix-signature": "v1,zz"}, "s"),
        ("linear", b"x", {"Linear-Signature": "0" * 63}, "s"),
    ]
    for provider, body, headers, sec in hostile:
        try:
            r = verify(provider, body, headers, sec)
            check(f"{provider} hostile input returns result", isinstance(r, VerifyResult))
            check(f"{provider} hostile input is rejected", not r,
                  f"accepted {headers!r}")
        except Exception as exc:  # noqa: BLE001
            check(f"{provider} hostile input did not raise", False,
                  f"{type(exc).__name__}: {exc}")

    # --- the re-serialisation trap is refused, not silently wrong ----------
    for bad in ({"id": "evt_1"}, ["evt_1"], '{"id":"evt_1"}'):
        try:
            verify("stripe", bad, {"Stripe-Signature": "t=1,v1=" + "0" * 64}, "s")
            check(f"parsed payload {type(bad).__name__} refused", False,
                  "should have raised TypeError")
        except TypeError:
            check(f"parsed payload {type(bad).__name__} refused", True)

    print(f"selftest: {checks - len(failures)}/{checks} checks passed")
    for failure in failures:
        print(f"  FAIL {failure}")
    return len(failures)


if __name__ == "__main__":  # pragma: no cover
    import sys

    print(f"verify.py {__version__} -- providers: {', '.join(SUPPORTED_PROVIDERS)}")
    print()
    for name in SUPPORTED_PROVIDERS:
        tolerance = TOLERANCE_SECONDS[name]
        shown = "no replay check possible" if tolerance is None else f"{tolerance}s tolerance"
        print(f"  {name:14s} {shown}")
    print()
    sys.exit(1 if selftest() else 0)
