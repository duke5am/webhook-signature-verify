/**
 * Webhook signature verification for 9 providers. Zero dependencies.
 *
 *   import { verify } from "./verify.mjs";
 *   const result = verify("stripe", rawBodyBytes, req.headers, process.env.STRIPE_WEBHOOK_SECRET);
 *   if (!result.ok) return res.status(401).json({ reason: result.reason });
 *
 * THE ONE RULE
 * ------------
 * `payload` MUST be the raw request body bytes, exactly as they arrived.
 * Never `JSON.stringify(req.body)`, never a re-encoded string. Every provider
 * signs the bytes it put on the wire; re-serialising changes key order,
 * whitespace, unicode escaping and number formatting, so the HMAC stops
 * matching -- and the usual "fix" for that is to weaken the check, which is how
 * forged webhooks get accepted.
 *
 * In Express the reliable way to get raw bytes on a webhook route is:
 *   app.post("/webhooks/stripe", express.raw({ type: "*\/*" }), handler)
 * placed BEFORE any `express.json()`, or with `verify: (req,_res,buf)=>req.rawBody=buf`.
 * In Next.js App Router: `await req.arrayBuffer()` and never call `req.json()` first.
 * In Fastify: `addContentTypeParser` with `parseAs: "buffer"`.
 *
 * Passing a plain object, array, or string where bytes are expected THROWS, on
 * purpose. That is the bug this pack exists to prevent.
 *
 * WHAT THIS MODULE DOES NOT DO
 * ----------------------------
 * It authenticates the sender and, where the provider supplies a timestamp,
 * rejects replay. It does not make your handler's business logic correct and it
 * does not make a duplicate delivery harmless -- that is what `idempotency/`
 * is for.
 *
 * Providers verified against first-party documentation and, where available, an
 * official test vector or official SDK source: stripe, github, shopify, slack,
 * twilio, paddle, lemonsqueezy, svix, linear. See docs/PROVIDER-SCHEMES.md for
 * the URL each construction was read from and the providers deliberately absent.
 */

import { createHmac, timingSafeEqual, createHash } from "node:crypto";

export const VERSION = "1.0.0";

export const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * Per-provider default replay tolerance, in seconds. `null` means the provider
 * gives the verifier nothing trustworthy to compare against a clock, so no
 * recency check is possible; the result says so in `reason`/`detail`.
 */
export const TOLERANCE_SECONDS = Object.freeze({
  stripe: 300,          // Stripe's own libraries default to 5 minutes
  github: null,         // no timestamp in the delivery
  shopify: null,        // no timestamp in the delivery
  slack: 300,           // Slack's docs: "more than five minutes"
  twilio: null,         // signature covers URL + params only, no timestamp
  paddle: 5,            // Paddle SDK default is 5 seconds
  lemonsqueezy: null,   // no timestamp in the delivery
  svix: 300,            // Svix sends svix-timestamp; 5 min is the usual setting
  linear: 60,           // Linear's docs: "within a minute"
});

export const SUPPORTED_PROVIDERS = Object.freeze(Object.keys(TOLERANCE_SECONDS).sort());

/** Stable machine-readable reason codes. Compare against these, not prose. */
export const Reason = Object.freeze({
  OK: "ok",
  OK_NO_REPLAY_CHECK: "ok_no_replay_check",
  MISSING_HEADER: "missing_header",
  MALFORMED_HEADER: "malformed_header",
  MALFORMED_PAYLOAD: "malformed_payload",
  NO_MATCHING_SCHEME: "no_matching_scheme",
  SIGNATURE_MISMATCH: "signature_mismatch",
  TIMESTAMP_EXPIRED: "timestamp_expired",
  TIMESTAMP_IN_FUTURE: "timestamp_in_future",
  TIMESTAMP_NOT_INTEGER: "timestamp_not_integer",
  MISSING_SECRET: "missing_secret",
  MISSING_ARGUMENT: "missing_argument",
  BODY_HASH_MISMATCH: "body_hash_mismatch",
  UNSUPPORTED_PROVIDER: "unsupported_provider",
  INTERNAL_ERROR: "internal_error",
});

/* ------------------------------------------------------------------ *
 * input normalisation -- strict on purpose
 * ------------------------------------------------------------------ */

/** Coerce the payload to a Buffer, refusing anything already parsed. */
function asBytes(payload) {
  if (Buffer.isBuffer(payload)) return payload;
  if (payload instanceof Uint8Array) return Buffer.from(payload);
  if (payload instanceof ArrayBuffer) return Buffer.from(payload);
  if (typeof payload === "string") {
    throw new TypeError(
      "payload must be raw bytes (Buffer/Uint8Array), not a string. A string means " +
      "the body was already decoded somewhere; re-encoding it can change the bytes " +
      "and quietly break the HMAC. Read the raw body (Express: express.raw(); " +
      "Next.js: await req.arrayBuffer()) and pass those bytes."
    );
  }
  throw new TypeError(
    `payload must be raw bytes, got ${payload === null ? "null" : typeof payload}` +
    (payload && typeof payload === "object" ? ` (${payload.constructor?.name})` : "") +
    ". Never pass a parsed object -- re-serialising it changes key order and " +
    "whitespace and the signature will not match."
  );
}

/**
 * Case-insensitive, duplicate-tolerant header view. Accepts a `Headers` (fetch),
 * a Node `IncomingHttpHeaders` object, a `Map`, or an array of [name, value].
 */
class HeaderBag {
  constructor(headers) {
    this.map = new Map();
    if (headers == null) return;

    const put = (name, value) => {
      if (typeof name !== "string" || value == null) return;
      const key = name.trim().toLowerCase();
      if (this.map.has(key)) return; // first wins, like Node's own lookup
      this.map.set(key, Array.isArray(value) ? String(value[0] ?? "") : String(value));
    };

    if (typeof headers.forEach === "function" && typeof headers.get === "function") {
      headers.forEach((value, name) => put(name, value));            // fetch Headers / Map
    } else if (Array.isArray(headers)) {
      for (const pair of headers) { if (pair) put(pair[0], pair[1]); }
    } else if (typeof headers[Symbol.iterator] === "function") {
      for (const pair of headers) { if (pair) put(pair[0], pair[1]); }
    } else if (typeof headers === "object") {
      for (const [name, value] of Object.entries(headers)) put(name, value);
    }
  }

  get(name) {
    if (typeof name !== "string") return undefined;
    return this.map.get(name.trim().toLowerCase());
  }

  /** Returns [name, value] for the first of `names` that is present. */
  getAny(...names) {
    for (const name of names) {
      const value = this.get(name);
      if (value !== undefined) return [name, value];
    }
    return [undefined, undefined];
  }
}

function b64ToBuffer(value) {
  if (typeof value !== "string") return null;
  const candidate = value.trim();
  if (!candidate) return null;
  // Reject anything that is not canonical base64 rather than letting Node
  // silently ignore garbage characters.
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(candidate)) return null;
  const padding = "=".repeat((4 - (candidate.length % 4)) % 4);
  const buf = Buffer.from(candidate + padding, "base64");
  // Round-trip check: base64 that decodes then re-encodes differently was not
  // valid to begin with.
  const normalised = buf.toString("base64").replace(/=+$/, "");
  if (normalised !== candidate.replace(/=+$/, "")) return null;
  return buf;
}

function isHex(value) {
  return typeof value === "string" && value.length > 0 && /^[0-9a-fA-F]+$/.test(value);
}

/**
 * Constant-time comparison that never throws on unequal lengths.
 *
 * `crypto.timingSafeEqual` THROWS if the two buffers differ in length -- a
 * very common source of 500s in webhook handlers, which then look like
 * "provider retried and it worked the second time" instead of a clean 401.
 * We normalise the timing profile first and return false.
 */
function constantTimeEqual(expected, provided) {
  if (!Buffer.isBuffer(expected) || !Buffer.isBuffer(provided)) return false;
  if (expected.length !== provided.length) {
    // Burn a comparison anyway so the early return is not a timing oracle.
    timingSafeEqual(
      createHash("sha256").update(expected).digest(),
      createHash("sha256").update(provided).digest()
    );
    return false;
  }
  return timingSafeEqual(expected, provided);
}

function secretToString(secret) {
  if (Buffer.isBuffer(secret)) return secret.toString("utf8");
  if (secret instanceof Uint8Array) return Buffer.from(secret).toString("utf8");
  if (typeof secret === "string") return secret;
  throw new TypeError(`secret must be a string or Buffer, got ${typeof secret}`);
}

function checkRecency(timestampSeconds, { tolerance, now }) {
  const age = Math.trunc(now - timestampSeconds);
  if (age > tolerance) return { fresh: false, reason: Reason.TIMESTAMP_EXPIRED, age };
  if (-age > tolerance) return { fresh: false, reason: Reason.TIMESTAMP_IN_FUTURE, age };
  return { fresh: true, reason: Reason.OK, age };
}

function invalid(provider, reason, extra = {}) {
  return { valid: false, ok: false, reason, provider, ...extra };
}

function valid(provider, reason = Reason.OK, extra = {}) {
  return { valid: true, ok: true, reason, provider, ...extra };
}

function needsArgument(provider, reason, detail) {
  return invalid(provider, reason, { detail });
}

/* ------------------------------------------------------------------ *
 * Stripe -- Stripe-Signature: t=<unix>,v1=<hex>,v0=<hex>
 * HMAC-SHA256 over `${t}.${payload}`, hex. Tolerance default 300s.
 * Source: https://docs.stripe.com/webhooks (verify manually) and
 *         https://docs.stripe.com/webhooks/signature
 * ------------------------------------------------------------------ */

export function verifyStripe(payload, headers, secret, options = {}) {
  const provider = "stripe";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  const now = options.now ?? Date.now() / 1000;

  const headerValue = bag.get("Stripe-Signature");
  if (!headerValue) return invalid(provider, Reason.MISSING_HEADER, { detail: { header: "Stripe-Signature" } });

  let timestamp = null;
  const v1Signatures = [];
  // Only v1. Stripe's docs: ignore every scheme that is not v1, so an attacker
  // cannot downgrade to the fake v0 scheme.
  for (const rawElement of headerValue.split(",")) {
    const element = rawElement.trim();
    const eq = element.indexOf("=");
    if (eq === -1) continue;
    const prefix = element.slice(0, eq).trim();
    const value = element.slice(eq + 1).trim();
    if (prefix === "t" && timestamp === null) timestamp = value;
    else if (prefix === "v1" && value) v1Signatures.push(value);
  }

  if (timestamp === null || v1Signatures.length === 0) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      detail: { header: "Stripe-Signature", expected: "t=<unix>,v1=<hex>" },
    });
  }
  if (!/^-?\d+$/.test(timestamp)) {
    return invalid(provider, Reason.TIMESTAMP_NOT_INTEGER, { detail: { timestamp } });
  }
  const ts = Number(timestamp);

  const recency = checkRecency(ts, { tolerance, now });
  if (!recency.fresh) {
    return invalid(provider, recency.reason, {
      timestamp: ts, timestampAge: recency.age, detail: { tolerance },
    });
  }

  const signedPayload = Buffer.concat([
    Buffer.from(`${ts}.`, "utf8"),
    body,
  ]);
  const expected = createHmac("sha256", secretToString(secret))
    .update(signedPayload)
    .digest("hex");

  for (const candidate of v1Signatures) {
    if (constantTimeEqual(Buffer.from(expected, "ascii"), Buffer.from(candidate, "ascii"))) {
      return valid(provider, Reason.OK, { timestamp: ts, timestampAge: recency.age });
    }
  }
  return invalid(provider, Reason.SIGNATURE_MISMATCH, {
    timestamp: ts, timestampAge: recency.age,
    detail: { v1Count: v1Signatures.length },
  });
}

/* ------------------------------------------------------------------ *
 * GitHub -- X-Hub-Signature-256: sha256=<hex>, HMAC-SHA256 over raw body.
 * Source: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
 * Official vector on that page: secret "It's a Secret to Everybody",
 * payload "Hello, World!" -> 757107ea...b043e17
 * ------------------------------------------------------------------ */

export function verifyGithub(payload, headers, secret, options = {}) {
  const provider = "github";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);

  const [name, headerValue] = bag.getAny("X-Hub-Signature-256", "X-Hub-Signature");
  const deliveryId = bag.get("X-GitHub-Delivery");

  if (!headerValue) {
    return invalid(provider, Reason.MISSING_HEADER, {
      deliveryId,
      detail: {
        header: "X-Hub-Signature-256",
        note: "GitHub omits this header entirely when no webhook secret is configured -- a missing header is not a valid delivery",
      },
    });
  }
  if (name === "X-Hub-Signature") {
    return invalid(provider, Reason.NO_MATCHING_SCHEME, {
      deliveryId,
      detail: { header: name, note: "X-Hub-Signature is the deprecated HMAC-SHA1 header; use X-Hub-Signature-256" },
    });
  }

  const eq = headerValue.indexOf("=");
  if (eq === -1) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      deliveryId, detail: { header: name, expected: "sha256=<hex>" },
    });
  }
  const algorithm = headerValue.slice(0, eq).trim().toLowerCase();
  const signatureHex = headerValue.slice(eq + 1).trim();

  if (algorithm !== "sha256") {
    return invalid(provider, Reason.NO_MATCHING_SCHEME, {
      deliveryId, detail: { algorithm, expected: "sha256" },
    });
  }
  if (!isHex(signatureHex) || signatureHex.length !== 64) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      deliveryId,
      detail: { header: name, note: "sha256= must be followed by 64 hex characters" },
    });
  }

  const expected = createHmac("sha256", secretToString(secret)).update(body).digest("hex");
  if (constantTimeEqual(Buffer.from(expected, "ascii"), Buffer.from(signatureHex, "ascii"))) {
    return valid(provider, Reason.OK_NO_REPLAY_CHECK, {
      deliveryId,
      detail: { replay: "GitHub deliveries carry no usable timestamp; deduplicate on X-GitHub-Delivery" },
    });
  }
  return invalid(provider, Reason.SIGNATURE_MISMATCH, { deliveryId });
}

/* ------------------------------------------------------------------ *
 * Shopify -- X-Shopify-Hmac-Sha256: base64(HMAC-SHA256(raw body, client secret)).
 * Source: https://shopify.dev/docs/apps/build/webhooks/verify-deliveries
 * ------------------------------------------------------------------ */

export function verifyShopify(payload, headers, secret, options = {}) {
  const provider = "shopify";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);

  const headerValue = bag.get("X-Shopify-Hmac-Sha256");
  const webhookId = bag.get("X-Shopify-Webhook-Id");
  const eventId = bag.get("X-Shopify-Event-Id");
  const topic = bag.get("X-Shopify-Topic");

  if (!headerValue) {
    return invalid(provider, Reason.MISSING_HEADER, {
      deliveryId: webhookId, detail: { header: "X-Shopify-Hmac-Sha256" },
    });
  }

  const provided = b64ToBuffer(headerValue);
  if (provided === null) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      deliveryId: webhookId,
      detail: { header: "X-Shopify-Hmac-Sha256", note: "expected standard base64 of a 32-byte HMAC-SHA256 digest" },
    });
  }

  const expected = createHmac("sha256", secretToString(secret)).update(body).digest();
  if (constantTimeEqual(expected, provided)) {
    return valid(provider, Reason.OK_NO_REPLAY_CHECK, {
      deliveryId: webhookId,
      detail: {
        topic,
        shopifyEventId: eventId,
        replay: "no timestamp in the delivery",
        dedupeKey: "X-Shopify-Webhook-Id (per subscription); X-Shopify-Event-Id correlates the same merchant action across subscriptions",
      },
    });
  }
  return invalid(provider, Reason.SIGNATURE_MISMATCH, { deliveryId: webhookId });
}

/* ------------------------------------------------------------------ *
 * Slack -- X-Slack-Signature: v0=<hex>, HMAC-SHA256 over
 * "v0:{X-Slack-Request-Timestamp}:{raw body}". Tolerance 5 minutes.
 * Source: https://docs.slack.dev/authentication/verifying-requests-from-slack/
 * Slack's published worked example yields
 * v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503
 * ------------------------------------------------------------------ */

export function verifySlack(payload, headers, secret, options = {}) {
  const provider = "slack";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  const now = options.now ?? Date.now() / 1000;

  const tsHeader = bag.get("X-Slack-Request-Timestamp");
  const sigHeader = bag.get("X-Slack-Signature");

  if (!tsHeader) return invalid(provider, Reason.MISSING_HEADER, { detail: { header: "X-Slack-Request-Timestamp" } });
  if (!sigHeader) return invalid(provider, Reason.MISSING_HEADER, { detail: { header: "X-Slack-Signature" } });

  if (!/^-?\d+$/.test(tsHeader.trim())) {
    return invalid(provider, Reason.TIMESTAMP_NOT_INTEGER, { detail: { timestamp: tsHeader } });
  }
  const ts = Number(tsHeader.trim());

  if (!sigHeader.startsWith("v0=")) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      detail: { header: "X-Slack-Signature", expected: "v0=<hex>", gotPrefix: sigHeader.slice(0, 8) },
    });
  }
  const signatureHex = sigHeader.slice(3).trim();
  if (!isHex(signatureHex)) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      detail: { header: "X-Slack-Signature", note: "v0= must be followed by hex" },
    });
  }

  // Recency FIRST: cheap, and it is the only thing that stops a captured
  // request from being replayed forever.
  const recency = checkRecency(ts, { tolerance, now });
  if (!recency.fresh) {
    return invalid(provider, recency.reason, {
      timestamp: ts, timestampAge: recency.age, detail: { tolerance },
    });
  }

  const expected = createHmac("sha256", secretToString(secret))
    .update(Buffer.concat([Buffer.from(`v0:${tsHeader.trim()}:`, "utf8"), body]))
    .digest("hex");

  if (constantTimeEqual(Buffer.from(expected, "ascii"), Buffer.from(signatureHex, "ascii"))) {
    return valid(provider, Reason.OK, { timestamp: ts, timestampAge: recency.age });
  }
  return invalid(provider, Reason.SIGNATURE_MISMATCH, { timestamp: ts, timestampAge: recency.age });
}

/**
 * Slack's `url_verification` handshake, to call ONLY after verifySlack passed.
 * Returning the challenge for an unverified request lets anyone confirm that
 * your endpoint exists.
 */
export function slackUrlVerificationChallenge(payload, result) {
  if (!result || !result.ok) return null;
  let document;
  try {
    document = JSON.parse(asBytes(payload).toString("utf8"));
  } catch {
    return null;
  }
  if (!document || typeof document !== "object" || document.type !== "url_verification") return null;
  if (typeof document.challenge !== "string") return null;
  return { challenge: document.challenge };
}

/* ------------------------------------------------------------------ *
 * Twilio -- X-Twilio-Signature: base64(HMAC-SHA1(signing string, auth token)).
 *
 * IMPORTANT: Twilio does NOT sign the body. The signing string is the full
 * request URL (scheme, host, port, query string) with every POST parameter
 * appended as name+value, sorted by name -- and for repeated names, each value
 * sorted too -- with no delimiters. HMAC-SHA1, base64.
 *
 * Twilio's docs state the whole algorithm and a worked example, and the example
 * reproduces EXACTLY here (re-checked against the live page: token 12345, url
 * https://example.com/myapp.php?foo=1&bar=2, params CallSid/Caller/Digits/From/To
 * -> L/OH5YylLD5NRKLltdqwSvS0BnU=). The docs still label it "illustrative only",
 * so the port variants and the repeated-parameter rule were cross-checked against
 * the official twilio-python RequestValidator source: Twilio's backend is
 * inconsistent about the port, so a signature computed with OR without it is
 * accepted, and values for a repeated name are de-duplicated then sorted.
 *
 * For application/json bodies Twilio appends a bodySHA256 query parameter to
 * the URL (hex SHA-256 of the raw body) and signs the URL alone; both the hash
 * and the signature are checked.
 * Source: https://www.twilio.com/docs/usage/webhooks/webhooks-security
 * ------------------------------------------------------------------ */

export function twilioSigningString(url, params = {}) {
  const grouped = new Map();
  const entries = params instanceof Map ? [...params.entries()] : Object.entries(params ?? {});
  for (const [key, value] of entries) {
    const k = String(key);
    if (!grouped.has(k)) grouped.set(k, new Set());
    grouped.get(k).add(String(value));
  }
  let signing = url;
  for (const key of [...grouped.keys()].sort()) {
    for (const value of [...grouped.get(key)].sort()) signing += key + value;
  }
  return signing;
}

function twilioParamsFromBody(body) {
  const text = body.toString("utf8");
  if (!text) return null;
  const params = {};
  let found = false;
  for (const pair of text.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const rawKey = eq === -1 ? pair : pair.slice(0, eq);
    const rawValue = eq === -1 ? "" : pair.slice(eq + 1);
    try {
      const key = decodeURIComponent(rawKey.replace(/\+/g, " "));
      params[key] = decodeURIComponent(rawValue.replace(/\+/g, " "));
      found = true;
    } catch {
      return null; // malformed percent-encoding
    }
  }
  return found ? params : null;
}

export function verifyTwilio(payload, headers, secret, options = {}) {
  const provider = "twilio";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);
  const url = options.url;

  const headerValue = bag.get("X-Twilio-Signature");
  if (!headerValue) return invalid(provider, Reason.MISSING_HEADER, { detail: { header: "X-Twilio-Signature" } });
  if (!url) {
    return needsArgument(provider, Reason.MISSING_ARGUMENT, {
      required: "url",
      note: "Twilio signs the full request URL plus the POST parameters; pass the exact configured URL, query string included and still URL-encoded",
    });
  }

  const provided = b64ToBuffer(headerValue);
  if (provided === null) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      detail: { header: "X-Twilio-Signature", note: "expected base64 of a SHA-1 digest" },
    });
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return needsArgument(provider, Reason.MISSING_ARGUMENT, {
      required: "url", note: "url is not parseable as an absolute URL",
    });
  }

  let signingParams;
  let bodyHashDetail = {};

  if (options.params !== undefined && options.params !== null) {
    const source = options.params instanceof Map ? Object.fromEntries(options.params) : options.params;
    signingParams = Object.fromEntries(Object.entries(source).map(([k, v]) => [String(k), String(v)]));
  } else {
    const bodySha = parsed.searchParams.get("bodySHA256");
    const looksJson = /^\s*[{[]/.test(body.toString("utf8").slice(0, 1));
    if (bodySha && looksJson) {
      const digest = createHash("sha256").update(body).digest("hex");
      if (!constantTimeEqual(Buffer.from(digest, "ascii"), Buffer.from(bodySha, "ascii"))) {
        return invalid(provider, Reason.BODY_HASH_MISMATCH, {
          detail: {
            expected: bodySha, actual: digest,
            note: "the raw body does not match the bodySHA256 query parameter, so the delivery was altered in transit",
          },
        });
      }
      signingParams = {};
      bodyHashDetail = { bodySHA256Verified: true };
    } else {
      // Like Python's parse_qsl(keep_blank_values=True): keep repeated keys and
      // preserve each value; twilioSigningString sorts and de-duplicates.
      const multi = {};
      let any = false;
      for (const pair of body.toString("utf8").split("&")) {
        if (!pair) continue;
        const eq = pair.indexOf("=");
        let rawKey = eq === -1 ? pair : pair.slice(0, eq);
        const rawValue = eq === -1 ? "" : pair.slice(eq + 1);
        let key, value;
        try {
          key = decodeURIComponent(rawKey.replace(/\+/g, " "));
          value = decodeURIComponent(rawValue.replace(/\+/g, " "));
        } catch {
          return invalid(provider, Reason.MISSING_ARGUMENT, {
            detail: { required: "params", note: "body has malformed percent-encoding; pass params= explicitly" },
          });
        }
        if (multi[key] === undefined) multi[key] = [];
        multi[key].push(value);
        any = true;
      }
      if (!any) {
        return invalid(provider, Reason.MISSING_ARGUMENT, {
          detail: {
            required: "params",
            note: "body is not urlencoded form data and there is no bodySHA256 query parameter; pass params= explicitly",
          },
        });
      }
      signingParams = multi;
    }
  }

  // Twilio's backend is inconsistent about the port, so the official SDK accepts
  // a signature computed with or without it. We do the same.
  const candidates = new Set([url]);
  if (parsed.port === "") {
    const withPort = new URL(url);
    withPort.port = parsed.protocol === "https:" ? "443" : "80";
    candidates.add(withPort.toString());
  } else {
    const withoutPort = new URL(url);
    withoutPort.port = "";
    candidates.add(withoutPort.toString());
  }

  const key = secretToString(secret);
  for (const candidateUrl of candidates) {
    const signingString = twilioSigningString(candidateUrl, signingParams);
    const expected = createHmac("sha1", key).update(Buffer.from(signingString, "utf8")).digest();
    // Compare RAW DIGEST BYTES: the header was base64-decoded above. Comparing
    // base64 text against raw bytes always fails, and that failure looks
    // exactly like "wrong secret".
    if (constantTimeEqual(expected, provided)) {
      return valid(provider, Reason.OK_NO_REPLAY_CHECK, {
        detail: {
          signedUrlVariant: candidateUrl === url ? "as_given" : "port_variant",
          paramCount: Object.keys(signingParams).length,
          replay: "Twilio signatures carry no timestamp; replay is unlimited. Deduplicate on MessageSid/CallSid.",
          ...bodyHashDetail,
        },
      });
    }
  }

  return invalid(provider, Reason.SIGNATURE_MISMATCH, {
    detail: {
      paramCount: Object.keys(signingParams).length,
      hint: "the most common causes are a proxy-rewritten URL (http vs https, host, or the port), a URL that was decoded and re-encoded, or params parsed from a body that a framework had already whitespace-trimmed",
      ...bodyHashDetail,
    },
  });
}

/* ------------------------------------------------------------------ *
 * Paddle -- Paddle-Signature: ts=<unix>;h1=<hex>, HMAC-SHA256 over
 * `${ts}:${raw body}`, hex. SDK default tolerance 5 seconds.
 * Source: https://developer.paddle.com/webhooks/about/signature-verification/
 * Cross-checked against PaddleHQ/paddle-python-sdk (PaddleSignature.py) and its
 * unit-test vector: ts 1710498758 -> 558bf93944dbeb4790c7a8af6cb2ea435c8ca9c8396aafc1a4e37424ac132744
 * ------------------------------------------------------------------ */

export function verifyPaddle(payload, headers, secret, options = {}) {
  const provider = "paddle";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);
  const tolerance = options.tolerance ?? TOLERANCE_SECONDS.paddle;
  const now = options.now ?? Date.now() / 1000;

  const headerValue = bag.get("Paddle-Signature");
  if (!headerValue) return invalid(provider, Reason.MISSING_HEADER, { detail: { header: "Paddle-Signature" } });

  let timestamp = null;
  const h1Values = [];
  for (const rawElement of headerValue.split(";")) {
    const element = rawElement.trim();
    const eq = element.indexOf("=");
    if (eq === -1) continue;
    const key = element.slice(0, eq).trim();
    const value = element.slice(eq + 1).trim();
    if (key === "ts") timestamp = value;
    else if (key === "h1" && value) h1Values.push(value);
  }

  if (timestamp === null || h1Values.length === 0) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      detail: { header: "Paddle-Signature", expected: "ts=<unix>;h1=<hex>" },
    });
  }
  if (!/^-?\d+$/.test(timestamp)) {
    return invalid(provider, Reason.TIMESTAMP_NOT_INTEGER, { detail: { timestamp } });
  }
  const ts = Number(timestamp);

  const recency = checkRecency(ts, { tolerance, now });
  if (!recency.fresh) {
    return invalid(provider, recency.reason, {
      timestamp: ts, timestampAge: recency.age,
      detail: {
        tolerance,
        hint: "Paddle's SDK default is only 5 seconds; if you see this in production your server clock is probably skewed (use NTP)",
      },
    });
  }

  const expected = createHmac("sha256", secretToString(secret))
    .update(Buffer.concat([Buffer.from(`${ts}:`, "utf8"), body]))
    .digest("hex");

  for (const candidate of h1Values) {
    if (constantTimeEqual(Buffer.from(expected, "ascii"), Buffer.from(candidate, "ascii"))) {
      return valid(provider, Reason.OK, { timestamp: ts, timestampAge: recency.age, detail: { h1Count: h1Values.length } });
    }
  }
  return invalid(provider, Reason.SIGNATURE_MISMATCH, {
    timestamp: ts, timestampAge: recency.age, detail: { h1Count: h1Values.length },
  });
}

/* ------------------------------------------------------------------ *
 * Lemon Squeezy -- X-Signature: hex HMAC-SHA256 of the raw body using the
 * webhook's signing secret.
 * Source: https://docs.lemonsqueezy.com/help/webhooks/signing-requests
 * NOTE (re-verified against the live page): the docs state "an HMAC hex digest"
 * and name the `X-Signature` header, but publish no secret+payload test vector,
 * so the digest could not be checked against an official value. The page's Node
 * sample wraps the hex digest in Buffer.from(digest, 'utf8') and compares it to
 * the header with timingSafeEqual -- which works only because 64 ASCII hex
 * characters are 64 bytes, i.e. it is still a comparison of HEX TEXT, not of raw
 * digest bytes. This compares hex strings for the same reason. See
 * docs/PROVIDER-SCHEMES.md ("partially verified").
 * ------------------------------------------------------------------ */

export function verifyLemonSqueezy(payload, headers, secret, options = {}) {
  const provider = "lemonsqueezy";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);

  const headerValue = bag.get("X-Signature");
  const eventName = bag.get("X-Event-Name");

  if (!headerValue) return invalid(provider, Reason.MISSING_HEADER, { detail: { header: "X-Signature" } });

  const signatureHex = headerValue.trim().toLowerCase();
  if (signatureHex.length !== 64) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      detail: { header: "X-Signature", note: "expected 64 hex characters (HMAC-SHA256 hex digest)" },
    });
  }
  if (!isHex(signatureHex)) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      detail: { header: "X-Signature", note: "header is not hexadecimal" },
    });
  }

  const expected = createHmac("sha256", secretToString(secret)).update(body).digest("hex");
  if (constantTimeEqual(Buffer.from(expected, "ascii"), Buffer.from(signatureHex, "ascii"))) {
    return valid(provider, Reason.OK_NO_REPLAY_CHECK, {
      detail: {
        eventName,
        replay: "Lemon Squeezy sends no timestamp header, so a captured request cannot be aged out. Deduplicate on the payload's data.id / meta.event_name through the idempotency layer.",
      },
    });
  }
  return invalid(provider, Reason.SIGNATURE_MISMATCH);
}

/* ------------------------------------------------------------------ *
 * Svix (and every Standard Webhooks sender) -- svix-id, svix-timestamp,
 * svix-signature. signed content = `${id}.${timestamp}.${raw body}`;
 * key = base64-decode the part of the secret after "whsec_"; HMAC-SHA256,
 * base64. svix-signature is a SPACE-separated list of "v1,<base64>".
 * Source: https://docs.svix.com/receiving/verifying-payloads/how-manual
 * Official example: secret whsec_plJ3nmyCDGBKInavdOK15jsl,
 * id msg_loFOjxBNrRLzqYUf, ts 1731705121
 * -> v1,rAvfW3dJ/X/qxhsaXPOyyCGmRKsaKWcsNccKXlIktD0=
 * ------------------------------------------------------------------ */

export function verifySvix(payload, headers, secret, options = {}) {
  const provider = "svix";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);
  const tolerance = options.tolerance ?? DEFAULT_TOLERANCE_SECONDS;
  const now = options.now ?? Date.now() / 1000;

  const [idName, msgId] = bag.getAny("svix-id", "webhook-id");
  const [tsName, tsHeader] = bag.getAny("svix-timestamp", "webhook-timestamp");
  const [sigName, sigHeader] = bag.getAny("svix-signature", "webhook-signature");

  if (!msgId) return invalid(provider, Reason.MISSING_HEADER, { detail: { header: "svix-id" } });
  if (!tsHeader) return invalid(provider, Reason.MISSING_HEADER, { deliveryId: msgId, detail: { header: "svix-timestamp" } });
  if (!sigHeader) return invalid(provider, Reason.MISSING_HEADER, { deliveryId: msgId, detail: { header: "svix-signature" } });

  if (!/^-?\d+$/.test(tsHeader.trim())) {
    return invalid(provider, Reason.TIMESTAMP_NOT_INTEGER, { deliveryId: msgId, detail: { timestamp: tsHeader } });
  }
  const ts = Number(tsHeader.trim());

  const recency = checkRecency(ts, { tolerance, now });
  if (!recency.fresh) {
    return invalid(provider, recency.reason, {
      deliveryId: msgId, timestamp: ts, timestampAge: recency.age, detail: { tolerance },
    });
  }

  const rawSecret = secretToString(secret);
  let key;
  if (rawSecret.startsWith("whsec_")) {
    key = b64ToBuffer(rawSecret.slice("whsec_".length));
    if (key === null) {
      return invalid(provider, Reason.MISSING_SECRET, {
        deliveryId: msgId, detail: { note: "secret after whsec_ is not valid base64" },
      });
    }
  } else {
    // A secret without the prefix is used as literal UTF-8 bytes.
    key = Buffer.from(rawSecret, "utf8");
  }

  const expected = createHmac("sha256", key)
    .update(Buffer.concat([Buffer.from(`${msgId}.${ts}.`, "utf8"), body]))
    .digest("base64");

  // Multiple secrets may be active during rotation, so any match wins.
  for (const entry of sigHeader.split(/\s+/)) {
    if (!entry) continue;
    const comma = entry.indexOf(",");
    if (comma === -1) continue;
    if (entry.slice(0, comma).trim() !== "v1") continue;
    const candidate = entry.slice(comma + 1).trim();
    if (!candidate) continue;
    if (constantTimeEqual(Buffer.from(expected, "ascii"), Buffer.from(candidate, "ascii"))) {
      return valid(provider, Reason.OK, {
        deliveryId: msgId, timestamp: ts, timestampAge: recency.age,
        detail: { idHeader: idName, timestampHeader: tsName, signatureHeader: sigName },
      });
    }
  }
  return invalid(provider, Reason.SIGNATURE_MISMATCH, {
    deliveryId: msgId, timestamp: ts, timestampAge: recency.age,
    detail: { note: "no v1,<base64> entry in svix-signature matched" },
  });
}

/* ------------------------------------------------------------------ *
 * Linear -- Linear-Signature: hex HMAC-SHA256 over the raw body.
 * Replay: the parsed body carries webhookTimestamp in MILLISECONDS; Linear's
 * docs recommend 60 seconds. That value is not part of the signed string, so it
 * cannot be authenticated -- only bounded. Pass it with
 * `webhookTimestampMs` or let this read it from the already-verified body.
 * Source: https://linear.app/developers/webhooks  ("Securing Webhooks")
 * ------------------------------------------------------------------ */

export function verifyLinear(payload, headers, secret, options = {}) {
  const provider = "linear";
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);
  const tolerance = options.tolerance ?? TOLERANCE_SECONDS.linear;
  const now = options.now ?? Date.now() / 1000;

  const headerValue = bag.get("Linear-Signature");
  const deliveryId = bag.get("Linear-Delivery");
  const eventType = bag.get("Linear-Event");

  if (!headerValue) return invalid(provider, Reason.MISSING_HEADER, { deliveryId, detail: { header: "Linear-Signature" } });

  const signatureHex = headerValue.trim().toLowerCase();
  if (signatureHex.length !== 64 || !isHex(signatureHex)) {
    return invalid(provider, Reason.MALFORMED_HEADER, {
      deliveryId, detail: { header: "Linear-Signature", note: "expected 64 hex characters" },
    });
  }

  const expected = createHmac("sha256", secretToString(secret)).update(body).digest("hex");
  if (!constantTimeEqual(Buffer.from(expected, "ascii"), Buffer.from(signatureHex, "ascii"))) {
    return invalid(provider, Reason.SIGNATURE_MISMATCH, { deliveryId });
  }

  const detail = { event: eventType };
  let ms = options.webhookTimestampMs;
  if (ms === undefined || ms === null) {
    // Signature is authentic; only now may we read the body.
    try {
      const document = JSON.parse(body.toString("utf8"));
      if (document && typeof document === "object" && Number.isFinite(document.webhookTimestamp)) {
        ms = document.webhookTimestamp;
      }
    } catch { /* not JSON, or no timestamp: handled below */ }
  }

  if (ms === undefined || ms === null) {
    detail.replay = "no webhookTimestamp found in the authenticated body, so no recency check was possible; pass webhookTimestampMs to enforce one";
    return valid(provider, Reason.OK_NO_REPLAY_CHECK, { deliveryId, detail });
  }

  const timestampSeconds = Math.trunc(ms / 1000);
  const age = Math.trunc(now - ms / 1000);
  if (age > tolerance) {
    return invalid(provider, Reason.TIMESTAMP_EXPIRED, {
      deliveryId, timestamp: timestampSeconds, timestampAge: age,
      detail: { ...detail, tolerance, webhookTimestamp: ms },
    });
  }
  if (-age > tolerance) {
    return invalid(provider, Reason.TIMESTAMP_IN_FUTURE, {
      deliveryId, timestamp: timestampSeconds, timestampAge: age,
      detail: { ...detail, tolerance, webhookTimestamp: ms },
    });
  }
  detail.webhookTimestamp = ms;
  return valid(provider, Reason.OK, { deliveryId, timestamp: timestampSeconds, timestampAge: age, detail });
}

/* ------------------------------------------------------------------ *
 * registry
 * ------------------------------------------------------------------ */

const VERIFIERS = Object.freeze({
  stripe: verifyStripe,
  github: verifyGithub,
  shopify: verifyShopify,
  slack: verifySlack,
  twilio: verifyTwilio,
  paddle: verifyPaddle,
  lemonsqueezy: verifyLemonSqueezy,
  svix: verifySvix,
  linear: verifyLinear,
});

/** Provider docs read to build this file. */
export const VERIFIED_AGAINST = Object.freeze({
  stripe: "https://docs.stripe.com/webhooks (md: /webhooks.md) + https://docs.stripe.com/webhooks/signature",
  github: "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
  shopify: "https://shopify.dev/docs/apps/build/webhooks/verify-deliveries",
  slack: "https://docs.slack.dev/authentication/verifying-requests-from-slack/",
  twilio: "https://www.twilio.com/docs/usage/security + https://www.twilio.com/docs/usage/webhooks/webhooks-security + twilio-python/twilio/request_validator.py",
  paddle: "https://developer.paddle.com/webhooks/about/signature-verification/ + PaddleHQ/paddle-python-sdk PaddleSignature.py",
  lemonsqueezy: "https://docs.lemonsqueezy.com/help/webhooks/signing-requests",
  svix: "https://docs.svix.com/receiving/verifying-payloads/how-manual",
  linear: "https://linear.app/developers/webhooks",
});

/** Providers people ask for that are deliberately NOT here, and why. */
export const NOT_INCLUDED = Object.freeze({
  sendgrid:
    "The SendGrid Event Webhook is not HMAC. It uses ECDSA over " +
    "SHA-256(ts + raw body) with an ASN.1 DER signature and a public key you " +
    "generate in the dashboard, so it does not fit an HMAC verifier and would " +
    "need an ECDSA implementation. Verified at https://www.twilio.com/docs/" +
    "sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features",
  mailgun:
    "Mailgun signs timestamp+token only -- NOT the payload -- and carries the " +
    "token, timestamp and signature INSIDE the JSON body rather than in " +
    "headers, so you must parse the body before you can verify anything about " +
    "it. Adding it to this pack would encourage exactly the parse-then-verify " +
    "order this pack warns about. Verified at https://documentation.mailgun.com/" +
    "docs/mailgun/user-manual/webhooks/securing-webhooks",
  standardwebhooks:
    "Use verifySvix: Standard Webhooks uses the identical construction and the same svix-* headers.",
});

/**
 * Verify a webhook delivery. Returns a result object, never throws on malformed
 * wire data.
 *
 * @param {string} provider  one of SUPPORTED_PROVIDERS
 * @param {Buffer|Uint8Array|ArrayBuffer} payload  RAW request body bytes
 * @param {object|Headers|Array} headers  case-insensitive header source
 * @param {string|Buffer} secret  signing secret / auth token
 * @param {object} [options]  provider specific: tolerance, now, url, params,
 *                            webhookTimestampMs
 * @returns {{valid:boolean, ok:boolean, reason:string, provider:string, ...}}
 *
 * Programmer errors (unknown provider, a parsed object passed as the payload, a
 * non-string secret) DO throw -- silently returning "invalid" there would hide a
 * wiring bug behind a security-looking rejection. Malformed wire data (truncated
 * header, bad base64, non-numeric timestamp, wrong length) never throws.
 */
export function verify(provider, payload, headers, secret, options = {}) {
  const key = String(provider ?? "").trim().toLowerCase();
  const handler = VERIFIERS[key];
  if (!handler) {
    throw new Error(
      `unsupported provider ${JSON.stringify(provider)}; supported: ${SUPPORTED_PROVIDERS.join(", ")}`
    );
  }
  try {
    return handler(payload, headers, secret, options);
  } catch (error) {
    if (error instanceof TypeError) throw error;
    return invalid(key, Reason.INTERNAL_ERROR, {
      detail: { exception: error?.name, message: String(error?.message ?? error) },
    });
  }
}

/** `verify()` collapsed to a plain boolean. */
export function verifyBool(provider, payload, headers, secret, options = {}) {
  return verify(provider, payload, headers, secret, options).valid === true;
}

/**
 * Return the exact byte string that must be HMACed, for debugging. "Which string
 * is signed?" is the question that costs people an afternoon. The secret is
 * never part of the signed string, so nothing sensitive is exposed.
 */
export function signingStringPreview(provider, payload, headers) {
  const bag = new HeaderBag(headers);
  const body = asBytes(payload);
  const key = String(provider ?? "").trim().toLowerCase();
  switch (key) {
    case "stripe": {
      const value = bag.get("Stripe-Signature") ?? "";
      let ts = null;
      for (const element of value.split(",")) {
        const eq = element.indexOf("=");
        if (eq !== -1 && element.slice(0, eq).trim() === "t") { ts = element.slice(eq + 1).trim(); break; }
      }
      return Buffer.concat([Buffer.from(`${ts}.`, "utf8"), body]);
    }
    case "github":
    case "shopify":
    case "lemonsqueezy":
    case "linear":
      return body;
    case "slack": {
      const ts = (bag.get("X-Slack-Request-Timestamp") ?? "").trim();
      return Buffer.concat([Buffer.from(`v0:${ts}:`, "utf8"), body]);
    }
    case "paddle": {
      const value = bag.get("Paddle-Signature") ?? "";
      let ts = null;
      for (const element of value.split(";")) {
        const eq = element.indexOf("=");
        if (eq !== -1 && element.slice(0, eq).trim() === "ts") { ts = element.slice(eq + 1).trim(); break; }
      }
      return Buffer.concat([Buffer.from(`${ts}:`, "utf8"), body]);
    }
    case "svix": {
      const id = bag.get("svix-id") ?? bag.get("webhook-id") ?? "";
      const ts = bag.get("svix-timestamp") ?? bag.get("webhook-timestamp") ?? "";
      return Buffer.concat([Buffer.from(`${id}.${ts}.`, "utf8"), body]);
    }
    case "twilio":
      throw new Error(
        "twilio signs the URL plus sorted params, not the body; use twilioSigningString(url, params)"
      );
    default:
      throw new Error(`unsupported provider ${JSON.stringify(provider)}`);
  }
}
