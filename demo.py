#!/usr/bin/env python3
"""Prove the verifiers accept what they should and reject what they should not.

Standard library only. Run:  python3 demo.py

Three details a naive demo gets wrong, and which this handles:

1. Every case names its OWN body file. Reading the provider's default body for
   all cases makes the tampered-body test silently vacuous.
2. Some cases override the secret (the "wrong secret" case). Using the provider
   secret for every case makes that test vacuous too.
3. Signature fixtures carry a FROZEN timestamp, and providers with replay
   protection reject anything outside their tolerance - so a fixture signed when
   the pack was built is expired by the time you run it. For those providers the
   demo re-signs at the current time, which is what a real webhook looks like.
"""
import base64, hashlib, hmac, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "python"))
from verify import verify  # noqa: E402

TIMESTAMPED = {"stripe": ("Stripe-Signature", "t={t},v1={s}", "{t}.{body}"),
               "slack":  ("X-Slack-Signature", "v0={s}", "v0:{t}:{body}")}
PLAIN = {"github":  ("X-Hub-Signature-256", "sha256={s}"),
         "shopify": ("X-Shopify-Hmac-Sha256", "{s}")}
# Cases whose point is that the fixture is stale or from the future.
CLOCK_CASES = {"expired_timestamp", "future_timestamp"}


def sign(name, body: bytes, secret: str, ts: int | None = None):
    ts = int(time.time()) if ts is None else ts
    if name in TIMESTAMPED:
        hdr, tmpl, signed = TIMESTAMPED[name]
        base = signed.format(t=ts, body=body.decode())
        sig = hmac.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
        return {hdr: tmpl.format(t=ts, s=sig)}
    if name in PLAIN:
        hdr, tmpl = PLAIN[name]
        raw = hmac.new(secret.encode(), body, hashlib.sha256)
        val = base64.b64encode(raw.digest()).decode() if name == "shopify" else raw.hexdigest()
        return {hdr: tmpl.format(s=val)}
    return None


def main():
    m = json.load(open(os.path.join(HERE, "fixtures", "manifest.json")))
    total = passed = 0

    for name, p in sorted(m["providers"].items()):
        print(f"\n=== {name} ===")
        provider_secret = p["secret"]

        for case, spec in sorted(p["cases"].items()):
            if case in CLOCK_CASES:
                continue
            body_file = spec.get("body_file") or p.get("body_file")
            path = os.path.join(HERE, "fixtures", body_file)
            if not os.path.exists(path):
                print(f"  skip  {case:22s} ({body_file} not in this repo)")
                continue
            body = open(path, "rb").read()          # <-- per-case body
            secret = spec.get("secret", provider_secret)   # <-- per-case secret
            headers = dict(spec.get("headers", {}))

            if case == "valid":
                fresh = sign(name, body, secret)
                if fresh:
                    headers = fresh
            elif case == "tampered_body":
                # sign the ORIGINAL body, then send the tampered one: the payload
                # no longer matches the signature, so it MUST be rejected.
                original = open(os.path.join(HERE, "fixtures",
                                             p.get("body_file")), "rb").read()
                fresh = sign(name, original, secret)
                if fresh:
                    headers = fresh

            result = verify(name, body, headers, secret)
            got = bool(result)
            want = case == "valid"
            good = got == want
            total += 1
            passed += good
            print(f"  {'PASS' if good else 'FAIL'}  {case:22s} "
                  f"accepted={str(got):5s} {getattr(result, 'reason', '')}")

        # replay: a signature made a day ago must be refused where supported
        if name in TIMESTAMPED:
            body = open(os.path.join(HERE, "fixtures", p.get("body_file")), "rb").read()
            stale = sign(name, body, provider_secret, ts=int(time.time()) - 86400)
            r = verify(name, body, stale, provider_secret)
            good = not r
            total += 1
            passed += good
            print(f"  {'PASS' if good else 'FAIL'}  {'replay_1_day_old':22s} "
                  f"accepted={str(bool(r)):5s} {getattr(r, 'reason', '')}")

    print(f"\n{passed}/{total} checks behaved as expected")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
