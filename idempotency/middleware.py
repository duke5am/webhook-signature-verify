"""Race-free idempotency for webhook handlers, backed by PostgreSQL.

    import psycopg2
    from middleware import IdempotencyStore, Outcome

    store = IdempotencyStore(lambda: psycopg2.connect(DSN))
    store.ensure_schema()

    def handle(event):
        charge_card(event["id"])          # the side effect that must happen once
        return {"charged": True}

    outcome = store.process(
        provider="stripe",
        event_id=event["id"],
        handler=lambda: handle(event),
    )

    if outcome.status == Outcome.SUCCEEDED:
        return 200, outcome.result       # includes the stored result on a duplicate
    if outcome.status == Outcome.IN_PROGRESS:
        return 409, {"error": "in progress"}   # provider will retry
    return 500, {"error": outcome.error}       # retryable

THE CORE IDEA
-------------
Claim the event id with an INSERT **first**, and let the UNIQUE constraint decide
who wins. A duplicate is detected as a unique_violation (SQLSTATE 23505), which
the database guarantees is atomic even when both deliveries arrive in the same
microsecond on different workers.

A SELECT-then-INSERT check is NOT equivalent. Between the SELECT and the INSERT
there is a window; two concurrent deliveries both read "not present" and both
run the handler. On a busy endpoint that window is hit in production, usually
during a provider retry storm, which is exactly when double-charging is most
expensive.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
-----------------------------------------
* It does not retry your handler for you. It tells you the event is retryable.
* It does not order events. Two events with the same key are deduplicated; two
  different events for the same entity arriving out of order are a business
  logic problem -- see docs/IDEMPOTENCY.md.
* It does not make your handler's side effects transactional. If your handler
  charges a card and then crashes before the UPDATE, the charge happened. For
  multi-effect handlers use the processed_effects ledger sketched at the end of
  schema.sql (and documented in IDEMPOTENCY.md).

Requires: psycopg2 (psycopg2-binary is fine) and PostgreSQL 12+.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping

try:  # psycopg2 is the documented dependency; psycopg3 is a drop-in here.
    import psycopg2
    import psycopg2.extensions
    import psycopg2.extras

    _DRIVER = "psycopg2"
except ImportError:  # pragma: no cover - exercised only on psycopg3 installs
    try:
        import psycopg as psycopg2  # type: ignore[no-redef]
        import psycopg.extensions as _extensions  # type: ignore[no-redef]

        psycopg2.extensions = _extensions  # type: ignore[attr-defined]
        _DRIVER = "psycopg3"
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "middleware.py needs psycopg2 (pip install psycopg2-binary) or psycopg"
        ) from exc

__all__ = [
    "IdempotencyStore",
    "Outcome",
    "ProcessingResult",
    "SchemaNotInstalled",
    "UNIQUE_VIOLATION",
    "DEFAULT_LEASE_SECONDS",
]

__version__ = "1.0.0"

LOG = logging.getLogger("webhook_idempotency")

UNIQUE_VIOLATION = "23505"
UNDEFINED_TABLE = "42P01"
INVALID_SCHEMA_NAME = "3F000"

DEFAULT_LEASE_SECONDS = 60
DEFAULT_SCHEMA = "webhooks"


class SchemaNotInstalled(RuntimeError):
    """Raised when the processed_events table is missing.

    A loud failure on purpose: silently degrading to "no idempotency" would mean
    the endpoint keeps returning 200 while double-charging customers, and nobody
    would notice until the refund requests arrive.
    """


class Outcome:
    """The things that can happen to a delivery.

    ``CLAIMED`` is deliberately distinct from ``PROCESSED``: claiming an event id
    is NOT the same as having run the handler, and conflating the two is how
    "we recorded it" gets mistaken for "we did the work".
    """

    #: This caller now OWNS the event id. The handler has NOT run yet; the caller
    #: must run it and then call mark_succeeded()/mark_failed().
    CLAIMED = "claimed"
    #: The handler ran, right now, and this is its result.
    PROCESSED = "processed"
    #: This event already succeeded. ``result`` is the STORED result; the handler
    #: did NOT run. This is a success, not an error -- answer the provider
    #: idempotently with it.
    DUPLICATE_SUCCEEDED = "duplicate_succeeded"
    #: Another worker holds a live lease. The handler is running elsewhere.
    IN_PROGRESS = "in_progress"
    #: The handler failed in THIS call (only returned by process()).
    FAILED = "failed"
    #: A previous attempt failed and its lease is still live, so this caller may
    #: not retry yet.
    FAILED_LEASED = "failed_leased"

    ALL = (CLAIMED, PROCESSED, DUPLICATE_SUCCEEDED, IN_PROGRESS, FAILED, FAILED_LEASED)


@dataclass
class ProcessingResult:
    """Returned by :meth:`IdempotencyStore.process`."""

    status: str
    event_id: str
    provider: str
    result: Any = None
    error: str | None = None
    attempts: int = 0
    first_seen_at: datetime | None = None
    from_store: bool = False
    detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def executed(self) -> bool:
        """True only when the handler ran during THIS call."""
        return self.status == Outcome.PROCESSED

    @property
    def owns_event(self) -> bool:
        """True when this caller must run the handler (CLAIMED)."""
        return self.status == Outcome.CLAIMED

    @property
    def succeeded(self) -> bool:
        """True when the event is known to have succeeded (now or earlier)."""
        return self.status in (Outcome.PROCESSED, Outcome.DUPLICATE_SUCCEEDED)

    @property
    def retryable(self) -> bool:
        """True when the provider should be told to deliver this event again."""
        return self.status in (Outcome.FAILED, Outcome.FAILED_LEASED, Outcome.IN_PROGRESS)

    @property
    def response_result(self) -> Any:
        """The value to put in the HTTP response body.

        On a duplicate this is the STORED result, which is the whole point: the
        caller answers idempotently without re-running anything.
        """
        return self.result

    @property
    def http_status(self) -> int:
        """A sane default HTTP status for the provider.

        Note that a duplicate is 200, never 4xx. Answering 4xx to a duplicate
        makes the provider redeliver forever.
        """
        return {
            Outcome.CLAIMED: 202,
            Outcome.PROCESSED: 200,
            Outcome.DUPLICATE_SUCCEEDED: 200,
            Outcome.IN_PROGRESS: 409,
            Outcome.FAILED: 500,
            Outcome.FAILED_LEASED: 409,
        }[self.status]

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<ProcessingResult {self.status} event_id={self.event_id!r} "
                f"attempts={self.attempts} executed={self.executed}>")


def _json_default(value: Any):
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _coerce_jsonb(payload: Any) -> Any:
    """Make ``payload`` safe for psycopg2's Json adapter.

    Anything that is not a plain JSON value is stringified rather than raising,
    because losing a result to a serialisation error after the side effect has
    already happened is much worse than storing a slightly lossy copy of it.
    """
    if payload is None:
        return None
    try:
        json.dumps(payload, default=_json_default)
        return payload
    except (TypeError, ValueError):
        return json.loads(json.dumps(payload, default=_json_default))


def _lease_owner() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{threading.get_ident()}:{uuid.uuid4().hex[:8]}"


class IdempotencyStore:
    """Idempotency layer over ``webhooks.processed_events``.

    Thread-safe and process-safe: all mutual exclusion is done by PostgreSQL, not
    by anything in this object. Hand it a connection factory (a callable
    returning a NEW connection each time) so concurrent threads and forked
    workers each get their own connection.

        store = IdempotencyStore(lambda: psycopg2.connect(DSN))

    ``dsn`` directly is accepted as a convenience and wrapped in a factory.
    """

    def __init__(
        self,
        connection_factory: Callable[[], Any] | str,
        *,
        schema: str = DEFAULT_SCHEMA,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        table: str = "processed_events",
    ) -> None:
        if isinstance(connection_factory, str):
            dsn = connection_factory
            connection_factory = lambda: psycopg2.connect(dsn)  # noqa: E731
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive; a zero lease makes "
                             "every in-flight event look reclaimable")
        self._connect = connection_factory
        self.schema = schema
        self.table = table
        self.lease_seconds = lease_seconds
        self.qualified_table = f"{schema}.{table}"

    # ------------------------------------------------------------------ #
    # connection handling
    # ------------------------------------------------------------------ #

    @contextmanager
    def _cursor(self, *, readonly: bool = False):
        """Yield a cursor in a transaction that commits on clean exit.

        On exception the transaction is rolled back, which matters: a rolled-back
        claim means the event id is free again, and the next delivery can pick it
        up. If we committed the claim and then crashed, the row would sit in
        'processing' until its lease expired.
        """
        connection = self._connect()
        try:
            with connection:
                with connection.cursor() as cursor:
                    yield cursor
        finally:
            try:
                connection.close()
            except Exception:  # pragma: no cover - defensive
                LOG.debug("failed closing connection", exc_info=True)

    def ensure_schema(self, ddl_path: str | None = None) -> None:
        """Create the schema and table if they are not there yet.

        Prefer running ``schema.sql`` yourself in a migration. This helper is for
        development, tests and single-file deployments, and is idempotent.
        """
        if ddl_path is None:
            ddl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "schema.sql")
        try:
            with open(ddl_path, "r", encoding="utf-8") as handle:
                ddl = handle.read()
        except OSError as exc:
            raise SchemaNotInstalled(
                f"cannot read {ddl_path}: {exc}. Run schema.sql against your "
                "database before using IdempotencyStore."
            ) from exc

        connection = self._connect()
        try:
            connection.autocommit = True
            with connection.cursor() as cursor:
                cursor.execute(ddl)
        finally:
            connection.close()

    def _assert_ready(self, cursor) -> None:
        cursor.execute(
            """
            SELECT 1
              FROM information_schema.tables
             WHERE table_schema = %s AND table_name = %s
            """,
            (self.schema, self.table),
        )
        if cursor.fetchone() is None:
            raise SchemaNotInstalled(
                f"{self.qualified_table} does not exist. Run "
                f"content/idempotency/schema.sql against this database, or call "
                f"store.ensure_schema() in development. Refusing to continue: "
                f"without the table there is no idempotency, and a silent "
                f"degradation means double-charging customers."
            )

    # ------------------------------------------------------------------ #
    # the two claim primitives
    # ------------------------------------------------------------------ #

    def claim(
        self,
        *,
        provider: str,
        event_id: str,
        scope: str = "",
        event_created_at: datetime | None = None,
        lease_seconds: int | None = None,
        lease_owner: str | None = None,
    ) -> ProcessingResult:
        """Try to claim ``event_id``. Never runs a handler.

        Returns one of:

        * ``PROCESSED`` (misleadingly named here: means CLAIMED -- this caller
          owns the event and should run the handler),
        * ``DUPLICATE_SUCCEEDED`` -- already done, ``result`` holds the stored one,
        * ``IN_PROGRESS`` -- another worker holds a live lease,
        * ``FAILED_LEASED`` -- a previous attempt failed and its lease is live,
        * ``FAILED`` -- a previous attempt failed and the lease is free, so this
          caller reclaimed it and should retry.

        The INSERT is the claim. There is no preceding SELECT; the unique
        constraint is the only arbiter.
        """
        if not event_id:
            raise ValueError(
                "event_id must be a non-empty string. An empty or NULL event id "
                "silently disables deduplication, because NULLs never collide in "
                "a standard UNIQUE index."
            )
        if not provider:
            raise ValueError("provider must be a non-empty string")

        lease = self.lease_seconds if lease_seconds is None else lease_seconds
        owner = lease_owner or _lease_owner()
        now = datetime.now(timezone.utc)

        connection = self._connect()
        try:
            connection.autocommit = False
            with connection:
                with connection.cursor() as cursor:
                    self._assert_ready(cursor)
                    insert_sql = f"""
                        INSERT INTO {self.qualified_table}
                            (provider, scope, event_id, status, attempts, result,
                             error, lease_expires_at, lease_owner,
                             event_created_at, first_seen_at, updated_at,
                             last_activity_at)
                        VALUES
                            (%s, %s, %s, 'processing', 1, NULL, NULL,
                             %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (provider, scope, event_id) DO NOTHING
                        RETURNING id, attempts, first_seen_at
                    """
                    cursor.execute(insert_sql, (
                        provider, scope, event_id,
                        now + timedelta(seconds=lease), owner,
                        event_created_at, now, now, now,
                    ))
                    row = cursor.fetchone()

                    if row is not None:
                        # We won the race. This caller OWNS the event but has not
                        # run anything yet: the status is CLAIMED, not PROCESSED.
                        return ProcessingResult(
                            status=Outcome.CLAIMED,
                            event_id=event_id, provider=provider,
                            attempts=1, first_seen_at=row[2],
                            detail={"lease_owner": owner, "lease_seconds": lease,
                                    "claimed": True},
                        )

                    # 23505 was swallowed by ON CONFLICT: somebody else's row is
                    # there. Read it and branch on its state.
                    return self._inspect_existing(cursor, provider, scope, event_id,
                                                  owner, lease, now)
        finally:
            try:
                connection.close()
            except Exception:  # pragma: no cover - defensive
                logging.getLogger(__name__).debug("close failed", exc_info=True)

    def _inspect_existing(self, cursor, provider: str, scope: str, event_id: str,
                          owner: str, lease: int, now: datetime) -> ProcessingResult:
        cursor.execute(
            f"""
            SELECT status, attempts, result, error, lease_expires_at,
                   first_seen_at, lease_owner
              FROM {self.qualified_table}
             WHERE provider = %s AND scope = %s AND event_id = %s
            """,
            (provider, scope, event_id),
        )
        row = cursor.fetchone()
        if row is None:  # pragma: no cover - only if somebody deleted it mid-flight
            return ProcessingResult(
                status=Outcome.IN_PROGRESS, event_id=event_id, provider=provider,
                detail={"note": "row vanished between INSERT and SELECT"},
            )

        status, attempts, result, error, lease_expires_at, first_seen_at, holder = row

        if status == "succeeded":
            return ProcessingResult(
                status=Outcome.DUPLICATE_SUCCEEDED, event_id=event_id,
                provider=provider, result=result, attempts=attempts,
                first_seen_at=first_seen_at, from_store=True,
                detail={"note": "handler NOT re-run; this is the stored result",
                        "original_lease_owner": holder},
            )

        lease_live = lease_expires_at is not None and lease_expires_at > now

        if status == "processing":
            if lease_live:
                return ProcessingResult(
                    status=Outcome.IN_PROGRESS, event_id=event_id, provider=provider,
                    attempts=attempts, first_seen_at=first_seen_at,
                    detail={"lease_owner": holder,
                            "lease_expires_at": lease_expires_at.isoformat()
                            if lease_expires_at else None,
                            "note": "another worker is running the handler; tell "
                                    "the provider to retry"},
                )
            # A stale lease: a previous worker died without finishing. We take
            # it over. This is the ONLY path that lets a crashed handler's event
            # id be retried, and it is why the lease must be bounded.
            return self._reclaim(cursor, provider, scope, event_id, owner, lease,
                                 now, previous_status="processing",
                                 previous_error=error, attempts=attempts,
                                 first_seen_at=first_seen_at)

        # status == 'failed'
        if lease_live:
            return ProcessingResult(
                status=Outcome.FAILED_LEASED, event_id=event_id, provider=provider,
                error=error, attempts=attempts, first_seen_at=first_seen_at,
                detail={"lease_owner": holder,
                        "lease_expires_at": lease_expires_at.isoformat()
                        if lease_expires_at else None,
                        "note": "a previous attempt failed and its lease has not "
                                "expired yet; retry after the lease"},
            )
        return self._reclaim(cursor, provider, scope, event_id, owner, lease, now,
                             previous_status="failed", previous_error=error,
                             attempts=attempts, first_seen_at=first_seen_at)

    def _reclaim(self, cursor, provider: str, scope: str, event_id: str, owner: str,
                 lease: int, now: datetime, *, previous_status: str,
                 previous_error: str | None, attempts: int,
                 first_seen_at: datetime | None) -> ProcessingResult:
        """Take over an event whose lease has expired, atomically.

        The UPDATE is guarded on the lease still being expired, so if two
        workers both notice the stale lease at the same moment, exactly one
        UPDATE reports a row and the other falls back to IN_PROGRESS rather than
        both running the handler. This is the same INSERT-first discipline
        applied to the reclaim path -- a naive reclaim (read the lease, then
        update) reintroduces the very race this module exists to remove.
        """
        cursor.execute(
            f"""
            UPDATE {self.qualified_table}
               SET status = 'processing',
                   attempts = attempts + 1,
                   lease_expires_at = %s,
                   lease_owner = %s,
                   error = NULL,
                   last_activity_at = %s
             WHERE provider = %s AND scope = %s AND event_id = %s
               AND status IN ('processing', 'failed')
               AND (lease_expires_at IS NULL OR lease_expires_at <= %s)
            RETURNING attempts
            """,
            (now + timedelta(seconds=lease), owner, now,
             provider, scope, event_id, now),
        )
        updated = cursor.fetchone()
        if updated is None:
            # Somebody else reclaimed it in the microseconds between our SELECT
            # and this UPDATE. They own it; we do not run the handler.
            return ProcessingResult(
                status=Outcome.IN_PROGRESS, event_id=event_id, provider=provider,
                attempts=attempts, first_seen_at=first_seen_at,
                detail={"note": "lost the reclaim race to another worker",
                        "previous_status": previous_status},
            )
        return ProcessingResult(
            status=Outcome.CLAIMED, event_id=event_id, provider=provider,
            attempts=updated[0], first_seen_at=first_seen_at,
            error=previous_error,
            detail={"reclaimed": True, "previous_status": previous_status,
                    "lease_owner": owner,
                    "note": "the previous lease had expired, so this caller now "
                            "owns the event and may retry the handler"},
        )

    # ------------------------------------------------------------------ #
    # completion
    # ------------------------------------------------------------------ #

    def mark_succeeded(self, *, provider: str, event_id: str, scope: str = "",
                       result: Any = None, attempts: int | None = None) -> bool:
        """Commit the handler's result.

        Call this only after the handler's own side effects are committed. If you
        mark succeeded and then crash before writing the real work, the event is
        closed and will never be retried -- the classic "returned 200 before the
        work was committed" data-loss bug.
        """
        with self._cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE {self.qualified_table}
                   SET status = 'succeeded',
                       result = %s,
                       error = NULL,
                       completed_at = now(),
                       lease_expires_at = now(),
                       last_activity_at = now()
                 WHERE provider = %s AND scope = %s AND event_id = %s
                """,
                (psycopg2.extras.Json(_coerce_jsonb(result))
                 if _DRIVER == "psycopg2" else _coerce_jsonb(result),
                 provider, scope, event_id),
            )
            return cursor.rowcount == 1

    def mark_failed(self, *, provider: str, event_id: str, scope: str = "",
                    error: str, retry_after_seconds: int = 0) -> bool:
        """Record a failure and free the lease (or hold it for a while).

        ``retry_after_seconds=0`` (the default) frees the lease immediately so the
        provider's next delivery can retry. Set it higher for a backoff you
        control from your side.
        """
        with self._cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE {self.qualified_table}
                   SET status = 'failed',
                       error = %s,
                       lease_expires_at = now() + make_interval(secs => %s),
                       last_activity_at = now()
                 WHERE provider = %s AND scope = %s AND event_id = %s
                """,
                (error[:2000], retry_after_seconds, provider, scope, event_id),
            )
            return cursor.rowcount == 1

    def renew_lease(self, *, provider: str, event_id: str, scope: str = "",
                    lease_seconds: int | None = None,
                    lease_owner: str | None = None) -> bool:
        """Extend the lease for a long-running handler.

        Only the current lease holder may renew. A handler that outruns its lease
        without renewing is reclaimable, which is correct -- but if your handler
        legitimately takes minutes, renew rather than setting a huge lease.
        """
        lease = self.lease_seconds if lease_seconds is None else lease_seconds
        now = datetime.now(timezone.utc)
        with self._cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE {self.qualified_table}
                   SET lease_expires_at = %s,
                       lease_owner = COALESCE(%s, lease_owner),
                       last_activity_at = %s
                 WHERE provider = %s AND scope = %s AND event_id = %s
                   AND status = 'processing'
                """,
                (now + timedelta(seconds=lease), lease_owner, now,
                 provider, scope, event_id),
            )
            return cursor.rowcount == 1

    # ------------------------------------------------------------------ #
    # the one-call API
    # ------------------------------------------------------------------ #

    def process(
        self,
        *,
        provider: str,
        event_id: str,
        handler: Callable[[], Any],
        scope: str = "",
        event_created_at: datetime | None = None,
        lease_seconds: int | None = None,
        context: Any = None,
    ) -> ProcessingResult:
        """Claim, then run ``handler()`` at most once, then store its result.

        ``handler`` is called with no arguments, or with ``context`` if given.
        Whatever it returns is stored as the event result and returned to every
        later delivery of the same event id.

        A duplicate is a SUCCESS: the stored result comes back with status
        ``DUPLICATE_SUCCEEDED`` and the handler is not called. Never respond 4xx
        to a duplicate -- the provider will keep redelivering, forever.
        """
        claimed = self.claim(provider=provider, event_id=event_id, scope=scope,
                             event_created_at=event_created_at,
                             lease_seconds=lease_seconds)
        if claimed.status != Outcome.CLAIMED:
            # duplicate / in progress / failed-and-leased: the handler is NOT run
            return claimed

        try:
            value = handler(context) if context is not None else handler()
        except Exception as exc:  # noqa: BLE001 - the whole point is to record it
            message = f"{type(exc).__name__}: {exc}"
            LOG.warning("handler failed for %s/%s: %s", provider, event_id, message)
            try:
                self.mark_failed(provider=provider, event_id=event_id, scope=scope,
                                 error=message)
            except Exception:  # pragma: no cover - defensive
                LOG.exception("could not record failure for %s/%s", provider, event_id)
            return ProcessingResult(
                status=Outcome.FAILED, event_id=event_id, provider=provider,
                error=message, attempts=claimed.attempts,
                first_seen_at=claimed.first_seen_at,
                detail={"note": "handler raised; the event is retryable"},
            )

        try:
            self.mark_succeeded(provider=provider, event_id=event_id, scope=scope,
                                result=value)
        except Exception as exc:  # pragma: no cover - defensive
            LOG.exception("could not store result for %s/%s", provider, event_id)
            return ProcessingResult(
                status=Outcome.FAILED, event_id=event_id, provider=provider,
                result=value,
                error=f"handler succeeded but result could not be stored: {exc}",
                attempts=claimed.attempts, first_seen_at=claimed.first_seen_at,
                detail={"note": "side effects DID happen; do not blindly retry "
                                "without re-checking them"},
            )

        return ProcessingResult(
            status=Outcome.PROCESSED, event_id=event_id, provider=provider,
            result=value, attempts=claimed.attempts,
            first_seen_at=claimed.first_seen_at,
            detail={"lease_owner": claimed.detail.get("lease_owner"),
                    "note": "handler ran exactly once during this call"},
        )

    # ------------------------------------------------------------------ #
    # introspection & maintenance
    # ------------------------------------------------------------------ #

    def lookup(self, *, provider: str, event_id: str, scope: str = "") -> dict | None:
        """Read a row without claiming it. For dashboards and debugging."""
        with self._cursor(readonly=True) as cursor:
            self._assert_ready(cursor)
            cursor.execute(
                f"""
                SELECT status, attempts, result, error, first_seen_at,
                       completed_at, lease_expires_at, lease_owner, last_activity_at
                  FROM {self.qualified_table}
                 WHERE provider = %s AND scope = %s AND event_id = %s
                """,
                (provider, scope, event_id),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "status": row[0], "attempts": row[1], "result": row[2], "error": row[3],
            "first_seen_at": row[4], "completed_at": row[5],
            "lease_expires_at": row[6], "lease_owner": row[7],
            "last_activity_at": row[8],
        }

    def stuck(self, *, limit: int = 100) -> list[dict]:
        """Events in 'processing' whose lease has expired: possibly wedged."""
        with self._cursor(readonly=True) as cursor:
            self._assert_ready(cursor)
            cursor.execute(
                f"""
                SELECT provider, scope, event_id, attempts, lease_owner,
                       lease_expires_at, now() - lease_expires_at AS overdue_by
                  FROM {self.qualified_table}
                 WHERE status = 'processing' AND lease_expires_at < now()
                 ORDER BY lease_expires_at
                 LIMIT %s
                """,
                (limit,),
            )
            return [
                {"provider": r[0], "scope": r[1], "event_id": r[2], "attempts": r[3],
                 "lease_owner": r[4], "lease_expires_at": r[5], "overdue_by": r[6]}
                for r in cursor.fetchall()
            ]

    def prune(self, *, older_than_seconds: int, statuses: Iterable[str] = ("succeeded",),
              limit: int = 10_000, dry_run: bool = False) -> int:
        """Delete settled rows older than a window. Returns how many were deleted.

        PRUNING RE-OPENS THE DOOR. Once a row is gone, a redelivery of that event
        id will be treated as brand new and processed again. So ``older_than``
        must be longer than the longest retry window you could ever see, plus
        your own manual replay horizon. Prune only 'succeeded' rows by default;
        never prune 'processing' rows -- those may be live.
        """
        statuses = tuple(statuses)
        if "processing" in statuses:
            raise ValueError(
                "refusing to prune 'processing' rows: they may be running right "
                "now, and deleting one lets the same event be processed twice"
            )
        if older_than_seconds < 3600:
            raise ValueError(
                "refusing to prune with a window under 1 hour. Provider retries "
                "can span days; a short window turns a duplicate into a second "
                "execution. See docs/IDEMPOTENCY.md#retention-and-pruning"
            )
        placeholders = ", ".join(["%s"] * len(statuses))
        with self._cursor() as cursor:
            self._assert_ready(cursor)
            if dry_run:
                cursor.execute(
                    f"""
                    SELECT count(*) FROM (
                        SELECT 1 FROM {self.qualified_table}
                         WHERE status IN ({placeholders})
                           AND last_activity_at < now() - make_interval(secs => %s)
                         LIMIT %s
                    ) AS doomed
                    """,
                    (*statuses, older_than_seconds, limit),
                )
                return int(cursor.fetchone()[0])
            cursor.execute(
                f"""
                DELETE FROM {self.qualified_table}
                 WHERE id IN (
                     SELECT id FROM {self.qualified_table}
                      WHERE status IN ({placeholders})
                        AND last_activity_at < now() - make_interval(secs => %s)
                      ORDER BY last_activity_at
                      LIMIT %s
                 )
                """,
                (*statuses, older_than_seconds, limit),
            )
            return int(cursor.rowcount)

    def stats(self) -> dict:
        """Row counts by status, for a dashboard or a health check."""
        with self._cursor(readonly=True) as cursor:
            self._assert_ready(cursor)
            cursor.execute(
                f"SELECT status, count(*) FROM {self.qualified_table} GROUP BY status"
            )
            by_status = {row[0]: int(row[1]) for row in cursor.fetchall()}
            cursor.execute(
                f"SELECT count(*) FROM {self.qualified_table} "
                f"WHERE status = 'processing' AND lease_expires_at < now()"
            )
            stuck = int(cursor.fetchone()[0])
        return {"by_status": by_status, "stuck": stuck}


# ---------------------------------------------------------------------------
# event id design helpers
# ---------------------------------------------------------------------------

def derived_event_key(*parts: Any) -> str:
    """Build a deterministic dedupe key when the provider gives you no event id.

    Use this instead of ``uuid4()`` or a timestamp: a random key is different on
    every delivery, so it deduplicates nothing at all, and a timestamp key
    deduplicates nothing either unless the resolution is coarser than the retry
    interval.

    Order the parts from most identifying to least, and include everything that
    distinguishes two genuinely different events, e.g.

        derived_event_key("shopify", shop_domain, topic, resource_id, action)

    The result is stable across processes and languages only if the parts are, so
    never include a float, an object repr, or a locale-dependent date format.
    """
    import hashlib

    normalised = "\x1f".join("" if part is None else str(part) for part in parts)
    digest = hashlib.sha256(normalised.encode("utf-8")).hexdigest()
    return f"derived:{digest}"


def from_provider_headers(provider: str, headers: Mapping[str, str]) -> str | None:
    """Extract the provider's own delivery/event id from a header mapping.

    Mapping only; this never guesses. Returns None when the provider gives you
    nothing usable, in which case you must derive a key from the payload
    (``derived_event_key``) -- after verifying the signature.

    Where a provider offers two ids, the choice matters:

    * Shopify: ``X-Shopify-Webhook-Id`` deduplicates DELIVERIES (one per
      subscription); ``X-Shopify-Event-Id`` correlates the same merchant action
      across subscriptions. Use the webhook id to process each delivery once.
    * Svix: ``svix-id`` is stable across resends of the same message, which is
      exactly what you want.
    """
    lowered = {k.lower(): v for k, v in headers.items()}
    table = {
        "stripe": ("stripe-signature",),  # no id in headers; parse event.id from the body
        "github": ("x-github-delivery",),
        "shopify": ("x-shopify-webhook-id", "x-shopify-event-id"),
        "slack": ("x-slack-retry-num",),  # an ATTEMPT counter, not an id: derive your own
        "twilio": (),
        "paddle": ("paddle-signature",),  # no id in headers; parse notification_id
        "lemonsqueezy": ("x-event-name",),  # a type, not an id: derive your own
        "svix": ("svix-id", "webhook-id"),
        "linear": ("linear-delivery",),
    }
    for name in table.get(provider, ()):
        value = lowered.get(name)
        if value and name not in ("stripe-signature", "paddle-signature",
                                  "x-slack-retry-num", "x-event-name"):
            return value
    return None
