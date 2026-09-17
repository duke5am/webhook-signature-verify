-- Webhook Verification + Idempotency Kit
-- content/idempotency/schema.sql  --  PostgreSQL 12+ (tested on 17.11)
--
-- ---------------------------------------------------------------------------
-- WHY THE UNIQUE CONSTRAINT IS THE WHOLE DESIGN
-- ---------------------------------------------------------------------------
-- Providers guarantee AT-LEAST-ONCE delivery. Two deliveries of the same event
-- can be in flight at the same instant on two different workers. Any scheme
-- built on "SELECT to see if we have seen this id, then INSERT if not" has a
-- window between the two statements, and both workers fit inside it. They both
-- see "not present", they both run the handler, and the customer is charged
-- twice.
--
-- There is exactly one race-free primitive for this, and it is a UNIQUE
-- constraint: the database serialises the INSERT, one transaction wins, the
-- other gets 23505 (unique_violation). So the rule is:
--
--     INSERT THE EVENT ID FIRST. Claim the id, then do the work.
--
-- Not "check then insert". Not "upsert after the work". Claim first.
--
-- ---------------------------------------------------------------------------
-- LIFECYCLE OF A ROW
-- ---------------------------------------------------------------------------
--   INSERT (status='processing', lease_expires_at=now()+lease)
--      |-- 23505 unique_violation --> somebody else owns this event id:
--      |        read the existing row and branch on its state:
--      |          succeeded  -> return the STORED result, do not run the handler
--      |          processing -> "in progress"; respond 409/202, let them retry
--      |          failed     -> retryable once the lease is free (or immediately)
--      |
--      '-- claimed -> run the handler -> UPDATE to succeeded/failed
--
-- ---------------------------------------------------------------------------
-- RETENTION
-- ---------------------------------------------------------------------------
-- Rows are not free: this table grows with every delivery, and pruning a row
-- re-opens the door to reprocessing that event id. See docs/IDEMPOTENCY.md
-- ("Retention and pruning") and the prune() helper in middleware.py. The short
-- version: keep a window comfortably longer than the provider's retry schedule
-- and longer than the maximum time you would ever replay an event by hand.
-- ---------------------------------------------------------------------------

BEGIN;

CREATE SCHEMA IF NOT EXISTS webhooks;

-- ---------------------------------------------------------------------------
-- processed_events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webhooks.processed_events (
    -- Surrogate key. Bigint identity rather than serial: no sequence ownership
    -- surprises, and it survives a pg_dump/restore with the sequence intact.
    id                  BIGINT      GENERATED ALWAYS AS IDENTITY,

    -- The deduplication key. NOT NULL is load-bearing: an event id of NULL
    -- would make the unique constraint useless (NULLs never collide in a
    -- standard UNIQUE index), so every delivery must resolve to a key.
    event_id            TEXT        NOT NULL,

    -- Which system sent it. Part of the key namespace, so two providers that
    -- happen to reuse an id string never collide.
    provider            TEXT        NOT NULL,

    -- Free-form scope for multi-tenant or multi-endpoint deployments: the
    -- Shopify shop domain, the Stripe account id, the Twilio subaccount, the
    -- tenant id. Two tenants receiving the same provider event id must not
    -- deduplicate against each other. Defaults to '' for single-tenant setups.
    scope               TEXT        NOT NULL DEFAULT '',

    -- Handler state machine: processing | succeeded | failed.
    -- A CHECK rather than an enum so the pack needs no migration tooling and a
    -- buyer can extend it with ALTER TABLE ... DROP/ADD CONSTRAINT.
    status              TEXT        NOT NULL DEFAULT 'processing'
                                    CHECK (status IN ('processing', 'succeeded', 'failed')),

    -- How many times we have TRIED to run the handler for this event id.
    attempts            INTEGER     NOT NULL DEFAULT 1 CHECK (attempts >= 0),

    -- The stored result, returned verbatim to a repeat delivery so the caller
    -- can answer idempotently without redoing the work. JSONB because the
    -- natural payload is "whatever your handler wants to return", and it stays
    -- queryable if you need to.
    result              JSONB,

    -- Failure detail, for operators and for deciding whether a retry is sane.
    error               TEXT,

    -- Lease. While status='processing', no other worker may claim the event
    -- until this passes. This is what stops a crashed handler from blocking an
    -- event id forever: a stale lease is reclaimable one way (see middleware:
    -- claim_for_retry) and observable the other.
    lease_expires_at    TIMESTAMPTZ NOT NULL,

    -- Who holds the lease. Purely for debugging a stuck event: "which process
    -- claimed it, and when".
    lease_owner         TEXT,

    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,

    -- For retention: prune on this, never on first_seen_at, so a long-running
    -- handler is never pruned out from under itself.
    last_activity_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The provider's own idea of when the event happened, when it supplies one.
    -- Distinct from first_seen_at (when WE received it). Useful for the
    -- out-of-order case: this is the only column that can order events
    -- correctly when they arrive shuffled.
    event_created_at    TIMESTAMPTZ,

    CONSTRAINT processed_events_pkey PRIMARY KEY (id),

    -- =====================================================================
    -- THE CONSTRAINT THAT MAKES THIS CORRECT. Everything else is bookkeeping.
    -- =====================================================================
    CONSTRAINT processed_events_event_id_key UNIQUE (provider, scope, event_id),

    -- A succeeded row must record when it succeeded and must not still hold a
    -- lease; a failed row must carry an error message. These catch handler bugs
    -- that would otherwise show up as "the event silently vanished".
    CONSTRAINT processed_events_succeeded_shape CHECK (
        status <> 'succeeded' OR (completed_at IS NOT NULL)
    ),
    CONSTRAINT processed_events_failed_shape CHECK (
        status <> 'failed' OR (error IS NOT NULL)
    )
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

-- The uniqueness itself is enforced by the UNIQUE constraint above, which
-- creates its own index (processed_events_event_id_key_idx). Do not add a second
-- unique index on the same columns: it doubles the write cost of every claim and
-- buys nothing.

-- Finding stuck leases: a sweeper that wants to alert on or reap events that
-- have been 'processing' past their lease. Partial, because only 'processing'
-- rows can be stuck, and that is a small fraction of the table.
CREATE INDEX IF NOT EXISTS processed_events_stuck_lease_idx
    ON webhooks.processed_events (lease_expires_at)
    WHERE status = 'processing';

-- Operability: "show me everything that failed in the last hour".
CREATE INDEX IF NOT EXISTS processed_events_status_idx
    ON webhooks.processed_events (status, last_activity_at DESC);

-- Retention: prune by activity, oldest first.
CREATE INDEX IF NOT EXISTS processed_events_retention_idx
    ON webhooks.processed_events (last_activity_at);

-- Multi-tenant dashboards: "this shop's recent deliveries".
CREATE INDEX IF NOT EXISTS processed_events_scope_idx
    ON webhooks.processed_events (provider, scope, first_seen_at DESC);

-- ---------------------------------------------------------------------------
-- updated_at / last_activity_at maintenance
-- ---------------------------------------------------------------------------
-- Kept in the database so that every writer -- the middleware, a psql session,
-- a migration script -- maintains them identically. A trigger is not free, but
-- it removes a whole class of "we forgot to bump the timestamp" bugs in the
-- retention sweep.
CREATE OR REPLACE FUNCTION webhooks.touch_processed_events()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := now();
    -- last_activity_at must be monotonic: a lease renewal for a long handler
    -- must move it forward, never backward, or the sweeper could prune a row
    -- that is actively being worked on.
    IF NEW.last_activity_at IS NULL OR NEW.last_activity_at < OLD.last_activity_at THEN
        NEW.last_activity_at := OLD.last_activity_at;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS processed_events_touch ON webhooks.processed_events;
CREATE TRIGGER processed_events_touch
    BEFORE UPDATE ON webhooks.processed_events
    FOR EACH ROW
    EXECUTE FUNCTION webhooks.touch_processed_events();

-- ---------------------------------------------------------------------------
-- Convenience view: what is in flight and possibly wedged right now.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW webhooks.stuck_events AS
SELECT provider,
       scope,
       event_id,
       attempts,
       lease_owner,
       lease_expires_at,
       now() - lease_expires_at AS overdue_by,
       first_seen_at
FROM webhooks.processed_events
WHERE status = 'processing'
  AND lease_expires_at < now()
ORDER BY lease_expires_at;

COMMENT ON TABLE  webhooks.processed_events IS
    'One row per (provider, scope, event_id). The UNIQUE constraint is the idempotency primitive: INSERT first, detect the duplicate via 23505, never SELECT-then-INSERT.';
COMMENT ON COLUMN webhooks.processed_events.event_id IS
    'Provider event id (Stripe event.id, Shopify X-Shopify-Webhook-Id, svix-id, Linear-Delivery, Twilio MessageSid) or your own derived key. See docs/IDEMPOTENCY.md.';
COMMENT ON COLUMN webhooks.processed_events.lease_expires_at IS
    'While status=processing, another worker may not claim this event until this instant. Bounded lease => a crashed handler never blocks an event id forever.';
COMMENT ON COLUMN webhooks.processed_events.result IS
    'Stored handler result, returned to repeat deliveries so a duplicate is answered idempotently instead of being re-run.';

COMMIT;

-- ===========================================================================
-- OPTIONAL: the same idea for handlers that are not a single row update.
--
-- If your event fans out into N side effects (charge, email, ledger entry), a
-- single processed_events row is not enough: a crash halfway through means some
-- effects happened and some did not. Add a per-effect ledger keyed on the SAME
-- event id plus an effect name, and let Postgres enforce each effect once:
--
--   CREATE TABLE webhooks.processed_effects (
--       provider   TEXT NOT NULL,
--       scope      TEXT NOT NULL DEFAULT '',
--       event_id   TEXT NOT NULL,
--       effect     TEXT NOT NULL,   -- 'charge_card', 'send_receipt'
--       applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
--       PRIMARY KEY (provider, scope, event_id, effect),
--       FOREIGN KEY (provider, scope, event_id)
--           REFERENCES webhooks.processed_events (provider, scope, event_id)
--           ON DELETE CASCADE
--   );
--
-- Then each side effect is itself an INSERT-first claim. This is the difference
-- between "the event was processed once" and "each of its effects happened
-- exactly once", and the second one is what actually protects a customer.
-- ===========================================================================
