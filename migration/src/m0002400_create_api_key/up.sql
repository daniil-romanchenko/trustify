-- API keys, owned by SBOM groups, allowing to upload SBOMs into them.

CREATE TABLE IF NOT EXISTS api_key
(
    id            UUID        NOT NULL PRIMARY KEY,
    -- the public part of the key, used for looking it up
    key_id        TEXT        NOT NULL,
    -- HMAC-SHA256 of the secret part, using a server side pepper
    secret_hmac   BYTEA       NOT NULL,
    name          TEXT        NOT NULL,
    permissions   TEXT[]      NOT NULL,
    default_group UUID        NULL REFERENCES sbom_group (id) ON DELETE SET NULL,
    labels        JSONB       NOT NULL DEFAULT '{}',
    external_id   TEXT        NULL,
    state         TEXT        NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'revoked')),
    expires_at    TIMESTAMPTZ NOT NULL,
    rotated_from  UUID        NULL REFERENCES api_key (id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT        NOT NULL,
    last_used_at  TIMESTAMPTZ NULL,

    CONSTRAINT api_key_key_id_key UNIQUE (key_id),
    CONSTRAINT api_key_external_id_key UNIQUE (external_id)
);

CREATE TABLE IF NOT EXISTS api_key_scope
(
    api_key_id UUID NOT NULL REFERENCES api_key (id) ON DELETE CASCADE,
    group_id   UUID NOT NULL REFERENCES sbom_group (id) ON DELETE CASCADE,

    PRIMARY KEY (api_key_id, group_id)
);

CREATE INDEX IF NOT EXISTS api_key_scope_group_id_idx ON api_key_scope (group_id);

-- A key without any scope left (all its groups got deleted) must not be usable anymore.
CREATE OR REPLACE FUNCTION api_key_revoke_unscoped() RETURNS trigger AS
$$
BEGIN
    UPDATE api_key
    SET state = 'revoked'
    WHERE id = OLD.api_key_id
      AND state = 'active'
      AND NOT EXISTS (SELECT 1 FROM api_key_scope s WHERE s.api_key_id = OLD.api_key_id);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS api_key_scope_revoke_unscoped ON api_key_scope;
CREATE TRIGGER api_key_scope_revoke_unscoped
    AFTER DELETE
    ON api_key_scope
    FOR EACH ROW
EXECUTE FUNCTION api_key_revoke_unscoped();
