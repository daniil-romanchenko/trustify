-- Tenancy directory: users, teams, role bindings on SBOM groups, and an audit trail.

ALTER TABLE sbom_group
    ADD COLUMN IF NOT EXISTS kind        TEXT NULL,
    ADD COLUMN IF NOT EXISTS external_id TEXT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS sbom_group_external_id_idx
    ON sbom_group (external_id)
    WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS principal_user
(
    id           UUID        NOT NULL PRIMARY KEY,
    -- stored lower-cased
    email        TEXT        NOT NULL,
    oidc_issuer  TEXT        NULL,
    oidc_sub     TEXT        NULL,
    display_name TEXT        NULL,
    external_id  TEXT        NULL,
    state        TEXT        NOT NULL DEFAULT 'invited'
        CHECK (state IN ('invited', 'active', 'disabled')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login   TIMESTAMPTZ NULL,
    revision     UUID        NOT NULL,

    CONSTRAINT principal_user_email_key UNIQUE (email),
    CONSTRAINT principal_user_external_id_key UNIQUE (external_id),
    CONSTRAINT principal_user_oidc_key UNIQUE (oidc_issuer, oidc_sub)
);

CREATE TABLE IF NOT EXISTS team
(
    id          UUID NOT NULL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NULL,
    external_id TEXT NULL,
    revision    UUID NOT NULL,

    CONSTRAINT team_external_id_key UNIQUE (external_id)
);

CREATE TABLE IF NOT EXISTS team_member
(
    team_id UUID NOT NULL REFERENCES team (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES principal_user (id) ON DELETE CASCADE,

    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX IF NOT EXISTS team_member_user_id_idx ON team_member (user_id);

CREATE TABLE IF NOT EXISTS role_binding
(
    id         UUID        NOT NULL PRIMARY KEY,
    group_id   UUID        NOT NULL REFERENCES sbom_group (id) ON DELETE CASCADE,
    user_id    UUID        NULL REFERENCES principal_user (id) ON DELETE CASCADE,
    team_id    UUID        NULL REFERENCES team (id) ON DELETE CASCADE,
    role       TEXT        NOT NULL
        CHECK (role IN ('viewer', 'uploader', 'editor', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT        NOT NULL,

    CONSTRAINT role_binding_one_principal CHECK (num_nonnulls(user_id, team_id) = 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS role_binding_group_user_idx
    ON role_binding (group_id, user_id)
    WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS role_binding_group_team_idx
    ON role_binding (group_id, team_id)
    WHERE team_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS role_binding_user_id_idx ON role_binding (user_id);
CREATE INDEX IF NOT EXISTS role_binding_team_id_idx ON role_binding (team_id);

-- Reverse lookup for "which SBOMs are in these groups", used by scoped filtering.
CREATE INDEX IF NOT EXISTS sbom_group_assignment_group_sbom_idx
    ON sbom_group_assignment (group_id, sbom_id);

-- A single, monotonically increasing counter. Bumped on every tenancy change, used to invalidate
-- authorization caches across pods.
CREATE TABLE IF NOT EXISTS authz_revision
(
    id    BOOLEAN NOT NULL PRIMARY KEY DEFAULT TRUE CHECK (id),
    value BIGINT  NOT NULL
);

INSERT INTO authz_revision (id, value)
VALUES (TRUE, 0)
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_event
(
    id          BIGSERIAL   NOT NULL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_kind  TEXT        NOT NULL,
    actor_id    TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    target_kind TEXT        NOT NULL,
    target_id   TEXT        NOT NULL,
    detail      JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS audit_event_at_idx ON audit_event (at);
CREATE INDEX IF NOT EXISTS audit_event_target_idx ON audit_event (target_kind, target_id);
