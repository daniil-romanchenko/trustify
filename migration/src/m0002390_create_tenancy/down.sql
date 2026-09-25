DROP TABLE IF EXISTS audit_event;
DROP TABLE IF EXISTS authz_revision;
DROP INDEX IF EXISTS sbom_group_assignment_group_sbom_idx;
DROP TABLE IF EXISTS role_binding;
DROP TABLE IF EXISTS team_member;
DROP TABLE IF EXISTS team;
DROP TABLE IF EXISTS principal_user;
DROP INDEX IF EXISTS sbom_group_external_id_idx;

ALTER TABLE sbom_group
    DROP COLUMN IF EXISTS external_id,
    DROP COLUMN IF EXISTS kind;
