-- Bump the authorization revision whenever something changes which affects what users may access.
-- Instances cache authorization information keyed by this revision.

CREATE OR REPLACE FUNCTION bump_authz_revision() RETURNS trigger AS
$$
BEGIN
    UPDATE authz_revision SET value = value + 1;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS role_binding_authz_revision ON role_binding;
CREATE TRIGGER role_binding_authz_revision
    AFTER INSERT OR UPDATE OR DELETE
    ON role_binding
    FOR EACH STATEMENT
EXECUTE FUNCTION bump_authz_revision();

DROP TRIGGER IF EXISTS team_member_authz_revision ON team_member;
CREATE TRIGGER team_member_authz_revision
    AFTER INSERT OR UPDATE OR DELETE
    ON team_member
    FOR EACH STATEMENT
EXECUTE FUNCTION bump_authz_revision();

-- not on every update, signing in updates the last login
DROP TRIGGER IF EXISTS principal_user_authz_revision ON principal_user;
CREATE TRIGGER principal_user_authz_revision
    AFTER UPDATE OF state, email OR DELETE
    ON principal_user
    FOR EACH STATEMENT
EXECUTE FUNCTION bump_authz_revision();

-- role bindings apply to descendants, so the shape of the tree matters
DROP TRIGGER IF EXISTS sbom_group_authz_revision ON sbom_group;
CREATE TRIGGER sbom_group_authz_revision
    AFTER INSERT OR UPDATE OF parent OR DELETE
    ON sbom_group
    FOR EACH STATEMENT
EXECUTE FUNCTION bump_authz_revision();
