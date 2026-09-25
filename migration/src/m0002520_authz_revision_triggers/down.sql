DROP TRIGGER IF EXISTS sbom_group_authz_revision ON sbom_group;
DROP TRIGGER IF EXISTS principal_user_authz_revision ON principal_user;
DROP TRIGGER IF EXISTS team_member_authz_revision ON team_member;
DROP TRIGGER IF EXISTS role_binding_authz_revision ON role_binding;
DROP FUNCTION IF EXISTS bump_authz_revision();
