DROP TRIGGER IF EXISTS api_key_scope_revoke_unscoped ON api_key_scope;
DROP FUNCTION IF EXISTS api_key_revoke_unscoped();
DROP TABLE IF EXISTS api_key_scope;
DROP TABLE IF EXISTS api_key;
