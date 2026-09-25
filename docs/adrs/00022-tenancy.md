# 00022. Tenancy: users, teams, role bindings, and API keys

Date: 2026-09-25

## Status

PROPOSED

## Context

Trustify authorizes requests using global permissions only: a user with `read.sbom` can read every
SBOM. Organizations running Trustify for many teams need to limit what each team sees, and want an
external orchestration platform (which creates repositories, CI pipelines, and infrastructure) to
manage who has access to what. CI pipelines need credentials which can only upload SBOMs, and only
into their own project.

## Decision

### Groups are the unit of ownership

The existing SBOM group tree (ADR 00013) is the tenancy hierarchy, e.g. organization → team →
project. Groups gain an optional `kind` and an `external_id`. Access is granted on a group, and
applies to all its descendants. No second hierarchy is introduced.

### Directory

A new `tenancy` module manages:

* **Users**, identified by their lower-cased e-mail address. Users can be provisioned upfront, and
  are linked to an OIDC identity (issuer and subject) on their first sign-in, when the access token
  carries a verified e-mail address (`email_verified`). Unknown users are created on their first
  sign-in, unless disabled. Disabled users are rejected with `401`.
* **Teams**, sets of users, which can hold roles as a unit.
* **Role bindings**: a role (`viewer`, `uploader`, `editor`, `admin`) for a user or team, on a
  group. Roles are cumulative, and fixed.

Teams, groups, and API keys can be addressed by ID, or by external ID using the key
`ext:<external id>`. `PUT` with an external key creates missing resources, which makes all
management calls idempotent, so that the orchestration platform can reconcile its state.

Management requires the new `manage.tenancy` permission, intended for the orchestration platform's
OIDC client (client credentials grant). It is not part of the default scope mappings.

### API keys

API keys are owned by groups, not users, and can only upload SBOMs into their groups (and their
descendants). Tokens have the form `tfy_<key id>_<secret>_<checksum>`. Only an HMAC-SHA256 of the
secret, using a server side pepper (`TRUSTD_API_KEY_PEPPER`), is stored, and verified in constant
time for every request. Keys expire, can be rotated with a grace period, revoked, and limited to
network ranges. Failed attempts are rate limited per client address.

The authenticator gains a `TokenValidator` hook, so that bearer tokens other than OIDC access tokens
can be validated, without the auth crate depending on the database.

### Scoped authorization

`TRUSTD_AUTHZ_MODE=scoped` enforces role bindings; the default (`global`) keeps the existing
behavior. A middleware computes an `AccessScope` for each request: the permissions per group,
expanded to descendants. Services filter queries with it, in SQL, so pagination and totals are
correct. The global permissions still apply, the scope limits which SBOMs.

* Inaccessible SBOMs are handled as if they didn't exist (`404`, omitted from lists).
* Advisories, vulnerabilities, packages, products, and licenses are shared data, visible to
  everyone. References to inaccessible SBOMs are removed from them.
* Graph queries only start from accessible SBOMs, and are cut where they cross into inaccessible
  ones.
* A test requires every endpoint to be classified (`server/tests/authorization.rs`), so that new
  endpoints can't be added without deciding how they're affected.

Enforcement happens in the service layer, not using PostgreSQL row level security, which would
require per-request session state on pooled connections, and conflicts with read replicas (ADR 00018).

### Consistency across instances

Scopes and user resolutions are cached per instance. Database triggers bump an authorization
revision whenever role bindings, team memberships, user states, or the group hierarchy change.
Cached entries are keyed by the revision, which is itself cached for one second. So changes take
effect on all instances within about a second, without messaging between instances.

### Audit

Every change, and the use of API keys, is written to an audit log, in the same transaction as the
change. It can be read using `/v3/audit`, and is pruned after `TRUSTD_AUDIT_RETENTION`.

## Alternatives considered

### Separate "tenant" hierarchy

A hierarchy separate from SBOM groups would allow organizing tenants independently from SBOMs, but
requires mapping between both, and duplicates the tree. Reusing groups is simpler, at the cost of
deleting a group also removing the access it granted.

### Invalidation by messaging

Instances could notify each other about changes (e.g. `LISTEN/NOTIFY`). The revision counter needs no
additional infrastructure, and bounds staleness to a second.

## Consequences

* Users need both the global permissions (e.g. from IdP scopes) and role bindings to access SBOMs in
  scoped mode.
* Uploads by users with scoped access must name a group, otherwise the SBOM would be inaccessible to
  them.
* An SBOM uploaded by two tenants is deduplicated, and assigned to groups of both.
* API keys only work with authentication enabled.

### Resolved questions

* Identical SBOMs uploaded by different tenants are shared: the SBOM is assigned to groups of both.
* Roles are fixed, custom roles are not required.
* API keys can only upload, reading is not required for now.
* Team memberships are managed by the orchestration platform. Identity providers currently don't
  provide group claims to Trustify, synchronizing from them may be added later.
