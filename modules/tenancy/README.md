# Tenancy

Manage users, teams, and their roles on SBOM groups. All endpoints require the `manage.tenancy`
permission, which is intended for an external orchestration platform. It is not part of the
default scope mappings, map it explicitly, e.g.:

```json
"scopeMappings": {
  "trustify:manage": ["manage.tenancy"]
}
```

Users are identified by their e-mail address, which is matched case-insensitively. Teams and SBOM
groups can be addressed by their ID, or by an external ID using the key `ext:<external id>`. `PUT`
using an external ID creates the resource if it doesn't exist, so the same calls can be repeated
safely.

Every change is recorded in the `audit_event` table.

Role bindings are only enforced when scoped authorization is enabled (see below). API key scopes
are always enforced.

## Signing in

When an access token carries a verified e-mail address (`email` claim, with `email_verified` being
`true`), the request is linked to a user:

1. A user already linked to the token's issuer and subject.
2. Otherwise, a user with that e-mail address, which is not linked yet. This is how users provisioned
   upfront become active.
3. Otherwise, a new, active user is created, without any role bindings.

Requests of disabled users are rejected with `401`. Linking is cached for 30 seconds per instance,
changes to users made through this API take effect immediately on the same instance.

The calling user, its global permissions, and its roles can be retrieved using:

```bash
http GET localhost:8080/api/v3/me
```

## Groups

```bash
http PUT localhost:8080/api/v3/group/sbom/ext:acme name=ACME kind=organization
http PUT localhost:8080/api/v3/group/sbom/ext:acme.payments name=payments kind=team parent=ext:acme
```

## Users

```bash
http PUT localhost:8080/api/v3/user/alice@acme.com displayName=Alice
http GET localhost:8080/api/v3/user/alice@acme.com/access
http POST localhost:8080/api/v3/user/alice@acme.com/change-email newEmail=alice@acme.org
http DELETE localhost:8080/api/v3/user/alice@acme.org
```

Setting `disabled=true` prevents the user from signing in, while keeping its role bindings.

## Teams

```bash
http PUT localhost:8080/api/v3/team/ext:acme.payments.devs name="Payments developers"
http PUT localhost:8080/api/v3/team/ext:acme.payments.devs/member emails:='["alice@acme.com", "bob@acme.com"]'
http PATCH localhost:8080/api/v3/team/ext:acme.payments.devs/member add:='["carol@acme.com"]' remove:='["bob@acme.com"]'
```

Users which are not known yet are created in state `invited`.

## Role bindings

A role applies to the group it is bound to, and all groups below it. Roles are `viewer`, `uploader`,
`editor`, and `admin`, each including the permissions of the ones before it.

```bash
# replace all bindings of a group
http PUT localhost:8080/api/v3/group/sbom/ext:acme.payments/binding <<EOF
[
  {"principal": {"team": "ext:acme.payments.devs"}, "role": "viewer"},
  {"principal": {"user": "lead@acme.com"}, "role": "admin"}
]
EOF

# a single binding
http PUT localhost:8080/api/v3/group/sbom/ext:acme.payments/binding/user/alice@acme.com role=uploader
http DELETE localhost:8080/api/v3/group/sbom/ext:acme.payments/binding/user/alice@acme.com
```

Replacing bindings accepts an `If-Match` header, using the `ETag` returned by the previous `GET` or
`PUT`.

## API keys

API keys allow machines, like CI pipelines, to upload SBOMs. A key belongs to one or more SBOM
groups, and can only upload into those groups and their descendants. Uploads without a `group`
parameter are assigned to the key's default group, and the key's labels are applied to every
upload. Requests using an API key are rejected for every other endpoint.

API keys are disabled unless a pepper is configured, which is used to derive the stored hashes:

```bash
TRUSTD_API_KEY_PEPPER="$(openssl rand -hex 32)" trustd api …
```

The token is only returned when a key is created or rotated:

```bash
http POST localhost:8080/api/v3/api-key name="checkout CI" groups:='["ext:acme.payments.checkout"]' \
  expiresAt=2027-01-01T00:00:00Z externalId=checkout.ci labels:='{"pipeline": "gitlab"}'

# upload using the key
curl -X POST localhost:8080/api/v3/sbom -H "Authorization: Bearer tfy_…" --data-binary @sbom.json

# rotate: the old key stays valid for the grace period (at most 7 days), the external ID moves to the new key
http POST localhost:8080/api/v3/api-key/ext:checkout.ci/rotate gracePeriod=24h expiresAt=2027-06-01T00:00:00Z

# revoke
http DELETE localhost:8080/api/v3/api-key/ext:checkout.ci
```

Keys can be limited to network ranges, using `allowedCidrs` (e.g. `["10.0.0.0/8"]`) when creating or
patching them. When running behind a proxy, set `TRUSTD_API_KEY_TRUST_FORWARDED_FOR=true` to use
the client address it reports. Only do this if the proxy overwrites the `Forwarded`/`X-Forwarded-For`
headers, as clients can forge them otherwise.

More than 20 failed attempts per minute from one address are rejected with `429`. The first use of a
key each hour, and every rejected attempt for an existing key, are recorded in the audit log.

To rotate the pepper, set the new one as `TRUSTD_API_KEY_PEPPER`, and the old one as
`TRUSTD_API_KEY_PEPPER_PREVIOUS`. Keys are migrated to the new pepper on their next use. Keys which
weren't used by the time the previous pepper is removed stop working.

Tokens have the form `tfy_<key id>_<secret>_<checksum>`. The key ID is public, and shown in logs and
the API. Revocations take effect immediately on the same instance, and within 60 seconds on others.
The maximum lifetime of a key is configured using `TRUSTD_API_KEY_MAX_TTL` (default: `365d`).

## Scoped authorization

By default (`TRUSTD_AUTHZ_MODE=global`), access to SBOMs is granted by the global permissions of the
access token only, and role bindings are not enforced. With `TRUSTD_AUTHZ_MODE=scoped`, a user can
only access SBOMs assigned to groups it holds a role on:

| Role       | Grants, on the group and all its descendants                                   |
|------------|--------------------------------------------------------------------------------|
| `viewer`   | Read SBOMs and groups                                                          |
| `uploader` | `viewer`, and upload SBOMs into the groups                                     |
| `editor`   | `uploader`, and update or delete SBOMs, and change their group assignments      |
| `admin`    | `editor`, and create, update, or delete groups, and manage bindings and API keys |

The global permissions still apply: a user needs e.g. `read.sbom` to read SBOMs at all. The role
bindings limit which SBOMs.

* SBOMs of other groups are handled as if they didn't exist (`404`, or omitted from lists).
* Vulnerabilities, advisories, and packages stay visible to everyone, but references to
  inaccessible SBOMs are removed. Graph queries (`/v3/analysis`) stop at the boundary of accessible
  SBOMs.
* Uploads require a `group` parameter, naming groups the user may upload into.
* Replacing the group assignments of an SBOM keeps assignments to groups outside the user's scope.
* New top-level groups can only be created with unrestricted access.
* The `read.allSboms` and `manage.tenancy` permissions grant unrestricted access, e.g. for platform
  operators.
* Changes to roles, memberships, users, and the group hierarchy take effect within about one
  second on all instances.

### Delegated administration

With scoped authorization, a group `admin` may manage the role bindings and API keys of its groups,
without the `manage.tenancy` permission. Keys can only be listed by passing a `group` it manages.
Users and teams can only be managed with the `manage.tenancy` permission.

## Audit log

Every change, and the use of API keys, is recorded. The log can be read with the `manage.tenancy`
permission, newest events first:

```bash
http GET localhost:8080/api/v3/audit targetKind==user action==delete since==2026-09-01T00:00:00Z
```

Events are kept for `TRUSTD_AUDIT_RETENTION` (default: `400d`).
