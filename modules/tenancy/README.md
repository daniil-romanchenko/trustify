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

> [!NOTE]
> Role bindings are stored, but not yet enforced. Access to SBOMs is still granted by the global
> permissions only. API key scopes are enforced.

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

Tokens have the form `tfy_<key id>_<secret>_<checksum>`. The key ID is public, and shown in logs and
the API. Revocations take effect immediately on the same instance, and within 60 seconds on others.
The maximum lifetime of a key is configured using `TRUSTD_API_KEY_MAX_TTL` (default: `365d`).
