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
> permissions only.

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
