[![Java CI with Maven](https://github.com/nicolabeghin/keycloak-password-reset-role-provider/actions/workflows/maven.yml/badge.svg)](https://github.com/nicolabeghin/keycloak-password-reset-role-provider/actions/workflows/maven.yml)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/nicolabeghin/keycloak-password-reset-role-provider?sort=semver)](https://github.com/nicolabeghin/keycloak-password-reset-role-provider/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

# keycloak-password-reset-role-provider

A Keycloak realm resource provider that exposes **exactly one** operation — send a user a
password-reset email — authorized by **a single custom realm role** instead of
`realm-management:manage-users`.

## Why this exists

To make Keycloak send a `UPDATE_PASSWORD` action email you normally call:

```
PUT /admin/realms/{realm}/users/{id}/execute-actions-email
```

That endpoint requires `realm-management:manage-users`. There is no narrower built-in role, and
`manage-users` also grants the ability to:

- set an arbitrary password for any user (`reset-password`)
- rewrite any user's email address or username
- disable or delete any user
- enumerate every user in the realm

So an application that only needs to say *"email this person a password-reset link"* has to be
handed a credential that can take over every account in the realm. Change a user's email, then
trigger a reset, and you own the account. Where Keycloak federates users **read-write** from a
legacy database, those writes reach that database too.

Fine-grained admin permissions v2 added a `reset-password` scope in Keycloak 26.4, but it governs
`PUT /users/{id}/reset-password` — setting a password directly — and **not**
`execute-actions-email`, which still requires `manage`. See
[keycloak/keycloak#51411](https://github.com/keycloak/keycloak/issues/51411), open at the time of
writing, where a maintainer notes *"there are no specific permissions to allow sending emails to
execute required actions."*

This provider closes that gap.

## What a holder of the credential can do

**Everything it can do:** cause Keycloak to email a `UPDATE_PASSWORD` link to a named user of one
realm.

**What it cannot do:** set a password, read or change any user attribute, change an email address,
enable/disable/delete a user, list or enumerate users, or touch any other realm. It holds no
`realm-management` role, so the entire Admin REST API returns `403` for it.

Cross-realm access is impossible by construction: the resource lives under `/realms/{realm}/` and
the bearer token is validated against the realm in the URL, so a token minted by realm A cannot be
replayed against realm B.

The residual risk is honest and small: the credential can mail a reset link to any user of its
realm. The link goes to that user's own mailbox, so exploiting it also requires control of the
mailbox — at which point the built-in "forgot password" flow would have served just as well.

## Compatibility

Versions of this provider are coupled to Keycloak versions, because it builds on Keycloak internals.
Use the release matching your server.

| Keycloak | Plugin release | Notes |
|----------|----------------|-------|
| 26.8.x | `26.8.2` | |

## Install

1. Download or build `password-reset-role-provider.jar` (see [Build](#build)).
2. Copy it into `<keycloak>/providers/`.
3. Restart Keycloak (the Quarkus distribution re-augments on boot). For an optimized image, the
   standard flow applies: copy into `providers/`, run `kc.sh build`, then `kc.sh start --optimized`.

Then, **per realm**:

1. Create a realm role — `trigger-password-reset` by default.
2. Create a confidential client with service accounts enabled and every flow disabled
   (no standard flow, no direct access grants, no implicit, no device, no CIBA),
   `fullScopeAllowed=false`, and empty redirect URIs / web origins.
3. Assign the service account **only** that realm role. Give it no `realm-management` roles.

If the role does not exist in a realm, every request to that realm is refused with `403` — the
provider fails closed rather than open.

## Configuration

Set via the `realm-restapi-extension` SPI, so either on the command line or in `keycloak.conf`:

```
--spi-realm-restapi-extension-password-reset-role=trigger-password-reset
--spi-realm-restapi-extension-password-reset-max-lifespan-seconds=3600
```

(Keycloak lower-cases and dash-cases SPI option keys, so the `maxLifespanSeconds` scope key is
written `max-lifespan-seconds` on the command line.)

| Key | Default | Meaning |
|---|---|---|
| `role` | `trigger-password-reset` | Realm role a caller must hold. Never a `realm-management` role. |
| `maxLifespanSeconds` | `3600` | Ceiling for the action-token lifetime, and the value used when the caller omits `lifespan`. |

The cap matters: without it the default would be the realm's `actionTokenGeneratedByAdminLifespan`,
which is **12 hours** out of the box. A reset email is a one-click credential sitting in a mailbox,
so the shorter the better.

## API

```http
POST /realms/{realm}/password-reset
Authorization: Bearer <client_credentials access token from this realm>
Content-Type: application/json

{"username": "mario.rossi"}
```

Optional query parameters, relayed to Keycloak with the same meaning as on the admin endpoint:

| Parameter | Type | Meaning |
|---|---|---|
| `lifespan` | integer | Seconds until the generated token expires. Capped at `maxLifespanSeconds`. |
| `client_id` | string | Client the "back to the application" link belongs to. |
| `redirect_uri` | string | Where to return after the password is changed. Requires `client_id`, and must be valid for it. |

Responses:

| Status | When |
|---|---|
| `204` | The email was sent **or** the user does not exist, is disabled, or has no email address |
| `400` | Missing `username`; invalid `lifespan`; `redirect_uri` without `client_id`; unknown or disabled `client_id`; `redirect_uri` not permitted for that client |
| `401` | Missing, expired, or wrong-realm bearer token |
| `403` | Caller lacks the role, or the role does not exist in the realm |
| `500` | `UPDATE_PASSWORD` is not an enabled required action in the realm, or the mail transport failed |

### Two deliberate design choices

**The action list is not a parameter.** It is the hardcoded constant `["UPDATE_PASSWORD"]`. If
callers could choose actions they could ask for `UPDATE_EMAIL`, `delete_credential` or
`CONFIGURE_TOTP`, and the credential would be as dangerous as `manage-users` again. An `actions`
field in the request body is silently ignored.

**`204` does not mean "sent".** Unknown, disabled and email-less users all return `204`, identical
to success, so the endpoint cannot be used to test whether a username exists. The real outcome is in
the server log and in a realm event (`SEND_RESET_PASSWORD`, with the calling client recorded).
If you surface this in a UI, word it as *"if that username exists, an email has been sent"*.

### Example

```bash
TOKEN=$(curl -s -X POST \
  "https://kc.example.org/realms/myrealm/protocol/openid-connect/token" \
  -d grant_type=client_credentials \
  -d client_id=password-reset-caller \
  -d client_secret=... | jq -r .access_token)

curl -i -X POST "https://kc.example.org/realms/myrealm/password-reset?lifespan=900" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"mario.rossi"}'
```

## Build

```bash
mvn -B clean package
```

Produces `target/password-reset-role-provider.jar`. Requires JDK 17.

> **If you fork this, do not delete or "tidy" `src/main/resources/META-INF/beans.xml`.** Its mere
> presence is what makes Keycloak's Quarkus build scan this archive for JAX-RS annotations. Without
> it the SPI factory still loads and logs normally, but the endpoint answers `405` with
> `Allow: HEAD, OPTIONS` because the resource is registered with no methods. It has to contain
> exactly `<beans/>` — adding comments to it, or `bean-discovery-mode="none"`, breaks it again.
> The full measurement matrix is in [`CLAUDE.md`](CLAUDE.md).

## Local testing

```bash
mvn -B clean package && docker compose up -d --force-recreate && ./verify.sh
```

That starts Keycloak with the built jar mounted into `providers/`, plus
[Mailpit](https://mailpit.axllent.org/) to catch the outgoing mail:

- Keycloak: <http://localhost:18080> (admin / admin)
- Mailpit: <http://localhost:18025>

`verify.sh` then runs 33 assertions against two disposable realms that have **no user federation**.
It covers the negatives as much as the happy path: wrong-realm token, missing and deleted role,
non-disclosure of user state, the lifespan clamp, and — by base64-decoding the action token out of
the captured email — that the action really is `UPDATE_PASSWORD` no matter what the caller asked
for.

Use `--force-recreate`: a single-file bind mount binds an inode and `mvn package` writes a new file,
so a plain restart can leave the old jar in place.

**Never point this at a realm whose users are federated from a real database.** A successful call
emails a real person a working link, and following it writes their real password.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).
