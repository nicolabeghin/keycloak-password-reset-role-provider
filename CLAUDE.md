# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Keycloak `RealmResourceProvider` that adds one route, `POST /realms/{realm}/password-reset`, which
emails a named user a `UPDATE_PASSWORD` action link. It exists so that an application can trigger a
password reset **without** being given `realm-management:manage-users`, which is what the built-in
`PUT /admin/realms/{realm}/users/{id}/execute-actions-email` requires and which also grants setting
arbitrary passwords, rewriting emails and usernames, deleting users and enumerating the realm.

Two invariants carry the whole value of this provider. Do not weaken either:

1. **Authorization is a single custom realm role** (`trigger-password-reset` by default), never a
   `realm-management` role. If the role is missing from a realm, every request to that realm is
   refused — it fails closed.
2. **The action list is the hardcoded constant `ACTIONS` in `PasswordResetResourceProvider`.** It is
   never read from the request. If a caller could choose actions it could ask for `UPDATE_EMAIL` or
   `delete_credential`, and the credential would be as dangerous as `manage-users` again. An
   `actions` field in the request body is deliberately ignored, not rejected.

Cross-realm access is impossible by construction: the resource is mounted under `/realms/{realm}/`
and `AppAuthManager.BearerTokenAuthenticator` resolves the realm from the request context, so a
token minted by realm A cannot be replayed against realm B. `verify.sh` asserts this.

## Build

- `mvn -B clean package` → `target/password-reset-role-provider.jar`. JDK 17.
- CI runs the same thing (`.github/workflows/maven.yml`).
- Keycloak version comes from `<keycloak.version>` in `pom.xml`, and the project `<version>` is kept
  equal to it. `/keycloak-bump-release <version>` updates both plus the README compatibility table,
  builds, commits and tags — the repo follows the spid/cieid convention it expects.

## THE GOTCHA: `src/main/resources/META-INF/beans.xml`

**That file's presence is load-bearing. Deleting it, or adding content to it, silently breaks the
endpoint.** Symptom:

```
POST /realms/{realm}/password-reset  ->  405 Method Not Allowed
OPTIONS /realms/{realm}/password-reset -> Allow: HEAD, OPTIONS
```

The SPI factory still registers (that goes through `META-INF/services` and the `ServiceLoader`, and
the factory's own startup log line still appears), so it looks like the provider loaded fine. What
fails is JAX-RS: Keycloak runs on Quarkus and builds its JAX-RS metadata at augmentation time,
Quarkus only scans archives it treats as part of the application, and the marker it looks for is
`META-INF/beans.xml`. Without it the resource is registered with **zero** resource methods.

Measured on Keycloak 26.8.1, one variable at a time:

| jar contents | `Allow` |
|---|---|
| no marker | `HEAD, OPTIONS` (broken) |
| `META-INF/jandex.idx` only (via `jandex-maven-plugin`) | `HEAD, OPTIONS` (broken) |
| `beans.xml` with `bean-discovery-mode="none"` | `HEAD, OPTIONS` (broken) |
| `beans.xml` containing XML comments + `<beans/>` | `HEAD, OPTIONS` (broken) |
| **`beans.xml` containing exactly `<beans/>`** | **`HEAD, POST, OPTIONS` (works)** |

So: keep the file exactly `<beans/>`. It is not a CDI feature we want — nothing here has a
bean-defining annotation — it is purely the marker that makes the archive visible to the annotation
scan. `bean-discovery-mode="none"` defeats the purpose because Quarkus then honours "do not scan".
Comments in the file also broke it, which was not predicted; do not tidy that file.

Things that are **not** the cause, all ruled out empirically — do not re-litigate them:

- the HTTP method (a trivial no-arg `@GET` was equally invisible)
- an entity-body parameter of a locally-declared type
- the absence of `@Produces`
- the Java package (`com.nicolabeghin.*` and `org.keycloak.*` behave identically)
- the deployment model (`start-dev` + bind-mounted jar and `kc.sh build` + baked jar both work,
  and both fail, depending only on `beans.xml`)
- the archiver (`maven-jar-plugin` vs `jar cf`)
- `META-INF/jboss-deployment-structure.xml`, which cieid ships and Quarkus ignores

## Architecture

`PasswordResetResourceProviderFactory` is the SPI factory. Its `ID` (`password-reset`) **is the URL
segment**, so changing it changes every caller's URL. `init(Config.Scope)` reads `role` and
`maxLifespanSeconds`; Keycloak dash-cases scope keys, so on the command line they are
`--spi-realm-restapi-extension-password-reset-role=...` and
`...-max-lifespan-seconds=...`. The SPI name is `realm-restapi-extension` (from `RealmResourceSPI`),
**not** `realm-restful-extension`.

`PasswordResetResourceProvider` implements `RealmResourceProvider` and returns `this` from
`getResource()`, so the JAX-RS method lives on the provider itself — the same shape as the cieid and
spid providers. Order of operations in `triggerPasswordReset`, each step load-bearing:

1. Bearer authentication, which also pins the realm.
2. Role check against the realm model (`realm.getRole` then `user.hasRole`), failing closed if the
   role does not exist. Deliberately **not** read from the token's `realm_access` claim.
3. Caller-input validation: `lifespan` parsed by hand (so a non-numeric value is a clean `400`
   rather than JAX-RS's `404`), and a check that `UPDATE_PASSWORD` is an enabled required action in
   the realm, since otherwise the emailed link would do nothing.
4. User resolution. **From here on the response is always `204`** — unknown, disabled and
   email-less users are indistinguishable from success, so the endpoint cannot be used as a username
   oracle. The real outcome goes to the log and to a `SEND_RESET_PASSWORD` realm event that records
   the calling client.
5. `UserResource.verifySendEmailParams(...)` — upstream's own `public static` helper — is reused for
   `client_id` / `redirect_uri` / `lifespan` defaulting rather than reimplemented. It must be called
   **after** step 4, because its own first two checks throw `400 "User email missing"` /
   `400 "User is disabled"`, which would leak exactly the user state step 4 is hiding.
6. Token build and send, mirroring `UserResource.executeActionsEmail`. Both
   `Constants.TEMPLATE_ATTR_REQUIRED_ACTIONS` and `Constants.IGNORE_ACCEPT_LANGUAGE_HEADER` must be
   set on the `EmailTemplateProvider` or the mail renders wrongly.

The returned lifespan is clamped to `maxLifespanSeconds` (default 3600). Upstream does not clamp,
and when the caller omits `lifespan` upstream defaults to the realm's
`actionTokenGeneratedByAdminLifespan` — 43200 (12 h) out of the box, i.e. a half-day one-click
credential in a mailbox.

### Version-sensitive upstream API

This provider calls Keycloak internals, so these are the things that break on upgrade. All verified
against the 26.8.1 tag:

- `AuthenticationManager.AuthResult` is a **record** — accessors are `user()`, `client()`, `token()`,
  not `getUser()`. It was a plain class with getters in older versions.
- `UserResource.verifySendEmailParams(KeycloakSession, RealmModel, UserModel, String, String, Integer)`
  is `public static` and returns `UserResource.SendEmailParams`. If it ever stops being public,
  inline its logic from the matching tag rather than approximating it.
- `ExecuteActionsActionToken(String userId, String email, int absoluteExpirationInSecs, List<String>
  requiredActions, String redirectUri, String clientId)`.
- When `client_id` is omitted, upstream resolves `SystemClientUtil.getSystemClient(realm)`, not the
  account console.

On a Keycloak bump, re-read `UserResource.executeActionsEmail` and `verifySendEmailParams` at the new
tag and diff against step 6 above.

## Testing

`verify.sh` is the real test suite: 33 assertions against the throwaway stack in
`docker-compose.yml` (Keycloak on 18080, Mailpit on 18025 — high ports because 8080/8025 are often
taken).

```bash
mvn -B clean package && docker compose up -d --force-recreate && ./verify.sh
```

It creates two disposable realms with **no user federation** and asserts the negatives as much as
the happy path: wrong-realm token, missing role, deleted role, non-disclosure of user state, the
hardcoded action (by base64-decoding the `rqac` claim out of the action token in the captured
email — the subject line is the generic "Update Your Account" template for every action and cannot
distinguish them), and the lifespan clamp.

Two things worth knowing before extending it:

- Keycloak's user profile **rejects** usernames containing characters like `&`
  (`error-username-invalid-character`), so there is no point writing test cases for them.
- A single-file bind mount binds an inode and `mvn package` writes a new file, so use
  `--force-recreate`; restarting the container alone can leave the old jar in place.

**Never point this at a realm whose users are federated from a real database.** A successful call
emails a real person a working link, and following it writes their real password.

## Deploying

Copy the jar into `<keycloak>/providers/` and restart. For an optimized/production image the
standard Keycloak flow applies — copy into `providers/`, run `kc.sh build`, then
`kc.sh start --optimized`. Both work; neither is a substitute for `beans.xml`.

Per realm: create the realm role, create a confidential client with service accounts enabled and
every flow disabled, and assign that client's service account **only** the custom role — no
`realm-management` roles at all.
