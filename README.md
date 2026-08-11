# goauth

Bearer token verification and role based authorization for HTTP APIs.

Authentication happens at a central OIDC identity provider. This module never talks to a login
provider, never stores a session and never sets a cookie: it validates the tokens the browser
presents, and decides what their bearer may do.

## What it provides

-   `RequireRoles` — middleware requiring a valid token whose user holds every listed role.
-   `RequireAnyRole` — middleware requiring one of the listed roles.
-   `RegisterRoutes` — mounts `GET /auth/config` and `GET /auth/session` for the browser UI.
-   A choice of identity provider, `zitadel` or `pocketid`, decided by a deployment setting.
-   An `Authorizer` mapping the role names the provider puts in the token to the application's own.

Setting a provider up is covered in `SETUP.md`.

## Installation

```sh
go get github.com/amauryval/goauth
```

```go
import (
    "github.com/amauryval/goauth"
    "github.com/amauryval/goauth/types"
)
```

## Usage

A deployment builds its `Auth` from a `Settings`, which records what the host declares and exposes
each setting through its own method. Undeclared role names fall back to `admin` and `guest`, the
names `SETUP.md` has you create at the provider.

Reading the settings from flags or from the environment is the host's business: this module only
names the variables a host is expected to read, through `DemoEnv`, `ProviderEnv`, `IssuerEnv`,
`AudienceEnv`, `AdminRoleEnv` and `GuestRoleEnv`.

```go
authApp, err := goauth.New(
    ctx,
    goauth.NewSettings(false, "pocketid", "https://auth.example.com", "portfolio", "portfolio_admin", "portfolio_viewer"),
    slog.Default(),
)

authApp.RegisterRoutes(router)

router.Group(func(r chi.Router) {
    r.Use(authApp.RequireRoles(types.RoleAdmin))
    r.Post("/skills", handler.Add)
})
```

It contacts the issuer once to discover its public keys, then caches and rotates them. It fails when
the provider is unreachable. `goauth.NewWithVerifier` is the same thing one level down, for a host
injecting its own `TokenVerifier` rather than mapping two role names.

### Local development

`Demo` authorizes every visitor as admin without contacting any provider, and says so loudly in the
logs. It must never be enabled in production, and two things stand between it and one.

It is left out of the binary unless it is built with the `authdemo` tag, named by `DemoBuildTag`, so
a misread environment variable cannot disable token verification on a deployment that was never
built for it. And it refuses to start beside a declared provider, issuer or audience, rather than
silently ignoring them.

```go
authApp, err := goauth.New(ctx, goauth.NewSettings(true, "", "", "", "", ""), slog.Default())
```

```bash
AUTH_PROVIDER= AUTH_ISSUER= AUTH_AUDIENCE= go run -tags authdemo ./app -auth-demo
```

## Audience isolation

Every application sharing an issuer declares its own `Audience`, checked against the token `aud`
claim. A token minted for one application is rejected by the others.

Providers disagree on what they put in `aud`, and on whether an access token is a JWT at all.
Zitadel uses the client Id, but only once the application is set to issue JWTs rather than opaque
tokens. Keycloak carries `account` unless the client is given an audience mapper. Expect to settle
this on the provider side rather than here — see `SETUP.md`.

## What is verified, and what is left to the host

A token is accepted once its signature matches a key of the issuer's published set, its `iss` is
that issuer, its `aud` this application, and `exp` and `nbf` place it in the present. The signature
algorithms are pinned to the asymmetric ones, so an issuer announcing a symmetric algorithm in its
discovery document is not taken at its word.

Two shapes are refused beyond that. A token without a `sub` is rejected, since the `(Provider, ID)`
pair below would otherwise be a key several users share. And an **ID token presented as an access
token** is rejected — recognised by the `nonce`, `at_hash` or `c_hash` an access token never
carries. An ID token is minted for the browser and states who signed in, never what its bearer may
call.

Three things the module deliberately does not do:

-   **Revocation.** A token stays valid until it expires, so a user removed at the provider keeps
    their access for the rest of that lifetime. The access token lifetime _is_ the revocation delay:
    keep it short at the provider, and rely on refresh for the session length.
-   **Rate limiting.** A rejected token costs a signature verification and a log line, both driven
    by an unauthenticated caller. Put a rate limiter in front of the API, as any public endpoint
    deserves.
-   **Anything about the browser's token storage.** An SPA keeping a refresh token in `localStorage`
    hands a long-lived credential to any XSS; `sessionStorage`, or no `offline_access` scope at all,
    narrows that window. This module never sees those tokens and cannot enforce the choice.

## What the token carries

The browser presents an **access token**, and an access token carries no profile claim: no name, no
email, no avatar. Those live in the ID token, which belongs to the browser and never reaches this
module. `UserInfo` therefore holds `Provider` (the issuer), `ID` (the subject) and `Roles`, and
nothing else. A UI needing a name or an avatar reads them from its own ID token.

Store the `(Provider, ID)` pair as an external identity beside your own user Id, never as the user
Id itself: the pair identifies the user only within that issuer, so changing provider would turn
into a data migration. To find a subject, sign in once and read `user.ID` from `GET /auth/session`,
which reports it for any valid token, authorized or not.

## Authorization

Roles are decided here, not by the provider: the token says who the user is, this module says what
the application lets them do.

A provider that manages roles itself — Zitadel project roles — puts them in the token, and
`FromToken` honours them. Roles then move in the provider's console, with no redeploy.

`NewSettings` builds that authorizer from the two role names, and a host needing another policy
passes its own verifier to `NewWithVerifier`.

No standard names the claim carrying them, so the claim to read comes from the provider a deployment
declares in `AUTH_PROVIDER`. It is the only setting that has no default: guessing it would have the
module read the roles from a claim nobody fills, denying everyone at once. An unknown name is
refused at startup, with the supported ones listed.

| `AUTH_PROVIDER` | Roles claim                         | Scopes the browser requests                  |
| --------------- | ----------------------------------- | -------------------------------------------- |
| `zitadel`       | `urn:zitadel:iam:org:project:roles` | `openid profile email offline_access`        |
| `pocketid`      | `groups`                            | `openid profile email offline_access groups` |

Nothing else is read, and a token holding no roles claim is logged as a warning. The claim's value
may be an array of names, or an object keyed by name as Zitadel emits; both are read.

The scopes are served to the browser by `GET /auth/config` beside the issuer and the client Id, so a
provider demanding its own scope — Pocket ID only emits `groups` when it is asked for — needs no
frontend change. Supporting one more provider is a `Provider` value in the `provider` package.

`FromToken` only grants the roles the application declares, so a provider granting `superadmin` to
someone widens nothing here. A user carrying none of them is not authorized, and reaches only the
public routes.

It matches a provider role by its name, which requires the provider to name its roles after the
application. Where it names them otherwise, `FromTokenNames` maps them, so the provider's vocabulary
stays a deployment setting rather than a value the application knows:

```go
authorization.FromTokenNames(map[string]types.Role{
    "portfolio_admin":  types.RoleAdmin,
    "portfolio_viewer": types.RoleGuest,
})
```

A token carrying roles that none of them matches is logged as a warning, because the user is then
denied by a naming mismatch rather than by a decision.

A misconfiguration — roles not asserted, wrong claim name — strips everyone of every role at once.
That is recoverable in the provider console, which has its own credentials, so it does not warrant a
configured admin beside it: two sources of truth for the same role means a revocation in the console
silently does nothing.

`Authorizer` is an interface, so an application keeping its roles in its own storage implements it
and looks the `(Provider, ID)` pair up. Such a lookup returns `types.ErrAuthorization` on failure,
answered with a `503`, so a store outage reads as a service problem rather than as a rejected token.

## Roles

Roles are plain strings; define your own. `types.RoleAdmin` (`"admin"`) and `types.RoleGuest`
(`"guest"`, read-only) are provided as the conventional ones.

`RequireRoles` requires **every** listed role, `RequireAnyRole` at least one. Missing or invalid
token → `401`; valid token whose user is unauthorized or lacks a role → `403`. Called with no role,
both let any authorized user through.

Use `RequireAnyRole` for a privilege several roles reach, rather than granting every role to the
same user:

```go
r.Use(authApp.RequireAnyRole(types.RoleAdmin, types.RoleGuest)) // reading the administration
r.Use(authApp.RequireRoles(types.RoleAdmin))                    // changing the data
```
