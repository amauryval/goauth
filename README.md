# goauth

Bearer token verification and role based authorization for HTTP APIs.

Authentication happens at a central OIDC identity provider, and **the provider has the last word**.
A token is evidence, not a decision: its signature says the issuer minted it, never that the
account still exists, that its password was not changed, or that the session was not ended
elsewhere. So the issuer is asked whether a token is still active, through RFC 7662 introspection,
rather than trusted until an expiry date it handed out at login. Its answer is reused for 15
seconds, so a revocation lands in seconds without the provider sitting in front of every request.
That constraint is what the design answers to — see `ARCHITECTURE.md`.

## What it provides

-   `RequireRoles` — middleware requiring a valid token whose user holds every listed role.
-   `RequireAnyRole` — middleware requiring one of the listed roles.
-   `RegisterRoutes` — mounts the endpoints the browser UI needs.
-   An optional **server driven login**, so the frontend never handles a token at all.
-   A choice of identity provider, `zitadel` or `pocketid`, decided by a deployment setting.
-   An `Authorizer` mapping the role names the provider puts in the token to the application's own.

Setting a provider up is covered in `SETUP.md`, and the browser side in `FRONTEND.md`.

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

## Two ways to sign users in

**Server driven** (`Options.Browser`) — the module runs the whole OIDC flow: it redirects to the
provider, exchanges the code with PKCE, keeps the tokens in a sealed `HttpOnly` cookie and spends
the refresh token when the access token ages out. The frontend never sees a token, so there is
nothing an XSS can steal and no OIDC library to ship:

```js
// The entire frontend.
const session = await (await fetch("/auth/session")).json();
if (!session.logged_in) location.href = "/auth/login?return_to=" + encodeURIComponent(location.pathname);

await fetch("/api/skills", { method: "POST", body }); // the cookie rides along
await fetch("/auth/logout", { method: "POST" });
```

**Browser driven** (the default) — the frontend obtains its own tokens with `oidc-client-ts` or
equivalent and presents them as `Authorization: Bearer`. `GET /auth/config` serves it the issuer,
the client Id and the scopes, so a single build works across every environment.

Server driven is the safer of the two and is what a first-party frontend should use. The bearer
path stays available in both modes, which is what lets a script or a service account call the same
API a browser does.

## Usage

A deployment builds its `Auth` from a `Settings`, which records what the host declares through the
named fields of an `Options`. Undeclared role names fall back to `admin` and `guest`, the names
`SETUP.md` has you create at the provider.

Reading the settings from flags or from the environment is the host's business: this module only
names the variables a host is expected to read, through `DemoEnv`, `ProviderEnv`, `IssuerEnv`,
`AudienceEnv`, `AdminRoleEnv` and `GuestRoleEnv`. `.env.example` spells out the mapping.

```go
authApp, err := goauth.New(ctx, goauth.NewSettings(goauth.Options{
    ProviderName: os.Getenv(goauth.ProviderEnv), // "pocketid"
    IssuerURL:    os.Getenv(goauth.IssuerEnv),   // "https://auth.example.com"
    Audience:     os.Getenv(goauth.AudienceEnv), // "portfolio"
    AdminRole:    os.Getenv(goauth.AdminRoleEnv), // "portfolio_admin", "admin" when empty
    GuestRole:    os.Getenv(goauth.GuestRoleEnv), // "portfolio_viewer", "guest" when empty
}), slog.Default())
if err != nil {
    return fmt.Errorf("auth: %w", err)
}
```

`New` contacts the issuer once to discover its public keys, then caches and rotates them. It fails
when the provider is unreachable, so a misconfigured deployment refuses to start rather than
rejecting every caller once it is up.

Mount the endpoints and guard the routes:

```go
authApp.RegisterRoutes(router) // GET /auth/config and GET /auth/session

router.Group(func(r chi.Router) {
    r.Use(authApp.RequireRoles(types.RoleAdmin))
    r.Post("/skills", handler.Add)
})
```

Inside a guarded handler, the authenticated user comes from the request context:

```go
func (h Handler) Add(w http.ResponseWriter, r *http.Request) {
    user, ok := goauth.UserFrom(r.Context())
    if !ok {
        // Unreachable behind RequireRoles, which never calls the handler without a user.
        http.Error(w, "unauthorized", http.StatusUnauthorized)

        return
    }

    log.Printf("skill added by %s/%s", user.Provider, user.ID)
}
```

`goauth.NewWithVerifier` is the same thing one level down, for a host injecting its own
`TokenVerifier` rather than mapping two role names. The `Auth` it returns knows no provider, so
`GET /auth/config` serves an empty client configuration: such a host tells the browser where to
sign in by its own means.

### Server driven login

Pass an `Options.Browser` and the module signs users in itself:

```go
authApp, err := goauth.New(ctx, goauth.NewSettings(goauth.Options{
    ProviderName: "pocketid",
    IssuerURL:    "https://auth.example.com",
    Audience:     "portfolio",
    Browser: &goauth.BrowserOptions{
        ClientSecret:  os.Getenv("AUTH_CLIENT_SECRET"), // empty for a public client, PKCE alone
        RedirectURL:   "https://app.example.com/auth/callback",
        Secret:        cookieSecret,                    // >= 32 bytes, from your secret store
        PostLoginPath: "/",
        PostLogoutURL: "https://app.example.com/",
    },
}), slog.Default())
```

`RedirectURL` must be registered at the provider and must resolve to `goauth.CallbackPath`. The
`Secret` seals the cookies: losing it signs everyone out, leaking it lets its holder mint sessions,
so it belongs wherever the deployment keeps its other secrets.

Three more endpoints appear. `GET /auth/login` starts the flow, taking an optional `?return_to`
that must be a path on this application — an absolute URL is dropped rather than followed, which is
what keeps the endpoint from being an open redirect. `GET /auth/callback` finishes it. `POST
/auth/logout` drops the session, and hands the browser on to the provider when `PostLogoutURL` is
set. Logout is a `POST` so that a cross-site page cannot sign a visitor out by linking to it.

Every login ends with the ID token being verified against the nonce it was started with, as OpenID
Connect Core 3.1.3.7 requires, which is what ties the session to the person it names. Signing out
hands the refresh token back to the provider where it advertises a revocation endpoint (RFC 7009),
rather than leaving it live.

A request that changes something, carrying the session cookie, must state this application's own
origin, derived from `RedirectURL`. That is the CSRF check, and it costs the frontend nothing: no
token to read, no header to echo. It applies only to cookie-authenticated requests, since a bearer
token is one the caller attached on purpose. A refused request answers `403` with the code
`cross_site`.

A session carries no expiry of its own. How long a sign in stays good is how long the provider
keeps honouring the refresh token, and how quickly it stops is the issuer being asked about the
token. Set the session length at the provider, where it is decided.

The session cookie is `HttpOnly`, `Secure` and `SameSite=Lax`, and holds the tokens sealed with
AES-GCM — the browser can present it but never read it. `SameSite=Lax` is the tightest setting the
flow works under, since the provider returns the browser by a top-level navigation. That leaves
cross-site `GET`: guard your writes as any cookie-authenticated API must. An API accepting only
`application/json` is already beyond the reach of a form post.

### Endpoints

`RegisterRoutes` mounts the handlers on any router exposing `Get` and `Post`, which `chi.Router`
does. The paths are `goauth.ConfigPath`, `SessionPath`, `LoginPath`, `CallbackPath` and
`LogoutPath`, all under `goauth.Root`, and the caller decides the API root they hang from. The
login endpoints are only mounted where the deployment asked for the server driven flow.

`GET /auth/config` — how to sign in. Server driven, the frontend needs nothing else:

```json
{ "server_flow": true, "login_path": "/auth/login", "logout_path": "/auth/logout" }
```

Browser driven, it names the provider to go to:

```json
{
    "server_flow": false,
    "issuer_url": "https://auth.example.com",
    "client_id": "portfolio",
    "scopes": "openid profile email offline_access groups"
}
```

`GET /auth/session` — who the caller is, always `200`, so an anonymous visitor is a fact rather
than an error:

```json
{
    "logged_in": true,
    "authorized": true,
    "roles": ["admin"],
    "user": { "provider": "https://auth.example.com", "id": "0f7c..." }
}
```

An absent, expired or rejected token yields `{"logged_in":false,"authorized":false}`. The `roles`
are the ones the policy granted; the raw provider role names behind them stay server side.

A rejected request on a guarded route answers with a stable code and a sentence:

```json
{ "error": "forbidden", "message": "this account is not allowed to perform this request" }
```

`error` is what a client branches on — `unauthorized` (401), `forbidden` (403), `unavailable`
(503). Neither field names what actually failed: that is for the logs, not for a caller who may be
probing.

### Local development

`Demo` authorizes every visitor as admin without contacting any provider, and says so loudly in the
logs. It must never be enabled in production, and two things stand between it and one.

It is left out of the binary unless it is built with the `authdemo` tag, named by `DemoBuildTag`.
The verifier authorizing every visitor, `verifier.NewUnverified`, is not compiled into any other
build, so no import path reaches it: a misread environment variable cannot disable token
verification on a deployment that was never built for it, and neither can a stray call. And demo
mode refuses to start beside a declared provider, issuer or audience, rather than silently ignoring
them.

`verifier.NewStatic` is the ungated sibling, for a host wanting a fixed user in its own tests. It
grants only what the caller spells out, so it opens nothing on its own.

```go
authApp, err := goauth.New(ctx, goauth.NewSettings(goauth.Options{Demo: true}), slog.Default())
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

The issuer itself must be `https`, loopback aside: the module fetches the signing keys over that
connection and forwards access tokens to it, so cleartext would hand both to anyone on the path.
There is no setting that lifts this.

Where roles come from the UserInfo endpoint, the subject it answers with must be the one the token
was verified for, as OpenID Connect Core 5.3.2 requires. Otherwise the roles of whoever the
endpoint chose to describe would be granted to the bearer.

Two shapes are refused beyond that. A token without a `sub` is rejected, since the `(Provider, ID)`
pair below would otherwise be a key several users share. And an **ID token presented as an access
token** is rejected — recognised by the `nonce`, `at_hash` or `c_hash` an access token never
carries. An ID token is minted for the browser and states who signed in, never what its bearer may
call.

### The issuer has the last word

A valid signature and an unexpired token say the issuer minted this, and when. They cannot say the
account still exists. So the issuer is asked whether the token is still active (RFC 7662), which is
what catches a **disabled account, a changed password, a revoked token or a session ended from
another device** — none of which a token can report about itself.

This is on by default: an issuer advertising an `introspection_endpoint` is asked, without the
deployment having to know it should ask.

-   `IntrospectionTTL` reuses the issuer's answer for that long, and defaults to **15 seconds**: a
    revocation lands within seconds, while a busy API leaves the provider alone for nearly every
    call. Asking on every single request would put the provider's latency and its outages in front
    of the whole API, which is the arrangement this module exists instead of. A negative value does
    ask every time, for a deployment that wants it. Only an `active` answer is ever cached, never a
    refusal, and never past the token's own expiry.
-   There is no setting that declines to ask. An issuer advertising no endpoint is not asked because
    there is nowhere to ask, and that is logged loudly at every start: it is the one case where a
    deleted account keeps working until its token expires.
-   An issuer that cannot be reached is a `503`, not a denial. Not knowing whether someone is still
    signed in is an outage; treating it as a revocation would sign everyone out on a hiccup.

Three things the module deliberately does not do:

-   **Rate limiting.** A rejected token costs a signature verification and a log line, both driven
    by an unauthenticated caller. Put a rate limiter in front of the API, as any public endpoint
    deserves.
-   **Server side session revocation.** The session cookie is sealed, not looked up, so there is no
    list here to strike it from. There does not need to be: the issuer is asked about the token it
    carries, so revoking at the provider stops it within seconds. Revocation lives where the
    account does.
-   **Back-channel logout.** The provider is asked rather than listened to. Introspection makes a
    revocation land within seconds; a pushed logout would make it land at once, without the round
    trip.
-   **Anything about the browser's token storage, in bearer mode.** An SPA keeping a refresh token
    in `localStorage` hands a long-lived credential to any XSS; `sessionStorage`, or no
    `offline_access` scope at all, narrows that window. In bearer mode this module never sees those
    tokens and cannot enforce the choice — which is the argument for the server driven flow, where
    the frontend holds nothing to lose.

Responses that depend on the caller carry `Vary: Authorization` and `Cache-Control: no-store`, so
no cache along the way can hand one user's session to the next.

## What the token carries

The browser presents an **access token**, and an access token carries no profile claim: no name, no
email, no avatar. Those live in the ID token, which belongs to the browser and never reaches this
module. `UserInfo` therefore holds `Provider` (the issuer), `ID` (the subject) and `Roles`, and
nothing else. A UI needing a name or an avatar reads them from its own ID token.

`Roles` there are the raw names the provider asserted, before any policy ruled on them, and they
are left out of the JSON encoding on purpose: what a browser is told are the roles the policy
granted, carried by the session's own `roles`, never the provider vocabulary behind them.

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

| `AUTH_PROVIDER` | Roles claim                         | Read from     | Scopes the browser requests                  |
| --------------- | ----------------------------------- | ------------- | -------------------------------------------- |
| `zitadel`       | `urn:zitadel:iam:org:project:roles` | the token     | `openid profile email offline_access`        |
| `pocketid`      | `groups`                            | `/userinfo`   | `openid profile email offline_access groups` |

Pocket ID emits a bare access token, so its roles are read from the UserInfo endpoint. That lookup
is cached per token for 30s, so a busy API queries the provider once per token rather than once per
request, and a role change is seen within that window. A UserInfo request that fails is not cached
and yields a `503`, never an empty role set: a provider outage must not read as a permission
problem. Both the TTL and the 5s request timeout are settings of `verifier.Config`, for a host
assembling its verifier itself.

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

## Development

Toolchain versions are pinned in `mise.toml`, and the same commands CI runs are available as tasks:

```sh
mise install
mise run check   # everything CI runs
mise run test
mise run vet
```

The demo path only compiles under `authdemo`, so the tests run twice: once for the shipped build,
once for the demo one. CI runs `gofmt`, `go vet`, `go mod tidy` and a `-race` test run on both.

