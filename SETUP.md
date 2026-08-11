# Provider setup

This module verifies OIDC tokens; it does not issue them. It reads roles from the claim of the
provider a deployment declares in `AUTH_PROVIDER`, and supports two:

| `AUTH_PROVIDER` | Provider  | Roles claim                         |
| --------------- | --------- | ----------------------------------- |
| `zitadel`       | Zitadel   | `urn:zitadel:iam:org:project:roles` |
| `pocketid`      | Pocket ID | `groups`                            |

The setting has no default: assuming one would have the server read roles from a claim nobody fills,
which denies everyone at once. Declaring an unsupported name fails at startup rather than at the
first login.

Zitadel is the heavier of the two — PostgreSQL, projects, per-application token settings — and
manages roles in its own console. Pocket ID is a single small service authenticating with passkeys
only, and names its roles with groups.

## Values to align

Three values must match across the provider, the server and the browser, whichever provider is used.
The browser reads what it needs from `GET /api/v1/auth/config`, so only the server is configured.

| Value          | At the provider           | Go server                          |
| -------------- | ------------------------- | ---------------------------------- |
| Provider URL   | the instance URL          | `AUTH_ISSUER`                      |
| Application Id | the client Id             | `AUTH_AUDIENCE`                    |
| Callback       | the client's Redirect URI | derived: origin + `/auth/callback` |

The redirect URI is `https://yourapp.example.com/auth/callback`. Registering an `http://` one
alongside it costs the application its OIDC compliance, so local development runs on `AUTH_DEMO`
instead, or on a second client of its own.

The OIDC scopes are not in that table: they follow from `AUTH_PROVIDER` and are served to the
browser, since Pocket ID only emits its groups when the `groups` scope is requested and Zitadel
knows no such scope.

`.env.example` lists these variables with what each one expects.

## Whichever provider

Two settings decide whether anything works at all, and neither reports its cause clearly when wrong.

**The client is a public browser client, with PKCE.** There is no client secret, and none should be
configured: anything shipped to a browser is public.

**The access token must be a JWT, and must carry the roles.** This module verifies signatures
against the issuer key set, which is impossible with an opaque token — that would require token
introspection, which is not implemented. The browser sends its **access token**, so roles put only
in the ID token or exposed only at the userinfo endpoint never reach the server.

## Zitadel

### Deployment shape

Zitadel needs PostgreSQL and terminates behind your own reverse proxy, on a dedicated subdomain so
that every application can share it:

```
https://auth.example.com  →  reverse proxy (TLS)  →  Zitadel  →  PostgreSQL
```

HTTPS is not optional: tokens travel through the browser. Exact container image, environment
variables and the first-run masterkey change between versions — take them from the current upstream
documentation rather than from a snippet copied here, which would rot silently.

### Client

Create a Project, then an Application of type _User Agent_ (a browser SPA) with **PKCE**. Its auth
token type must be **JWT**, not the opaque default.

### Roles

1. **Project → Roles**: create `admin` and `guest`. The role _key_ is the string that reaches the
   token, and these two are the defaults the application expects. Naming them otherwise is fine, as
   long as `AUTH_ADMIN_ROLE` and `AUTH_GUEST_ROLE` declare the names you chose.
2. **Project → check "Assert Roles on Authentication"**, otherwise the claim is never emitted and
   everybody ends up with no role at all.
3. **Application → Token settings → check "Add user roles to the access token"**.
4. **Project → Authorizations**: grant a user one of the roles. This is the day-to-day screen; the
   change takes effect on their next token.

The claim value is an object keyed by role, not an array, and is read as such:

```json
"urn:zitadel:iam:org:project:roles": {
    "guest": { "279...": "example.zitadel.cloud" }
}
```

### Token lifetime

Zitadel defaults the access token lifetime to 12 hours. Shorten it under **Instance settings → OIDC
Token Lifetimes and Expiration → Access Token Lifetime**; it is instance-wide, not per application.
Enable **Refresh Token** in the application's grant types, which the requested `offline_access`
scope relies on.

### Social login

Add Google and GitHub as identity providers on the instance, and register the callback they require
on the provider side — it points at Zitadel, not at your application. Zitadel then federates them
and issues its own tokens.

## Pocket ID

### Deployment shape

A single service, SQLite by default, behind your own reverse proxy on a dedicated subdomain:

```
https://auth.example.com  →  reverse proxy (TLS)  →  Pocket ID
```

Its public URL must be declared to it, and the proxy trusted, or it builds its issuer and callback
URLs from the wrong host and every token is rejected for a mismatched `iss`. Authentication is by
passkey only: there is no password to leak, and no social federation to configure.

### Client

Create an OIDC client, public, with PKCE, and its callback URL. The client Id it hands back is
`AUTH_AUDIENCE`.

### Roles

Roles are groups. Create `admin` and `guest`, or the names `AUTH_ADMIN_ROLE` and `AUTH_GUEST_ROLE`
declare, and put users in them. The change takes effect on their next token.

The `groups` claim holds a plain array of names, which is read as such:

```json
"groups": ["guest"]
```

Check on a real token that the group names reach the **access** token, and not only the ID token:
that is what the server reads, and the difference is invisible until a login grants no role.

## What each role reaches

| Role    | Public pages | Reading the administration | Changing the data |
| ------- | ------------ | -------------------------- | ----------------- |
| none    | yes          | no                         | no                |
| `guest` | yes          | yes                        | no                |
| `admin` | yes          | yes                        | yes               |

Grant yourself the admin role at the provider first: the application configuration holds no admin of
its own, so the provider is the only place a role is ever handed out.

## How fast a revoked role takes effect

Roles are written into the token when it is issued, and the browser reuses that token until it
expires: removing a role at the provider only takes effect on the next token. The access token
lifetime _is_ the revocation delay, so keep it to a few minutes.

Renewals need a refresh token, which is why the application requests the `offline_access` scope:
without one the session would end at the first expiry, since it does not serve an iframe renewal.
The browser renews on its own before expiry, so a short lifetime costs nothing but the renewals.

Revocation stays deferred by that lifetime, never immediate. Making it immediate means resolving
roles per request from the application's own store — `authorization.FromStore` — rather than reading
them from the token.

## When nobody is admin any more

A misconfigured claim — roles not asserted, wrong `AUTH_PROVIDER`, groups missing from the access
token — strips everyone of every role at once, and the application holds no admin of its own to fall
back on. That is deliberate: the repair happens in the provider's console, which has its own
credentials and does not depend on this application. Fix the setting there and sign in again;
nothing has to be redeployed.

## Local development

`mise run dev-server` passes `-auth-demo`, which authorizes every visitor as admin without
contacting any provider. No provider instance is needed to work on the application, and the browser
never sees a login button in that mode.
