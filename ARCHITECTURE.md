# Architecture

## Position

`auth` is a standalone Go module. It depends on no application package, so it can be shared by
several apps: each one declares its own audience and its own authorization policy.

Authentication is delegated to a central OIDC identity provider. The browser performs the
authorization code flow with PKCE and holds the tokens; this module only verifies them.

## Packages

-   `auth` — the facade and the deployment entry point: `Settings` and `NewSettings` holding what
    the host declares, `New` assembling the verifier and the policy from them, `Auth`, the
    `RequireRoles` and `RequireAnyRole` middlewares, `RegisterRoutes` mounting the config and
    session endpoints, and the bearer token extraction. It is the only package a host application
    needs to import.
-   `verifier` — OIDC discovery, key set caching and rotation, token verification, and the claims to
    `UserInfo` mapping. It reads the roles from the claim it is handed, and knows no provider by
    name. `Static` bypasses all of it for local development.
-   `provider` — the identity providers a deployment may choose from, `zitadel` and `pocketid`, each
    holding what reading its tokens demands: the roles claim, and the scopes the browser requests.
-   `authorization` — `FromToken` and `FromTokenNames`, mapping the role names the provider asserts
    to the roles the application declares.
-   `types` — `Role`, `Decision`, `Authorizer`, `TokenVerifier`, `UserInfo`, `SessionInfo`,
    `Logger`.

## Request flow

1. The browser sends `Authorization: Bearer <token>`.
2. `RequireRoles` extracts the token, empty when there is none, and always hands it to the verifier:
   what an absent token means is the verifier's call, not the middleware's.
3. `verifier` rejects an empty token, then checks the signature against the issuer key set, followed
   by `iss`, `aud`, `exp` and `nbf`, and finally refuses a token without a `sub` or carrying an ID
   token's own claims. A rejected token is a `401`.
4. The claims become a `UserInfo`, passed to the `Authorizer`.
5. The policy returns a `Decision` carrying the granted roles. An unauthorized user, or one missing
   a required role, is a `403`.
6. The handler runs, with the user reachable through `auth.UserFrom(ctx)`.

## Design notes

-   **Verification in the app, not in a proxy.** A forward auth proxy would sit in front of every
    request, so an identity provider outage would take the public pages down with it. Here the
    provider is only involved when someone signs in.
-   **Roles are the application's decision.** The token says who the user is; the policy says what
    this application lets them do. That keeps role mapping working with any provider, including ones
    with no notion of application roles. `FromToken` reads provider roles, but still only honours
    the ones the application declares, so the decision stays here.
-   **`TokenVerifier` is an interface.** Real verification and the development bypass are two
    implementations, so the middleware never learns which one it is talking to.
-   **Demo mode is a compile-time opt-in.** `New` refuses it unless the binary carries the
    `authdemo` tag, so disabling token verification takes a deliberate build and not a stray
    environment variable. The refusal to run beside a declared provider covers the rest.
-   **The provider is named, never guessed.** No standard names the claim carrying roles, so
    `AUTH_PROVIDER` is required and an unknown name is refused at startup. Defaulting it would read
    roles from a claim nobody fills and deny everyone, a failure that looks like a permission bug.
    Everything that differs between providers is a `Provider` value, so a third one is a value
    rather than a branch.
-   **No profile claim leaves the token.** The browser presents an access token, which carries the
    subject, the issuer and the roles — never a name, an email or an avatar. `UserInfo` holds only
    what is really there, so no policy can be written on a field that is always empty. A UI needing
    a profile reads its own ID token, which is where the provider puts it.
