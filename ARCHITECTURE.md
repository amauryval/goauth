# Architecture

## The constraint everything answers to

**The identity provider is the authority on whether someone is signed in, and it has the last
word.** Not this module, and not the token.

A token is evidence, not a decision. Its signature says the issuer minted it; its expiry says when
it was meant to stop being useful. Neither can say that the account still exists, that its password
was not changed an hour ago, or that the session was not ended from another device. Those are facts
only the issuer holds, and a module that reads a token and decides for itself is a module that
keeps a deleted account signed in until a timestamp it was handed at login happens to pass.

So the issuer is asked, on every request, through the mechanism the protocol defines for it:
**token introspection, RFC 7662**. The answer is a boolean the issuer states — `active` — not a
status code interpreted here, not a heuristic, not an inference from a request made for some other
purpose. Where a decision belongs to the issuer, it is read from the issuer saying it.

This has consequences the rest of the design bends to:

-   **There is no way to decline asking.** An issuer advertising an `introspection_endpoint` is
    asked. The only deployment that does not ask is one whose issuer advertises nowhere to ask,
    which is the issuer's statement about itself rather than a setting here, and it is logged
    loudly at every start.
-   **No answer is not a no.** An issuer that cannot be reached yields `types.ErrAuthorization` and
    a `503`. Not knowing whether someone is still signed in is an outage; treating it as a
    revocation would log everyone out the moment the provider hiccups.
-   **Nothing infers revocation from something else.** The UserInfo endpoint is a roles lookup and
    only that: every way it fails is an outage, and none of them is read as "the token died".
    Reading a rejection out of it would be guessing at an answer that has its own question.
-   **The answer is reused briefly, and a no is never kept.** `IntrospectionTTL` defaults to 15
    seconds: a revoked token, a disabled account or a closed session is refused within seconds,
    while a busy API leaves the provider alone for the overwhelming majority of its calls. Only an
    `active` answer is ever cached, and never past the expiry the issuer stated for the token
    itself. A negative TTL asks on every single request, for a deployment that needs it and accepts
    what it means.

That last point is the one to argue with, so here is the argument. Asking on every request would
put the provider in front of the entire API: its latency added to every call, its outage taking the
application down with it, and one request to it for every request to us. That is the forward auth
proxy this module exists instead of. Fifteen seconds keeps the provider the authority — its
decisions land in seconds rather than at some expiry it handed out at login — without making it a
dependency of every response. The window is a setting, so a deployment that wants zero can have it.

## Position

`goauth` is a standalone Go module. It depends on no application package, so it can be shared by
several apps: each one declares its own audience and its own authorization policy.

Authentication is delegated to a central OIDC identity provider. The browser performs the
authorization code flow with PKCE and holds the tokens; this module only verifies them.

## Packages

-   `goauth` — the facade and the deployment entry point: `Options` and `NewSettings` holding what
    the host declares, `New` assembling the verifier and the policy from them, `Auth`, the
    `RequireRoles` and `RequireAnyRole` middlewares, `RegisterRoutes` mounting the config and
    session endpoints, and the bearer token extraction. It is the only package a host application
    needs to import.
-   `verifier` — OIDC discovery, key set caching and rotation, token verification, and the claims to
    `UserInfo` mapping. It reads the roles from the claim it is handed, and knows no provider by
    name. Where the roles live at the UserInfo endpoint rather than in the token, it caches them
    per token so a busy API does not query the provider on every request. `Static` bypasses all of
    it for a host injecting a fixed user, and `NewUnverified` — the one authorizing everyone — only
    exists in binaries built with the `authdemo` tag.
-   `provider` — the identity providers a deployment may choose from, `zitadel` and `pocketid`, each
    holding what reading its tokens demands: the roles claim, and the scopes the browser requests.
-   `authorization` — `FromToken` and `FromTokenNames`, mapping the role names the provider asserts
    to the roles the application declares.
-   `browser` — the optional server driven login: PKCE, the state of a login in flight, the code
    exchange, the AES-GCM sealed session cookie, the refresh that keeps it alive and the origin
    check that stops another site spending it. It hands the access token of the calling browser to
    the rest of the module and nothing else, so verification and authorization are the same code
    path a bearer token takes.

    What it holds is what it reads: the two tokens, and the ID token only because a provider wants
    it back as a logout hint. It carries no lifetime of its own — how long a sign in stays good is
    how long the provider keeps honouring the refresh token. Cookie names, paths and the SameSite
    policy are not settings, because nothing needed them to be.
-   `types` — `Role`, `Decision`, `Authorizer`, `TokenVerifier`, `UserInfo`, `SessionInfo`,
    `Logger`.

## Request flow

1. The browser presents its credential: a session cookie where the module drives the login, an
   `Authorization: Bearer` header otherwise. Either way a `TokenSource` turns it into an access
   token, renewing it first when the cookie holds a refresh token and the access token is spent.
2. `RequireRoles` hands that token to the verifier, empty when there is none: what an absent token
   means is the verifier's call, not the middleware's.
3. `verifier` rejects an empty token, then checks the signature against the issuer key set, followed
   by `iss`, `aud`, `exp` and `nbf`, and refuses a token without a `sub` or carrying an ID token's
   own claims. A rejected token is a `401`.
4. It then asks the issuer whether the token is still active (RFC 7662). This is the step that
   catches a disabled account, a changed password or a session ended elsewhere, none of which the
   token itself can report. A token the issuer disowns is a `401`; an issuer that cannot answer is
   a `503`.
5. The claims become a `UserInfo`, passed to the `Authorizer`.
6. The policy returns a `Decision` carrying the granted roles. An unauthorized user, or one missing
   a required role, is a `403`.
7. The handler runs, with the user reachable through `goauth.UserFrom(ctx)`.

A policy that could not be evaluated at all is a `503` rather than a `401` or a `403`, carried by
`types.ErrAuthorization`. Reading the roles from an unreachable UserInfo endpoint fails that way
too: a user stripped of every role by a provider outage is a service problem, not a denied caller.

## Design notes

-   **The sealed cookie is a trade, not a free win.** A session that carries its own authority needs
    no store, no Redis and nothing shared between replicas, which is what lets this stay a library.
    The price is that it cannot be revoked: nothing can strike a cookie already handed out. An
    absolute session lifetime is what bounds that, and it is why the default is hours rather than
    weeks. A deployment that must kill sessions on demand needs a store, and this is the seam to
    replace.
-   **The frontend holds nothing, when it can.** A token in `localStorage` is a credential handed
    to any XSS on the page, and no care taken in the API takes that back. Where the module drives
    the login, the tokens live in a sealed `HttpOnly` cookie the browser can present but not read,
    and the frontend shrinks to a redirect and a `fetch`. The bearer path stays for callers that
    are not browsers.

-   **The provider decides, this module enforces.** See the constraint above: it is the reason
    introspection is on by default rather than offered, and the reason an unreachable issuer is a
    `503` rather than a denial.
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
    `authdemo` tag, and the verifier authorizing every visitor is not compiled into any other
    build: no import path reaches it, so disabling token verification takes a deliberate build and
    not a stray environment variable. The refusal to run beside a declared provider covers the rest.
-   **The provider is named, never guessed.** No standard names the claim carrying roles, so
    `AUTH_PROVIDER` is required and an unknown name is refused at startup. Defaulting it would read
    roles from a claim nobody fills and deny everyone, a failure that looks like a permission bug.
    Everything that differs between providers is a `Provider` value, so a third one is a value
    rather than a branch.
-   **No profile claim leaves the token.** The browser presents an access token, which carries the
    subject, the issuer and the roles — never a name, an email or an avatar. `UserInfo` holds only
    what is really there, so no policy can be written on a field that is always empty. A UI needing
    a profile reads its own ID token, which is where the provider puts it.
