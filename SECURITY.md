# Security policy

This module decides who reaches an application and with what rights. A flaw in it is a flaw in
every deployment that uses it, so reports are welcome and taken seriously.

## Reporting a vulnerability

**Report privately, through GitHub:**
[Security → Report a vulnerability](https://github.com/amauryval/goauth/security/advisories/new).

Please do not open a public issue, a pull request or a discussion for a suspected vulnerability —
those are visible to everyone the moment they are created, including to whoever would use the
finding.

Useful in a report, in rough order of usefulness:

-   What an attacker gets. "A token issued for another application is accepted" says more than
    "audience check looks weak".
-   The version, tag or commit you looked at, and the mode: bearer tokens, or the server driven
    browser flow.
-   A failing test, a request sequence, or a short program. This module's own tests are the shape
    that reproduces fastest — a `_test.go` that fails on `main` is the ideal report.
-   The identity provider involved, where it matters. Providers differ in what they put in a token
    and what they advertise in discovery, and several findings only exist against one of them.

This is a single maintainer project, so expect a best effort rather than a service level. You will
get an acknowledgement that the report was read, an assessment once there is one, and credit in the
advisory unless you would rather not have it. If a fix is warranted we will agree on a disclosure
date; if the behaviour turns out to be deliberate, you will get the reasoning rather than silence.

## Supported versions

The module is pre-1.0: only the latest tag receives fixes, and the API may still change between
minor versions. Deployments are expected to track it.

## In scope

The decisions this module makes on its own:

-   A token accepted that should have been refused — signature, issuer, audience, expiry, an ID
    token presented as an access token, or an algorithm that should not have been honoured.
-   A session cookie that can be read, forged or replayed without the sealing secret, including one
    sealed for one purpose being accepted as another.
-   A cross-site request that reaches a state changing route while carrying the session cookie.
-   A redirect that leaves the application — `?return_to`, the post login destination, the post
    logout destination.
-   A role granted that the authorization policy did not grant, or role names read from somewhere
    the deployment did not point at.
-   A credential reaching somewhere it should not: an access token, a refresh token or the cookie
    secret in a log line, an error message, a response body or a URL.
-   Introspection, UserInfo or discovery answers being trusted further than they should be.

## Not vulnerabilities

Deliberate behaviour, documented and reachable only on purpose:

-   **Demo mode authorizes every visitor as an administrator.** That is what it is for. It demands
    both the `AUTH_DEMO` setting and a binary built with `-tags authdemo`, and the code that grants
    it is not compiled into any other build. It also refuses to run beside a configured provider.
-   **`WithInsecureCookies` drops the `Secure` attribute.** It exists for a local stack served over
    http, it warns at startup, and it must never be set on a deployment.
-   **`verifier.NewStatic` authorizes whoever the caller names, without verifying anything.** It is
    a fixture for a host's own tests.
-   **A revocation lands within seconds rather than instantly.** The issuer's answer about a token
    is reused for `IntrospectionTTL`, 15 seconds by default. A negative value asks on every single
    request. This is a stated trade, argued in `ARCHITECTURE.md`.
-   **An issuer advertising no `introspection_endpoint` is not asked.** There is nowhere to ask, so
    a disabled account keeps working until its token expires. It is warned about at every start,
    and `WithRequireIntrospection(true)` turns that warning into a refusal to start.
-   **There is no rate limiting.** A rejected token costs a signature check and a log line. Put a
    rate limiter in front of the API, as with any public endpoint.
-   **Anything the host owns**: its own XSS, its response headers, its TLS termination, where it
    keeps the cookie secret, and whether it mounts the middleware on the routes it meant to.

Vulnerabilities in dependencies belong upstream. CI runs `govulncheck` on every push, so a reachable
advisory in `go-oidc`, `go-jose` or `x/oauth2` shows up there; report it to that project, and open a
normal issue here if this module needs to move.
