# Frontend

How a browser application talks to this module: what it must do, what it can stop doing, and how it
knows who the visitor is.

## Can the frontend always know whether it is authenticated and authorized?

Yes, and the two are separate questions with separate answers. `GET /auth/session` reports both, and
answers `200` whether or not anyone is signed in — an anonymous visitor is a fact, not an error:

| Response                                                  | Status | Meaning                                                   |
| --------------------------------------------------------- | ------ | --------------------------------------------------------- |
| `{"logged_in": false, "authorized": false}`                | `200`  | No token, or one that did not verify. Nobody is signed in. |
| `{"logged_in": true, "authorized": false, "user": {...}}`  | `200`  | Signed in, but this account holds no role here.            |
| `{"logged_in": true, "authorized": true, "roles": [...]}`  | `200`  | Signed in and allowed in. `roles` says what they may do.   |
| `{"error": "unavailable", ...}`                           | `503`  | The policy could not be evaluated. Nothing is known yet.   |

**The second row is the one to get right.** A visitor who signed in successfully but was granted no
role is authenticated and unauthorized. Sending them back to `/auth/login` puts them in a loop: the
provider signs them straight back in, and they land here again. Show them a dead end instead — an
"this account has no access to this application" page, with whom to ask.

```js
async function session() {
    const response = await fetch("/auth/session", { credentials: "same-origin" });

    if (response.status === 503) return { state: "unavailable" };

    const { logged_in, authorized, roles = [], user, profile } = await response.json();

    if (!logged_in) return { state: "anonymous" };
    if (!authorized) return { state: "no-access", user, profile };

    return { state: "signed-in", roles, user, profile };
}
```

`roles` is absent rather than empty when there are none, hence the `= []` default.

The response is `Cache-Control: no-store` and `Vary: Authorization, Cookie`, so neither the browser
nor any proxy hands one visitor's session to another.

## Which mode is this deployment in?

Two shapes exist, and `GET /auth/config` says which one you are talking to. Read it once at startup:

```js
const config = await (await fetch("/auth/config")).json();
```

```json
{ "server_flow": true, "login_path": "/auth/login", "logout_path": "/auth/logout" }
```

```json
{
    "server_flow": false,
    "issuer_url": "https://auth.example.com",
    "client_id": "portfolio",
    "scopes": "openid profile email offline_access groups"
}
```

Serving it at runtime is what lets one build of the frontend run against every environment.

## Server driven login (`server_flow: true`)

The server runs the whole OIDC flow. The frontend never sees a token, never stores one, and ships no
OIDC library. This is the entire integration:

```js
// Sign in: a top-level navigation, not a fetch. The provider has to draw its own page.
location.href = "/auth/login?return_to=" + encodeURIComponent(location.pathname);

// Call the API: the session cookie rides along on its own.
await fetch("/api/skills", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(skill),
});
```

Things worth knowing:

-   **`/auth/login` must be a navigation.** `fetch` cannot follow it: it redirects to the provider,
    which serves a login page cross-origin. Use `location.href`, or a plain `<a>`.
-   **`return_to` must be a path on this application.** An absolute URL is dropped and the visitor
    lands on the default instead — the endpoint refuses to be an open redirect. `/skills?tab=all` is
    fine; `https://elsewhere.example.com` is not.
-   **Refresh is automatic.** The server renews the access token when it ages out, and reseals the
    cookie. Any request through the API does it, `GET /auth/session` included, so nothing in the
    frontend has to track expiry.
-   **The session cookie is `HttpOnly`.** JavaScript cannot read it, which is the point: there is
    nothing on the page for an XSS to steal. Do not look for it in `document.cookie`.
-   **A session can end at any moment.** It ends when the provider stops standing behind it: an
    account disabled, a password changed, a session closed from another device, or the refresh
    simply running out. The provider is asked about the token, so this lands within seconds. Expect
    a `401` mid-session at any time, and send the visitor back through `/auth/login` when it does.

### Signing out

Logout answers to `POST`, so that a cross-site page cannot sign a visitor out by linking to it, and
checks the request's origin, so that one cannot do it with a form it submits itself either. Both
calls below are made from your own pages, so the browser states that origin on its own — there is
nothing for the frontend to attach.
Which call to make depends on whether the deployment configured a provider-wide logout:

```js
// The deployment set no PostLogoutURL: the endpoint answers 204 and only drops the local session.
await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
location.href = "/";
```

Where a `PostLogoutURL` **is** configured, the endpoint answers `302` towards the provider, to end
the session there too. `fetch` cannot follow that redirect cross-origin, so the logout has to be a
top-level navigation that is still a `POST` — which is what a form is for:

```html
<form method="post" action="/auth/logout">
    <button type="submit">Sign out</button>
</form>
```

If you are unsure which the deployment does, the form works in both cases.

### CSRF: nothing to do

The module checks it for you, by origin. A request that changes something and carries the session
must come from this application, which the browser states on its own — there is no token to read
and no header to echo back.

This means the frontend has to be served from the same origin as the API. A page elsewhere cannot
spend the session, which is the point, and this module does no CORS to make it possible.

A request refused by the check answers `403` with `{"error": "cross_site"}`.

## Browser driven login (`server_flow: false`)

The browser obtains its own tokens and presents them itself. Use a maintained library —
`oidc-client-ts` — rather than writing the flow by hand:

```js
import { UserManager, WebStorageStateStore } from "oidc-client-ts";

const config = await (await fetch("/auth/config")).json();

const users = new UserManager({
    authority: config.issuer_url,
    client_id: config.client_id,
    scope: config.scopes,
    redirect_uri: location.origin + "/callback",
    response_type: "code", // authorization code with PKCE
    userStore: new WebStorageStateStore({ store: sessionStorage }),
});
```

Then attach the token to every call:

```js
const user = await users.getUser();

await fetch("/api/skills", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${user.access_token}`,
    },
    body: JSON.stringify(skill),
});
```

`scopes` comes from the server because providers disagree on what they need: Pocket ID only emits
its `groups` claim when the scope of the same name is asked for. Reading it at runtime means adding
a provider never touches the frontend.

**On storage.** A refresh token in `localStorage` is a long-lived credential handed to any XSS on
the page, and it survives the tab. `sessionStorage` narrows the window to the tab's lifetime;
dropping `offline_access` altogether removes the refresh token from the browser entirely, at the
cost of re-authenticating when the access token expires. The module never sees these tokens and
cannot enforce the choice — which is the argument for the server driven mode, where the frontend
holds nothing worth stealing.

## Who is signed in

`user` identifies the account — `{ "provider": ..., "id": ... }` — and is the pair to store beside
your own records. It is not a thing to display: it is an issuer URL and a subject identifier.

What to display is `profile`, which the session carries **in the server driven flow only**:

```json
{
    "logged_in": true,
    "authorized": true,
    "roles": ["admin"],
    "user": { "provider": "https://auth.example.com", "id": "312..." },
    "profile": {
        "username": "amaury",
        "name": "Amaury Valorge",
        "email": "amaury@example.com",
        "picture": "https://auth.example.com/avatar.png"
    }
}
```

Every field is optional, and so is the whole object: a provider fills the claims it chooses to, and
a lookup that fails costs the name rather than the session. Fall back on `user.id` rather than
rendering an empty header, and never gate anything on a profile — it is what a page shows, not what
a decision is made on.

**In the browser driven flow there is no `profile`, by design.** The browser holds its own ID token,
which is where the provider put these claims, and `oidc-client-ts` hands them over already parsed:

```js
const user = await users.getUser();
const { name, email, picture, preferred_username } = user.profile;
```

## Reading roles

`roles` are the roles this application granted, not the raw names the provider uses. The provider's
own vocabulary — `portfolio_admin`, some group name — is mapped server side and never reaches the
browser, so the frontend depends on names that do not change when the provider does.

```js
const canEdit = roles.includes("admin");
const canRead = roles.includes("admin") || roles.includes("guest");
```

**Hiding a button is not authorization.** It is a courtesy to the user; the check that matters
already happened on the server, and will happen again on the next call. Never treat a hidden control
as a protected one.

## Handling API errors

Every rejection carries a stable code in `error` and a sentence in `message`. Branch on the code,
show the sentence, and never parse the sentence:

```json
{ "error": "forbidden", "message": "this account is not allowed to perform this request" }
```

| Status | `error`        | What happened                                     | What to do                                        |
| ------ | -------------- | ------------------------------------------------- | ------------------------------------------------- |
| `401`  | `unauthorized` | No token, or one that no longer verifies.         | Start a login again.                              |
| `403`  | `forbidden`    | Signed in, but not allowed to do this.            | Say so. Do **not** send them to login.            |
| `403`  | `cross_site`   | The request did not come from this application.   | A deployment setting is wrong. Report it.         |
| `503`  | `unavailable`  | Authorization could not be evaluated. Transient.  | Retry with a backoff. Keep the session as it was. |

The `401`/`403` distinction is the same trap as the session states: a `403` never means "sign in
again", and treating it that way sends the visitor around a loop that cannot end.

A `401` mid-session means the provider no longer stands behind the session: the token was revoked,
the account disabled, the password changed, or the refresh simply ran out. Send the visitor back
through `/auth/login`, which is the one response that fits all of them.

## Checklist

-   [ ] Read `/auth/config` once, branch on `server_flow`.
-   [ ] Distinguish the four session states, and give `logged_in && !authorized` a dead end rather
        than a redirect.
-   [ ] Display `profile`, fall back on `user.id`, and gate nothing on either.
-   [ ] Send `Content-Type: application/json` on every write.
-   [ ] Branch on `error`, never on `message`.
-   [ ] Treat `403` and `503` as anything but a reason to log in again.
-   [ ] Re-check every permission on the server. The UI only hides.
