# Agent instructions

Desk booking app: React UI (Vite) + plain Node HTTP API on built-in `node:sqlite`. See `README.md` for features and setup.

## Layout

- `server/app.ts` — `createHandler`: REST routes, sessions, Microsoft sign-in; dispatches `/mcp` and its metadata route to `mcp.ts`, the OAuth proxy routes to `oauth.ts`
- `server/service.ts` — room and booking logic shared by REST and MCP: validation (`text()`, `time()`, `readJson`), admin and ownership checks, clash check, user upsert from Entra claims
- `server/mcp.ts` — MCP server at `/mcp` (JSON-RPC over Streamable HTTP, JSON responses only, stateless) and its tool table
- `server/bearer.ts` — Entra access-token validation for `/mcp` (RS256 against the issuer's JWKS) and the rate limiter (per user, per IP)
- `server/oauth.ts` — stateless OAuth proxy for MCP clients (`/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token`): validates, drops `resource`, relays to Entra
- `server/db.ts` — schema (`openDb`) and in-place upgrades of an existing db
- `server/index.ts` — entry point; serves API + Vite dev middleware on one port
- `server/app.test.ts` — API tests (Microsoft sign-in runs against `oauth2-mock-server`)
- `server/mock-oidc.ts` — dev-only local OIDC provider for trying Microsoft sign-in without Entra
- `server/dev-env.ts` — loads `.env` for `npm run dev` (not `--env-file`: with `--watch-path` it restart-loops the server)
- `client/App.tsx` — the whole UI; `client/styles.css` — styles
- `.github/workflows/` — CI (lint, build, test, audit: blocks on high or critical advisories in production dependencies, reports dev-only advisories without failing), CodeQL, deploy (staging, then prod after approval)

## Commands

- `npm run dev` — run the app at http://localhost:3000
- `npm test` — API tests (`node:test`)
- `npm run build` — typecheck (`tsc`) + production build
- `npm run lint` — Biome linter (formatter is off)

## Definition of done

1. `npm test` passes.
2. `npm run build` passes (this is the typecheck).
3. `npm run lint` reports no errors.
4. Every API behavior change has a test in `server/app.test.ts`.
5. Every new or changed route has negative tests: 401 with no session, 403 for a non-admin on admin routes, 403 when acting on another user's data. Happy-path tests alone do not count.

## Security requirements

These are mandatory. A change that breaks one is not done, even if tests pass. If a task seems to need breaking one, stop and ask.

**Access control**
- Every route except `GET /api/login` and `GET /api/callback` (Microsoft sign-in) requires a valid session. New routes go after the session check in `route()`, never before it. These exceptions are dispatched before the session check:
  - The MCP routes below (`/mcp`, both `/.well-known/oauth-*` routes, `/oauth/*`) are local only: they return 404 unless `MCP_ENABLED=1` and the socket address is loopback. This check runs before anything else in `route()`.
  - `/mcp` is protected by bearer auth instead: it accepts only `Authorization: Bearer <Entra access token>` (validated in `bearer.ts` before the body is read) and never the `session` cookie. REST `/api/*` routes never accept bearer tokens.
  - `GET /.well-known/oauth-protected-resource` is public (RFC 9728 metadata, no side effects). Its `authorization_servers` is this app's origin, i.e. the OAuth proxy.
  - The OAuth proxy for MCP clients is public and stateless (no cookies, no session, no user rows): `GET /.well-known/oauth-authorization-server` (RFC 8414 metadata), `GET /oauth/authorize` (checks `client_id` = `OIDC_CLIENT_ID`, loopback `redirect_uri`, S256 PKCE, then redirects to Entra) and `POST /oauth/token` (form body capped at 100 KB; checks `grant_type` and `client_id`, then relays to Entra). Only allow-listed parameters are relayed, so RFC 8707 `resource` (rejected by Entra v2) is dropped. It is not another login path: users still sign in only at Microsoft. It never adds `OIDC_CLIENT_SECRET` or any client authentication to the relayed request, and never logs codes, verifiers or tokens.
- Admin-only actions call `requireAdmin()` on the server. Hiding a button in the UI is not authorization.
- Ownership is checked on the server: a user may only change or delete their own bookings (admins excepted). The user id comes from the session, never from the request body or URL.
- Deny by default: unknown paths and methods return 404; a missing check is a bug, not a feature.

**Input and data**
- All SQL uses prepared statements with `?` parameters. Never build SQL with string concatenation or template literals containing request data.
- Validate every request field at the API boundary (type, length, format) with the existing `text()` / `time()` helpers or equivalent. Request bodies stay capped (`readJson`, 100 KB).
- Responses never include session tokens of other users or stack traces. Unexpected errors return a generic 500 and are logged server-side only.
- The UI renders user-supplied text as text. No `dangerouslySetInnerHTML`, `innerHTML` or `eval`.

**Secrets and credentials**
- Session tokens come from `crypto.randomBytes` (at least 32 bytes). No `Math.random()` for anything security-related.
- Secrets live in environment variables / `.env`, never in code, tests, logs, commits or `README.md`.

**Dependencies**
- No new dependency without asking (see Conventions). Run `npm audit` when adding or upgrading one and report high/critical findings.

**Known gaps (accepted for now, do not make worse)**
- The `session` cookie lives 30 days in the browser; the session behind it expires on the server after 15 minutes, then the app signs in again silently through Microsoft.
- Revoking the Entra `Admin` role (or disabling the user) takes effect only at the next role re-check, up to 15 minutes. Future fix: near-immediate revocation (for example a Microsoft Graph check on admin actions).
- No CSRF token: the session is an HttpOnly, `SameSite=Lax`, `Secure` cookie, so CSRF protection relies on SameSite plus every state change being non-GET. Keep GET routes free of side effects. The exceptions are `GET /api/login` and `GET /api/callback`, the standard OIDC redirect shape: their side effects are limited to the sign-in flow itself, and the callback only signs in when `state` matches the HttpOnly `oidc` flow cookie. Because the cookie is always `Secure`, plain-http access works only on `localhost`.
- No security headers (CSP etc.) and no HTTPS in the app itself; deployment must put TLS in front.
- Rate limits: `/mcp` allows 60 requests/min per authenticated user; more than 30 failed bearer authentications/min per IP block that IP (including valid tokens) for the rest of the minute; `POST /oauth/token` allows 30 requests/min per IP. The IP is the socket address, so behind a reverse proxy all clients share one limit. Read a trusted `X-Forwarded-For` before any shared or public deployment.

## Conventions

- Node 24 runs `.ts` directly (type stripping): no enums, namespaces or parameter properties (`erasableSyntaxOnly` enforces this).
- Relative imports keep the `.ts`/`.tsx` extension; type-only imports use `import type` (`verbatimModuleSyntax`).
- Prefer Node built-ins (`node:sqlite`, `node:crypto`, `node:test`). No new dependencies without asking.
- Auth is OIDC via Entra ID with this server as BFF: Microsoft sign-in is the only way in. Don't add another login path.

## Files agents may touch

| Zone | Paths |
|---|---|
| Edit freely | `client/**`, `server/**`, `README.md`, `AGENTS.md` |
| Ask first | `package.json`, `package-lock.json`, `tsconfig.json`, `vite.config.ts`, `biome.json`, `index.html`, `.gitignore`, `.github/**` |
| Never touch | `*.db` (real data), `dist/**`, `node_modules/**`, `.env*` |

## Git

- One branch per task; never commit straight to `master`.
- No AI co-author trailers or "Generated with" lines in commits or PRs.
- Never commit secrets, `.db` files or build output.
