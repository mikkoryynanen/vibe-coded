# Desk Booking

A small web app for a team to book desks or meeting rooms by time slot.

## Features

- **Sign in with Microsoft** (Entra ID) is the only way in. Who may sign in and who is admin is managed in Entra; a user's account here is created on first sign-in.
- **Bookings** (all users): pick a day, see each room's bookings for that day, and book a room for a start–end time.
  - Overlapping bookings for the same room are rejected; back-to-back bookings are fine.
  - You can cancel your own bookings. Admins can cancel anyone's.
- **Manage rooms** (admins only): add, rename and delete rooms. Deleting a room also deletes its bookings.

The UI is React (Vite); the API is a plain Node HTTP server with a built-in SQLite database (`booking.db`).

## Requirements

- Node.js 24 or newer (the server runs `.ts` files directly and uses the built-in `node:sqlite`).

## Running

```sh
npm install
npm run dev
```

Open http://localhost:3000. One server serves both the API (`/api/...`) and the UI, with hot reload.

The app needs the four `OIDC_*` variables (see [Sign in with Microsoft](#sign-in-with-microsoft-entra-id)); without them it exits at start and names the missing ones. On the first run it creates `booking.db`. There is no built-in admin account: whoever holds the Entra `Admin` app role is admin. Sign in as an admin and add some rooms under **Manage rooms**.

## Configuration

Optional environment variables:

| Variable         | Default      | Purpose                                                          |
|------------------|--------------|------------------------------------------------------------------|
| `DB_PATH`        | `booking.db` | SQLite database file                                             |
| `PORT`           | `3000`       | HTTP port                                                        |
| `MCP_SCOPE`      | `api://<OIDC_CLIENT_ID>/Bookings.ReadWrite` | Scope advertised to MCP clients (see [MCP server](#mcp-server)) |

To start over, stop the server and delete `booking.db`.

## Sign in with Microsoft (Entra ID)

The login screen has a **Sign in with Microsoft** link. These four variables are required; the server refuses to start without them.

| Variable             | Example                                              |
|----------------------|------------------------------------------------------|
| `OIDC_ISSUER`        | `https://login.microsoftonline.com/<tenant-id>/v2.0` (never `/common`) |
| `OIDC_CLIENT_ID`     | the app registration's client id                     |
| `OIDC_CLIENT_SECRET` | the app registration's client secret                 |
| `OIDC_REDIRECT_URI`  | `http://localhost:3000/api/callback`                 |

`npm run dev` loads them from a `.env` file in the repo root if one exists. `.env` is git-ignored; never commit it or paste the secret anywhere else.

One-time setup in the Entra admin center (done by a person):

1. Use a tenant you administer (a free Azure account gives one).
2. **App registrations → New registration**: single tenant, platform **Web**, redirect URI `http://localhost:3000/api/callback` (deployed: `https://<host>/api/callback`).
3. **Certificates & secrets → New client secret**. Put the four values above in `.env`. Secrets expire (at most 24 months).
4. **App roles → Create app role**: display name and value `Admin`, allowed member type Users.
5. **Enterprise applications → the app → Properties**: Assignment required = Yes. Under **Users and groups**, add the people who may sign in and give admins the `Admin` role.

How it behaves:

- Users are matched by their Entra object id (`oid`). The display name comes from the `name` claim; if another user already has that name, a short id suffix is added.
- Clicking **Sign in with Microsoft** always shows the Microsoft account picker, so you can choose another account.
- Admin rights come from the `Admin` app role and are re-read on every sign-in.
- A Microsoft sign-in session lasts 15 minutes on the server, then the app signs in again silently (no prompt while the Microsoft session lives) and re-reads the role.
- **Known security gap:** removing the `Admin` role or disabling a user takes effect only at that next re-check, so up to 15 minutes later.

To try it locally without Entra, run the dev-only mock provider and point the app at it:

```sh
MOCK_PORT=8090 MOCK_ROLES=Admin node server/mock-oidc.ts
OIDC_ISSUER=http://localhost:8090 OIDC_CLIENT_ID=mock-client OIDC_CLIENT_SECRET=mock-secret OIDC_REDIRECT_URI=http://localhost:3000/api/callback npm run dev
```

## MCP server

MCP clients (Claude Code, Claude Desktop, other agents) can use the app at `/mcp` as the signed-in Microsoft user, with exactly that user's permissions in the web UI. The server speaks MCP over Streamable HTTP (JSON responses, no SSE, no sessions): protocol `2026-07-28` statelessly, and `2025-11-25` / `2025-06-18` clients through `initialize`.

Entra ID is the authorization server; this app only validates its access tokens. Clients find it through `GET /.well-known/oauth-protected-resource`. A token is accepted only if it is signed by the issuer's keys, `iss` is `OIDC_ISSUER`, `aud` is `OIDC_CLIENT_ID`, `scp` contains `Bookings.ReadWrite`, it has not expired, and it was issued **at most 15 minutes ago**. The 15-minute rule makes clients refresh their token, which re-reads the `Admin` role and fails for disabled users, so the revocation gap stays the same as for web sessions. Each user may make 60 requests per minute; more get `429` with `Retry-After`.

Tools:

| Tool | Who | Arguments | Does |
|---|---|---|---|
| `list_rooms` | anyone | – | rooms with id and name |
| `list_bookings` | anyone | `from`, `to` | bookings overlapping the range, with room and user names |
| `my_bookings` | anyone | – | your ongoing and upcoming bookings, soonest first |
| `find_free_rooms` | anyone | `start`, `end` | rooms with no booking in the range |
| `book_room` | anyone | `roomId`, `start`, `end` | books the room for you; fails on a clash |
| `cancel_booking` | owner or admin | `bookingId` | cancels the booking |
| `create_room` | admin | `name` | adds a room |
| `rename_room` | admin | `roomId`, `name` | renames a room |
| `delete_room` | admin | `roomId` | deletes a room and its bookings |

Times are ISO 8601 date-times, as in the REST API. Non-admins do not see the admin tools; calling one anyway fails with the same error as the REST API.

One-time Entra setup on the existing app registration (done by a person):

1. **Manifest**: set `requestedAccessTokenVersion` to `2`.
2. **Expose an API**: set the Application ID URI to `api://<client-id>` and add the delegated scope `Bookings.ReadWrite`.
3. **Authentication**: add a platform for the MCP client's redirect URI (Claude Code: `http://localhost:<port>/callback`), and allow public client flows if the client uses PKCE without a secret.
4. **API permissions**: add the app's own `Bookings.ReadWrite` permission and grant admin consent.

Entra supports neither Dynamic Client Registration nor Client ID Metadata Documents, so clients use the app's pre-registered client id. Claude Code:

```sh
claude mcp add --transport http booking https://<host>/mcp --client-id <client-id> --callback-port <port>
```

Check these flags against the current Claude Code docs. If the Application ID URI is not `api://<client-id>`, set `MCP_SCOPE` to the full scope.

## Tests

```sh
npm test
```

Runs the API tests in `server/app.test.ts`.
