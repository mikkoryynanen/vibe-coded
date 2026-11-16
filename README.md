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

## Tests

```sh
npm test
```

Runs the API tests in `server/app.test.ts`.
