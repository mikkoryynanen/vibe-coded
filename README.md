# Desk Booking

A small web app for a team to book desks or meeting rooms by time slot.

## Features

- **Log in** with a name and password. There is no self-registration: an admin creates every account.
- **Bookings** (all users): pick a day, see each room's bookings for that day, and book a room for a start–end time.
  - Overlapping bookings for the same room are rejected; back-to-back bookings are fine.
  - You can cancel your own bookings. Admins can cancel anyone's.
- **Manage rooms** (admins only): add, rename and delete rooms. Deleting a room also deletes its bookings.
- **Add user** (admins only): create new user accounts.

The UI is React (Vite); the API is a plain Node HTTP server with a built-in SQLite database (`booking.db`).

## Requirements

- Node.js 24 or newer (the server runs `.ts` files directly and uses the built-in `node:sqlite`).

## Running

```sh
npm install
npm run dev
```

Open http://localhost:3000. One server serves both the API (`/api/...`) and the UI, with hot reload.

On the first run the app creates `booking.db` and an `admin` account, and prints the admin password in the terminal:

```
Created admin account -> name: admin, password: ...
```

Log in as `admin`, add some rooms under **Manage rooms**, and create users under **Add user**.

## Configuration

Optional environment variables:

| Variable         | Default      | Purpose                                                          |
|------------------|--------------|------------------------------------------------------------------|
| `ADMIN_PASSWORD` | random       | Admin password, used only when the admin account is first created |
| `DB_PATH`        | `booking.db` | SQLite database file                                             |
| `PORT`           | `3000`       | HTTP port                                                        |

To start over, stop the server and delete `booking.db`.

## Tests

```sh
npm test
```

Runs the API tests in `server/app.test.ts`.
