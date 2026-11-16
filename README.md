# Desk Booking

Small team desk/room booking app. Users book time slots; admins add, rename and delete rooms.

Requires Node 24+ (the API runs `.ts` directly and uses built-in `node:sqlite`).

```sh
npm install
npm run dev   # app on http://localhost:3000 (API + UI); first run creates booking.db and prints the admin password
npm test      # API tests
```

Set `ADMIN_PASSWORD` before the first run to choose the admin password. `DB_PATH` and `PORT` are optional.

- Only admins can add users (no self-registration). Any logged-in user can book. Overlapping bookings for the same room are rejected; back-to-back is fine.
- Users can cancel their own bookings; admins can cancel any.
- Deleting a room deletes its bookings.
