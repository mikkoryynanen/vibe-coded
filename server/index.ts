import { createServer } from 'node:http';
import { createServer as createVite } from 'vite';
import { openDb, seedAdmin } from './db.ts';
import { createHandler } from './app.ts';

const db = openDb(process.env.DB_PATH ?? 'booking.db');
seedAdmin(db);
const { OIDC_ISSUER: issuer, OIDC_CLIENT_ID: clientId, OIDC_CLIENT_SECRET: clientSecret, OIDC_REDIRECT_URI: redirectUri } = process.env;
// Until password login is removed (job 003), missing OIDC config only disables "Sign in with Microsoft".
const api = createHandler(db, issuer && clientId && clientSecret && redirectUri ? { issuer, clientId, clientSecret, redirectUri } : undefined);
const port = Number(process.env.PORT ?? 3000);

// One server: /api goes to the API, everything else to Vite (UI with hot reload).
const server = createServer((req, res) => (req.url?.startsWith('/api') ? api(req, res) : vite.middlewares(req, res)));
const vite = await createVite({ server: { middlewareMode: true, hmr: { server } }, appType: 'spa' });
server.listen(port, () => console.log(`App on http://localhost:${port}`));
