import { createServer } from 'node:http';
import { createServer as createVite } from 'vite';
import { openDb } from './db.ts';
import { createHandler, oidcConfigFromEnv } from './app.ts';

// Microsoft sign-in is the only way in, so the app refuses to start without its config.
const oidc = (() => {
  try {
    return oidcConfigFromEnv(process.env);
  } catch (e) {
    console.error((e as Error).message);
    process.exit(1);
  }
})();
const db = openDb(process.env.DB_PATH ?? 'booking.db');
const api = createHandler(db, oidc);
const port = Number(process.env.PORT ?? 3000);

// One server: /api goes to the API, everything else to Vite (UI with hot reload).
const server = createServer((req, res) => (req.url?.startsWith('/api') ? api(req, res) : vite.middlewares(req, res)));
const vite = await createVite({ server: { middlewareMode: true, hmr: { server } }, appType: 'spa' });
server.listen(port, () => console.log(`App on http://localhost:${port}`));
