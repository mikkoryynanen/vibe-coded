// Preloaded by `npm run dev` (--import) to read .env. Not --env-file-if-exists: under --watch-path it makes Node
// restart on any file change in the repo root, and Vite's cache writes in node_modules/.vite then restart-loop the server.
import { existsSync } from 'node:fs';

if (existsSync('.env')) process.loadEnvFile('.env');
