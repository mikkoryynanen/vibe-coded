# Agent instructions

Desk booking app: React UI (Vite) + plain Node HTTP API on built-in `node:sqlite`. See `README.md` for features and setup.

## Layout

- `server/app.ts` — `createHandler`: all API routes, sessions, authorization checks
- `server/db.ts` — schema (`openDb`), admin seeding, password hashing
- `server/index.ts` — entry point; serves API + Vite dev middleware on one port
- `server/app.test.ts` — API tests
- `client/App.tsx` — the whole UI; `client/styles.css` — styles

## Commands

- `npm run dev` — run the app at http://localhost:3000
- `npm test` — API tests (`node:test`)
- `npm run build` — typecheck (`tsc`) + production build

## Definition of done

1. `npm test` passes.
2. `npm run build` passes (this is the typecheck).
3. Every API behavior change has a test in `server/app.test.ts`.

## Conventions

- Node 24 runs `.ts` directly (type stripping): no enums, namespaces or parameter properties (`erasableSyntaxOnly` enforces this).
- Relative imports keep the `.ts`/`.tsx` extension; type-only imports use `import type` (`verbatimModuleSyntax`).
- Prefer Node built-ins (`node:sqlite`, `node:crypto`, `node:test`). No new dependencies without asking.
- Authorization lives in `server/app.ts`; never rely on the client to hide admin actions.
- Planned, not built yet: auth moves to OIDC via Entra ID with this server as BFF. Don't extend the password login in ways that block that.

## Files agents may touch

| Zone | Paths |
|---|---|
| Edit freely | `client/**`, `server/**`, `README.md`, `AGENTS.md` |
| Ask first | `package.json`, `package-lock.json`, `tsconfig.json`, `vite.config.ts`, `index.html`, `.gitignore` |
| Never touch | `*.db` (real data), `dist/**`, `node_modules/**`, `.env*` |

## Git

- One branch per task; never commit straight to `master`.
- No AI co-author trailers or "Generated with" lines in commits or PRs.
- Never commit secrets, `.db` files or build output.
