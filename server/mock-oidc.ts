// Dev-only local OIDC provider for trying "Sign in with Microsoft" without Entra. Never used in production.
// Run: MOCK_PORT=8090 MOCK_ROLES=Admin node server/mock-oidc.ts, then start the app with the printed OIDC_* vars.
import { OAuth2Server } from 'oauth2-mock-server';

const port = Number(process.env.MOCK_PORT ?? 8090);
const roles = (process.env.MOCK_ROLES ?? '').split(',').filter(Boolean);

const server = new OAuth2Server();
await server.issuer.keys.generate('RS256');
server.service.on('beforeTokenSigning', (token) => {
  Object.assign(token.payload, { oid: '00000000-0000-4000-8000-000000000001', name: 'Mock User', preferred_username: 'mock.user@example.com', roles });
});
await server.start(port, 'localhost');
console.log(`Mock OIDC provider on ${server.issuer.url} (roles: ${roles.join(',') || 'none'})`);
console.log(`OIDC_ISSUER=${server.issuer.url} OIDC_CLIENT_ID=mock-client OIDC_CLIENT_SECRET=mock-secret OIDC_REDIRECT_URI=http://localhost:<app port>/api/callback`);
