import type { IncomingMessage, ServerResponse } from 'node:http';
import { createBearerAuth, MCP_SCOPE_NAME } from './bearer.ts';
import { type ActingUser, readJson, type Service } from './service.ts';

type McpConfig = {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  jwksUri: () => Promise<string | undefined>;
};

const send = (res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}) => {
  if (body === undefined) res.writeHead(status, headers).end();
  else res.writeHead(status, { 'Content-Type': 'application/json', ...headers }).end(JSON.stringify(body));
};

/** MCP over Streamable HTTP (JSON responses only) at /mcp, authenticated by Entra access tokens. */
export function createMcp(service: Service, cfg: McpConfig) {
  const origin = new URL(cfg.redirectUri).origin;
  const scope = cfg.scope || `api://${cfg.clientId}/${MCP_SCOPE_NAME}`;
  const challenge = `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource", scope="${scope}"`;
  const verifyToken = createBearerAuth(cfg);

  const metadata = () => ({
    resource: `${origin}/mcp`,
    authorization_servers: [cfg.issuer],
    scopes_supported: [scope],
    bearer_methods_supported: ['header'],
  });

  async function authenticate(req: IncomingMessage): Promise<ActingUser | undefined> {
    const token = req.headers.authorization?.match(/^Bearer +(\S+)$/i)?.[1];
    try {
      if (!token) throw new Error('No bearer token');
      return service.upsertOidcUser(await verifyToken(token));
    } catch (e) {
      console.error('MCP auth failed:', e instanceof Error ? e.message : 'unknown error');
    }
  }

  async function handle(req: IncomingMessage, res: ServerResponse, method: string) {
    if (method !== 'POST') return send(res, 405, { error: 'Method not allowed' }, { Allow: 'POST' });
    const user = await authenticate(req);
    if (!user) return send(res, 401, { error: 'Unauthorized' }, { 'WWW-Authenticate': challenge });
    const msg = await readJson(req);
    send(res, 404, { jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32601, message: 'Method not found' } });
  }

  return { metadata, handle };
}
