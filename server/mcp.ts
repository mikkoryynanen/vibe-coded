import type { IncomingMessage, ServerResponse } from 'node:http';
import { createBearerAuth, MCP_SCOPE_NAME } from './bearer.ts';
import { type ActingUser, type Body, HttpError, readJson, type Service } from './service.ts';

type McpConfig = {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  jwksUri: () => Promise<string | undefined>;
};

type Tool = {
  name: string;
  description: string;
  admin?: boolean;
  inputSchema: Record<string, unknown>;
  annotations: Record<string, boolean>;
  run: (user: ActingUser, args: Body) => unknown;
};

const LATEST = '2026-07-28';
const LEGACY = ['2025-11-25', '2025-06-18'];
const SERVER_INFO = { name: 'desk-booking', version: '1.0.0' };
const META = 'io.modelcontextprotocol/';

class RpcError extends Error {
  status: number;
  code: number;
  data?: unknown;
  constructor(status: number, code: number, message: string, data?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.data = data;
  }
}

const isObject = (v: unknown): v is Body => typeof v === 'object' && v !== null && !Array.isArray(v);
const header = (req: IncomingMessage, name: string) => {
  const v = req.headers[name];
  return Array.isArray(v) ? v.join(',') : v;
};
const decodeName = (v: string) => {
  const b64 = v.match(/^=\?base64\?(.*)\?=$/)?.[1];
  return b64 === undefined ? v : Buffer.from(b64, 'base64').toString('utf8');
};
const mismatch = (name: string, got: string | undefined, want: unknown) =>
  new RpcError(400, -32020, got === undefined ? `Header mismatch: missing ${name} header` : `Header mismatch: ${name} header value '${got}' does not match body value '${want}'`);
const unsupported = (requested: unknown) =>
  new RpcError(400, -32022, 'Unsupported protocol version', { supported: [LATEST, ...LEGACY], requested });

const send = (res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}) => {
  if (body === undefined) res.writeHead(status, headers).end();
  else res.writeHead(status, { 'Content-Type': 'application/json', ...headers }).end(JSON.stringify(body));
};

const tools: Tool[] = [];

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

  async function readMessage(req: IncomingMessage) {
    let msg: Body;
    try {
      msg = await readJson(req);
    } catch (e) {
      if (!(e instanceof HttpError)) throw e;
      if (e.status === 413) throw new RpcError(413, -32600, 'Request too large');
      if (e.message === 'Invalid JSON') throw new RpcError(400, -32700, 'Parse error');
      throw new RpcError(400, -32600, 'Invalid Request');
    }
    const validId = typeof msg.id === 'string' || (typeof msg.id === 'number' && Number.isFinite(msg.id));
    if (msg.jsonrpc !== '2.0' || typeof msg.method !== 'string' || ('id' in msg && !validId))
      throw new RpcError(400, -32600, 'Invalid Request');
    if (msg.params !== undefined && !isObject(msg.params)) throw new RpcError(400, -32602, 'Invalid params');
    return msg as Body & { method: string; params?: Body };
  }

  /** Checks the 2026-07-28 per-request metadata and headers, or the legacy version header. Returns true for 2026-07-28. */
  function checkVersion(req: IncomingMessage, method: string, params: Body) {
    const meta = isObject(params._meta) ? params._meta : {};
    const requested = meta[`${META}protocolVersion`];
    const headerVersion = header(req, 'mcp-protocol-version');
    if (requested === undefined && headerVersion !== LATEST) {
      if (headerVersion === undefined) throw mismatch('MCP-Protocol-Version', undefined, undefined);
      if (!LEGACY.includes(headerVersion)) throw unsupported(headerVersion);
      return false;
    }
    if (typeof requested !== 'string') throw new RpcError(400, -32602, `Missing params._meta["${META}protocolVersion"]`);
    if (requested !== LATEST) throw unsupported(requested);
    if (headerVersion !== requested) throw mismatch('MCP-Protocol-Version', headerVersion, requested);
    const headerMethod = header(req, 'mcp-method');
    if (headerMethod !== method) throw mismatch('Mcp-Method', headerMethod, method);
    if (method === 'tools/call') {
      const headerName = header(req, 'mcp-name');
      if (headerName === undefined || decodeName(headerName) !== params.name) throw mismatch('Mcp-Name', headerName, params.name);
    }
    if (!isObject(meta[`${META}clientCapabilities`])) throw new RpcError(400, -32602, `Missing params._meta["${META}clientCapabilities"]`);
    return true;
  }

  function callTool(user: ActingUser, params: Body) {
    const tool = tools.find((t) => t.name === params.name);
    if (!tool) throw new RpcError(400, -32602, `Unknown tool: ${String(params.name)}`);
    const args = params.arguments ?? {};
    if (!isObject(args)) throw new RpcError(400, -32602, 'Tool arguments must be an object');
    try {
      const out = tool.run(user, args);
      return { content: [{ type: 'text', text: JSON.stringify(out ?? { ok: true }) }] };
    } catch (e) {
      let message = 'Server error';
      if (e instanceof HttpError) message = e.message;
      else if (e instanceof Error && e.message.includes('UNIQUE')) message = 'That name is already taken';
      else console.error(e);
      return { content: [{ type: 'text', text: message }], isError: true };
    }
  }

  async function handle(req: IncomingMessage, res: ServerResponse, method: string) {
    if (method !== 'POST') return send(res, 405, { error: 'Method not allowed' }, { Allow: 'POST' });
    const user = await authenticate(req);
    if (!user) return send(res, 401, { error: 'Unauthorized' }, { 'WWW-Authenticate': challenge });

    let id: unknown = null;
    let modern = false;
    let legacy = false;
    try {
      const msg = await readMessage(req);
      id = msg.id ?? null;
      const params = msg.params ?? {};
      if (msg.method === 'initialize') {
        const v = params.protocolVersion;
        const protocolVersion = typeof v === 'string' && LEGACY.includes(v) ? v : LEGACY[0];
        return send(res, 200, { jsonrpc: '2.0', id, result: { protocolVersion, capabilities: { tools: {} }, serverInfo: SERVER_INFO } });
      }
      if (msg.method === 'notifications/initialized') return send(res, 202);
      modern = checkVersion(req, msg.method, params);
      legacy = !modern;
      if (!('id' in msg)) return send(res, 202);

      let result: Body;
      if (msg.method === 'ping') result = {};
      else if (msg.method === 'tools/list')
        result = { tools: tools.filter((t) => user.admin || !t.admin).map(({ run: _run, admin: _admin, ...t }) => t) };
      else if (msg.method === 'tools/call') result = callTool(user, params);
      else throw new RpcError(404, -32601, 'Method not found');
      if (modern) result._meta = { [`${META}serverInfo`]: SERVER_INFO };
      send(res, 200, { jsonrpc: '2.0', id, result });
    } catch (e) {
      if (!(e instanceof RpcError)) throw e;
      // Before 2026-07-28 a 404 meant "session gone", so legacy clients get JSON-RPC errors with 200 once the version is known.
      send(res, legacy ? 200 : e.status, { jsonrpc: '2.0', id, error: { code: e.code, message: e.message, ...(e.data !== undefined && { data: e.data }) } });
    }
  }

  return { metadata, handle };
}
