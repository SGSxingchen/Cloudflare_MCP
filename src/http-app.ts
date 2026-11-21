import { randomUUID } from 'node:crypto';
import { isIPv4 } from 'node:net';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import express, { type ErrorRequestHandler, type Request, type Response } from 'express';
import { AdminAuth } from './admin-auth.js';
import { mountAdminFiles } from './admin-files.js';
import { mountAdminRoutes } from './admin-routes.js';
import { AuditStore } from './audit-store.js';
import type { CloudflareClientOptions } from './cloudflare-client.js';
import { CredentialStore } from './credential-store.js';
import { errorMessage, HttpError, redactSecrets } from './errors.js';
import { LinkStore, type LinkAuthorization } from './link-store.js';
import { createMcpServer, FULL_ACCESS, MCP_INFO, MCP_TOOL_COUNT, type McpScope } from './mcp-tools.js';
import { ACTIONS } from './catalog.js';
import { allowedOriginsFrom, publicOriginFrom } from './runtime.js';

const MAX_SESSIONS = 512;
const MAX_PARALLEL_REQUESTS = 16;
const SESSION_IDLE_MS = 30 * 60_000;
const SESSION_SWEEP_MS = 30_000;
const LINK_ENDPOINT = '/cloudflare-mcp/:token/mcp';
const LOCAL_ENDPOINT = '/mcp';

export interface HttpAppOptions {
  stateDir: string;
  adminPassword?: string;
  publicOrigin?: string;
  allowedOrigins?: string | readonly string[];
  envToken?: string;
  envAccountId?: string;
  enableUnauthLocalMcp?: boolean;
  clientOptions?: Pick<CloudflareClientOptions, 'baseUrl' | 'fetchImpl'>;
}

interface Session {
  id: string;
  linkId?: string;
  linkRevision?: number;
  transport: StreamableHTTPServerTransport;
  pending: number;
  touchedAt: number;
}

function requestOrigin(req: Request): string {
  const host = req.get('Host');
  try {
    if (host && !/[@%,/\\?#\s]/u.test(host)) return publicOriginFrom(`${req.protocol}://${host}`)!;
  } catch {
    // 无效主机名不进入请求处理。
  }
  throw new HttpError(400, '请求主机名无效');
}

export function isLoopbackHost(host: string): boolean {
  const value = host.toLowerCase();
  return value === 'localhost' || value === '::1' || value === '[::1]'
    || (value.startsWith('127.') && isIPv4(value));
}

function isLocalRequest(req: Request, origin: string): boolean {
  const remote = req.socket.remoteAddress?.replace(/^::ffff:/i, '');
  return !!remote && remote !== 'localhost' && isLoopbackHost(remote)
    && isLoopbackHost(new URL(origin).hostname)
    && !['Forwarded', 'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto', 'CF-Connecting-IP']
      .some(header => req.get(header) !== undefined);
}

function isMcpPath(path: string): boolean {
  return path === LOCAL_ENDPOINT || path === `${LOCAL_ENDPOINT}/` || path.startsWith('/cloudflare-mcp/');
}

function sendMcpError(res: Response, status: number, message: string): void {
  const code = status === 404 ? -32001 : -32000;
  res.status(status).json({ jsonrpc: '2.0', error: { code, message }, id: null });
}

export async function createHttpApp(options: HttpAppOptions) {
  const publicOrigin = publicOriginFrom(options.publicOrigin);
  const allowedOrigins = allowedOriginsFrom(options.allowedOrigins);
  const [auth, credentials, links, audit] = await Promise.all([
    AdminAuth.open(options.stateDir, options.adminPassword),
    CredentialStore.open(options.stateDir, options),
    LinkStore.open(options.stateDir),
    AuditStore.open(options.stateDir),
  ]);
  const redact = (value: string) => redactSecrets(auth.redact(value), [
    credentials.getActiveToken().token ?? '', options.envToken?.trim() ?? '',
  ]);

  const app = express();
  app.disable('x-powered-by');
  app.set('case sensitive routing', true);
  app.use((_req, res, next) => {
    res.set({
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    });
    next();
  });

  const sessions = new Map<string, Session>();
  let closing: Promise<void> | undefined;

  function currentGrant(session: Session): LinkAuthorization | undefined {
    return session.linkId ? links.findActiveById(session.linkId) : undefined;
  }

  function isCurrent(session: Session): boolean {
    return !session.linkId || currentGrant(session)?.revision === session.linkRevision;
  }

  async function closeSession(session: Session): Promise<void> {
    if (!sessions.delete(session.id)) return;
    try {
      await session.transport.close();
    } catch {
      console.error('关闭 Cloudflare MCP 会话失败');
    }
  }

  const sweep = setInterval(() => {
    const now = performance.now();
    for (const session of sessions.values()) {
      if (!isCurrent(session) || now - session.touchedAt >= SESSION_IDLE_MS) void closeSession(session);
    }
  }, SESSION_SWEEP_MS);
  sweep.unref();

  async function disconnectLink(linkId: string): Promise<void> {
    await Promise.all([...sessions.values()].filter(session => session.linkId === linkId && !isCurrent(session))
      .map(closeSession));
  }

  app.get('/health', (_req, res) => {
    res.status(closing ? 503 : 200).json({
      status: closing ? 'stopping' : 'ok',
      service: MCP_INFO.name,
      version: MCP_INFO.version,
      disclosureMode: 'progressive',
      progressiveTools: MCP_TOOL_COUNT,
      totalActions: ACTIONS.length,
      tokenConfigured: credentials.getPublicStatus().configured,
    });
  });
  mountAdminRoutes(app, { auth, credentials, links, audit, publicOrigin, requestOrigin, disconnectLink, redact,
    clientOptions: options.clientOptions });
  mountAdminFiles(app);

  function checkMcpOrigin(req: Request, res: Response, local: boolean): void {
    const servingOrigin = requestOrigin(req);
    if (local && !isLocalRequest(req, servingOrigin)) throw new HttpError(403, '本地 MCP 接口仅允许回环访问');
    res.vary('Origin');
    const origin = req.get('Origin');
    if (origin === undefined) return;
    let normalized: string | undefined;
    try {
      normalized = publicOriginFrom(origin);
    } catch {
      throw new HttpError(403, 'MCP 请求来源不受信任');
    }
    const sameOrigin = local ? servingOrigin : publicOrigin ?? servingOrigin;
    if (normalized !== origin || (origin !== sameOrigin &&
      (local || (allowedOrigins !== '*' && !allowedOrigins?.has(origin))))) {
      throw new HttpError(403, 'MCP 请求来源不受信任');
    }
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Expose-Headers', 'Mcp-Session-Id, MCP-Protocol-Version');
  }

  async function openSession(grant?: LinkAuthorization, token?: string): Promise<Session> {
    if (sessions.size >= MAX_SESSIONS) throw new HttpError(503, 'MCP 会话数量已达到上限，请稍后重试');
    const id = randomUUID();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => id, keepAliveMs: 15_000 });
    const session: Session = {
      id, transport, linkId: grant?.id, linkRevision: grant?.revision, pending: 0, touchedAt: performance.now(),
    };
    const getScope = (): McpScope => {
      if (!sessions.has(id)) throw new HttpError(403, 'MCP 会话已断开');
      if (!grant) return FULL_ACCESS;
      const current = currentGrant(session);
      if (!current || current.revision !== session.linkRevision) throw new HttpError(403, '链接授权已失效');
      return {
        access_level: current.access_level, allowed_modules: current.allowed_modules, allowed_zones: current.allowed_zones,
        linkId: current.id, linkName: current.name, linkToken: token,
      };
    };
    const server = createMcpServer({
      credentials, auditStore: audit, getScope, redact, clientOptions: options.clientOptions,
      onToolCompleted: grant ? () => links.recordUsage(grant.id) : undefined,
    });
    transport.onclose = () => { sessions.delete(id); };
    sessions.set(id, session);
    try {
      await server.connect(transport);
      if (!sessions.has(id) || !isCurrent(session)) throw new HttpError(404, 'MCP 会话已失效');
      return session;
    } catch (error) {
      await closeSession(session);
      throw error;
    }
  }

  async function handleMcp(req: Request, res: Response, token?: string): Promise<void> {
    if (closing) throw new HttpError(503, 'MCP 服务正在关闭');
    if (req.method === 'POST' && (!req.is('application/json') || !req.body || Array.isArray(req.body))) {
      throw new HttpError(400, 'MCP POST 请求必须提供单条 JSON 消息');
    }
    const grant = token === undefined ? undefined : links.findActiveByToken(token);
    if (token !== undefined && !grant) throw new HttpError(404, 'MCP 链接不存在或已失效');
    const id = req.get('Mcp-Session-Id');
    let session: Session;
    if (id !== undefined) {
      const existing = sessions.get(id);
      if (!existing || existing.transport.sessionId !== id || existing.linkId !== grant?.id) {
        throw new HttpError(404, 'MCP 会话不存在或已失效');
      }
      if (existing.linkRevision !== grant?.revision || performance.now() - existing.touchedAt >= SESSION_IDLE_MS) {
        await closeSession(existing);
        throw new HttpError(404, 'MCP 会话不存在或已失效');
      }
      session = existing;
    } else {
      if (req.method !== 'POST' || !isInitializeRequest(req.body)) {
        throw new HttpError(400, '请先初始化 MCP 会话');
      }
      session = await openSession(grant, token);
    }

    if (session.pending >= MAX_PARALLEL_REQUESTS && req.method !== 'DELETE') {
      throw new HttpError(429, 'MCP 会话的并行请求过多');
    }
    session.pending += 1;
    session.touchedAt = performance.now();
    try {
      await session.transport.handleRequest(req, res, req.body);
    } finally {
      session.pending -= 1;
      if (id === undefined && (!session.transport.sessionId || res.statusCode >= 400 || !res.writableFinished)) {
        await closeSession(session);
      }
    }
  }

  const parseMcpJson = express.json({ limit: '256kb', inflate: false });
  function mountMcp(path: string, local: boolean) {
    app.all(path, (req, res, next) => {
      checkMcpOrigin(req, res, local);
      if (req.method === 'OPTIONS') {
        res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.set('Access-Control-Allow-Headers', 'Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID');
        res.status(204).end();
      } else if (!['GET', 'POST', 'DELETE'].includes(req.method)) {
        res.set('Allow', 'GET, POST, DELETE, OPTIONS');
        sendMcpError(res, 405, '该请求方法不受支持');
      } else {
        next();
      }
    }, parseMcpJson, (req, res) => {
      if (local) return handleMcp(req, res);
      if (typeof req.params.token !== 'string') throw new HttpError(404, 'MCP 链接不存在或已失效');
      return handleMcp(req, res, req.params.token);
    });
  }
  mountMcp(LINK_ENDPOINT, false);
  if (options.enableUnauthLocalMcp) mountMcp(LOCAL_ENDPOINT, true);

  app.use((req, res) => {
    if (isMcpPath(req.path)) sendMcpError(res, 404, '找不到 MCP 接口');
    else res.status(404).json({ error: '找不到该接口' });
  });
  const errorHandler: ErrorRequestHandler = (error: unknown, req, res, _next) => {
    if (res.destroyed || res.writableEnded) return;
    if (res.headersSent) {
      res.destroy();
      return;
    }
    let status = 500;
    let message = '服务处理请求时发生错误';
    if (error instanceof HttpError) {
      status = error.status;
      message = redact(errorMessage(error));
    } else if (error instanceof URIError || error instanceof SyntaxError) {
      status = 400;
      message = '请求路径或 JSON 无效';
    } else if (error && typeof error === 'object' && 'status' in error &&
      (error.status === 400 || error.status === 413 || error.status === 415)) {
      status = error.status;
      message = '请求内容过大或格式无效';
    } else {
      console.error('处理 Cloudflare MCP HTTP 请求失败');
    }
    if (isMcpPath(req.path)) sendMcpError(res, status, message);
    else res.status(status).json({ error: message });
  };
  app.use(errorHandler);

  return {
    app,
    close() {
      if (!closing) {
        clearInterval(sweep);
        closing = Promise.all([...sessions.values()].map(closeSession)).then(() => {});
      }
      return closing;
    },
  };
}
