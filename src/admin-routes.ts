import { Router, json, type Express, type Request, type Response } from 'express';
import { AdminAuth, clearAdminCookie, readAdminCookie, setAdminCookie } from './admin-auth.js';
import { ADMIN_PATH } from './admin-files.js';
import type { AuditStore } from './audit-store.js';
import { ACTIONS, getCatalogMetrics, MODULES } from './catalog.js';
import { CloudflareClient, type CloudflareClientOptions } from './cloudflare-client.js';
import type { CredentialStore, VerificationDetails } from './credential-store.js';
import { errorMessage, HttpError } from './errors.js';
import type { LinkStore } from './link-store.js';
import { z } from 'zod';

const loginSchema = z.strictObject({ password: z.string() });
const passwordSchema = z.strictObject({ currentPassword: z.string(), newPassword: z.string() });
const credentialsSchema = z.strictObject({
  apiToken: z.string().trim().min(1).max(4_096).regex(/^[A-Za-z0-9._~+/=\-]+$/),
  defaultAccountId: z.string().trim().toLowerCase().regex(/^[0-9a-f]{32}$/).optional(),
  skipVerify: z.boolean().optional(),
});
const auditLimit = z.string().regex(/^\d{1,9}$/).transform(Number);

export interface AdminRoutesOptions {
  auth: AdminAuth;
  credentials: CredentialStore;
  links: LinkStore;
  audit: AuditStore;
  publicOrigin?: string;
  requestOrigin: (req: Request) => string;
  disconnectLink: (linkId: string) => Promise<void>;
  clientOptions?: Pick<CloudflareClientOptions, 'baseUrl' | 'fetchImpl'>;
  redact: (text: string) => string;
}

function parse<T extends z.ZodType>(schema: T, input: unknown, message: string): z.output<T> {
  const result = schema.safeParse(input);
  if (!result.success) throw new HttpError(400, message);
  return result.data;
}

async function inspectToken(client: CloudflareClient): Promise<{ details: VerificationDetails; zonesError: string | null }> {
  const result = await client.verifyToken();
  const now = Date.now();
  if (result.status !== 'active' || (result.expires_on && Date.parse(result.expires_on) <= now)
    || (result.not_before && Date.parse(result.not_before) > now)) {
    throw new HttpError(422, 'Cloudflare API Token 当前不可用');
  }
  const [accounts, zones] = await Promise.allSettled([client.listAccounts(), client.listAllZones()]);
  const details: VerificationDetails = {
    verifiedAt: new Date(now).toISOString(), verifyStatus: 'ok', verifyMessage: 'Cloudflare API Token 验活通过',
  };
  if (accounts.status === 'fulfilled') details.cachedAccounts = accounts.value;
  if (zones.status === 'fulfilled') details.cachedZones = zones.value;
  return { details, zonesError: zones.status === 'rejected' ? errorMessage(zones.reason) : null };
}

function verificationError(error: unknown): unknown {
  // 管理台将 401 解释为登录过期，所以在此区分 Cloudflare 凭据错误。
  if (error instanceof HttpError && (error.status === 401 || error.status === 403)) {
    return new HttpError(422, error.message);
  }
  return error;
}

export function mountAdminRoutes(app: Express, options: AdminRoutesOptions): void {
  const { auth, credentials, links, audit, publicOrigin, requestOrigin, disconnectLink, redact } = options;
  const router = Router();
  const metrics = getCatalogMetrics();
  const catalog = {
    metrics,
    modules: MODULES.map(({ id, title, summary }) => ({
      module: id, title, summary, actionCount: ACTIONS.filter(action => action.module === id).length,
    })),
    actions: ACTIONS.map(({ action, module, title, summary, access, destructive, requiresConfirm }) => ({
      action, module, title, summary, access, destructive, requiresConfirm,
    })),
  };
  let zoneStatus: { revision: number; error: string | null } | undefined;

  function requireSession(req: Request): void {
    if (!auth.isAuthenticated(readAdminCookie(req))) throw new HttpError(401, '会话已失效，请重新登录');
  }

  function clientFor(req: Request, res: Response, token: string, defaultAccountId?: string): CloudflareClient {
    const cancel = new AbortController();
    res.once('close', () => cancel.abort());
    return new CloudflareClient({
      ...options.clientOptions,
      token, defaultAccountId,
      credentialStore: credentials,
      beforeRequest: () => requireSession(req),
      signal: AbortSignal.any([cancel.signal, AbortSignal.timeout(50_000)]),
    });
  }

  function currentZoneError(): string | null {
    return zoneStatus?.revision === credentials.revision ? zoneStatus.error : null;
  }

  function linkInput(body: unknown): unknown {
    if (body && typeof body === 'object' && 'name' in body && typeof body.name === 'string' && body.name.length <= 120) {
      return { ...body, name: redact(body.name).slice(0, 120) };
    }
    return body;
  }

  router.use((req, res, next) => {
    const expected = publicOrigin ?? requestOrigin(req);
    const origin = req.get('Origin');
    if ((origin !== undefined && origin !== expected) || req.get('Sec-Fetch-Site') === 'cross-site') {
      throw new HttpError(403, '管理台仅允许同源请求');
    }
    res.set('Cache-Control', 'no-store');
    next();
  });
  router.use(json({ limit: '256kb', inflate: false }));

  router.get('/session', (req, res) => {
    res.json({ authenticated: auth.isAuthenticated(readAdminCookie(req)), passwordSource: auth.passwordSource });
  });
  router.post('/login', (req, res) => {
    const { password } = parse(loginSchema, req.body, '请提供管理员口令');
    const session = auth.login(password, req.socket.remoteAddress ?? 'local', readAdminCookie(req));
    setAdminCookie(req, res, session, publicOrigin);
    res.json({ authenticated: true, passwordSource: auth.passwordSource });
  });
  router.post('/logout', (req, res) => {
    auth.logout(readAdminCookie(req));
    clearAdminCookie(req, res, publicOrigin);
    res.json({ ok: true });
  });

  router.use((req, _res, next) => {
    requireSession(req);
    next();
  });

  router.post('/password', async (req, res) => {
    const { currentPassword, newPassword } = parse(passwordSchema, req.body, '请提供当前口令和新口令');
    try {
      await auth.changePassword(currentPassword, newPassword);
    } catch (error) {
      if (error instanceof HttpError && error.status === 401) throw new HttpError(400, error.message);
      throw error;
    }
    const session = auth.login(newPassword, req.socket.remoteAddress ?? 'local');
    setAdminCookie(req, res, session, publicOrigin);
    res.json({ ok: true, message: '管理员口令已更新' });
  });

  router.get('/overview', (_req, res) => {
    res.json({
      token: credentials.getPublicStatus(),
      zones: credentials.getCachedZones(),
      zonesError: currentZoneError(),
      stats: { ...links.stats(), ...metrics },
    });
  });

  router.post('/credentials', async (req, res) => {
    const { apiToken, defaultAccountId, skipVerify } = parse(credentialsSchema, req.body, 'Cloudflare API Token 或默认账号 ID 格式无效');
    const revision = credentials.revision;
    let details: VerificationDetails = { verifyStatus: 'skipped', verifyMessage: '已跳过在线验活' };
    let zonesError: string | null = null;
    if (!skipVerify) {
      try {
        ({ details, zonesError } = await inspectToken(clientFor(req, res, apiToken, defaultAccountId)));
      } catch (error) {
        throw verificationError(error);
      }
    }
    requireSession(req);
    await credentials.saveToken(apiToken, { ...details, defaultAccountId: defaultAccountId ?? null }, revision);
    zoneStatus = { revision: revision + 1, error: zonesError };
    res.json({ token: credentials.getPublicStatus(), message: skipVerify ? 'API Token 已加密保存' : 'API Token 已验活并加密保存' });
  });

  router.post('/credentials/verify', async (req, res) => {
    const { token } = credentials.getActiveToken();
    if (!token) throw new HttpError(400, '尚未配置 Cloudflare API Token');
    const revision = credentials.revision;
    let details: VerificationDetails;
    let zonesError: string | null;
    try {
      ({ details, zonesError } = await inspectToken(clientFor(req, res, token)));
    } catch (error) {
      requireSession(req);
      const updated = await credentials.updateVerification({
        verifyStatus: 'error', verifyMessage: redact(errorMessage(error, [token])),
      }, token, revision);
      if (!updated) throw new HttpError(409, '验活期间凭据已更改，请重试');
      throw verificationError(error);
    }
    requireSession(req);
    if (!await credentials.updateVerification(details, token, revision)) {
      throw new HttpError(409, '验活期间凭据已更改，请重试');
    }
    zoneStatus = { revision, error: zonesError };
    res.json({ token: credentials.getPublicStatus(), message: 'Cloudflare API Token 验活通过' });
  });

  router.delete('/credentials', async (_req, res) => {
    await credentials.clearToken();
    res.json({ token: credentials.getPublicStatus(), message: '已清除本地加密保存的 API Token' });
  });

  router.get('/zones', async (req, res) => {
    const { token } = credentials.getActiveToken();
    if (req.query.refresh === '1' && token) {
      const revision = credentials.revision;
      let zonesError: string | null = null;
      try {
        const cachedZones = await clientFor(req, res, token).listAllZones();
        requireSession(req);
        await credentials.updateVerification({ cachedZones }, token, revision);
      } catch (error) {
        requireSession(req);
        zonesError = redact(errorMessage(error, [token]));
      }
      if (credentials.revision === revision) zoneStatus = { revision, error: zonesError };
    }
    res.json({ zones: credentials.getCachedZones(), error: currentZoneError() });
  });

  router.get('/catalog', (_req, res) => res.json(catalog));
  const originForLink = (req: Request) => publicOrigin ?? requestOrigin(req);
  router.get('/links', (req, res) => res.json({ links: links.list(originForLink(req)) }));
  router.post('/links', async (req, res) => {
    const link = await links.create(linkInput(req.body), originForLink(req));
    res.status(201).json({ link });
  });
  router.patch('/links/:id', async (req, res) => {
    const link = await links.update(req.params.id, linkInput(req.body), originForLink(req));
    await disconnectLink(link.id);
    res.json({ link });
  });
  router.delete('/links/:id', async (req, res) => {
    const link = await links.revoke(req.params.id, originForLink(req));
    await disconnectLink(link.id);
    res.json({ link });
  });
  router.get('/audit', (req, res) => {
    const limit = req.query.limit === undefined ? undefined : parse(auditLimit, req.query.limit, '审计记录条数无效');
    res.json({ records: audit.list(limit) });
  });
  app.use(`${ADMIN_PATH}/api`, router);
}
