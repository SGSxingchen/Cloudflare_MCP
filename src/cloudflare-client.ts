import { domainToASCII } from 'node:url';
import type { CachedAccount, CachedZone, CredentialStore } from './credential-store.js';
import { HttpError } from './errors.js';

const DEFAULT_API_URL = 'https://api.cloudflare.com/client/v4';
const REQUEST_TIMEOUT_MS = 25_000;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const PAGE_SIZE = 50;
const MAX_PAGES = 200;
const ACCOUNT_CACHE_MS = 5 * 60_000;
const IDENTIFIER = /^[0-9a-f]{32}$/i;

type Query = Record<string, string | number | boolean | null | undefined>;
type JsonRecord = Record<string, unknown>;

export interface CloudflareClientOptions {
  credentialStore?: CredentialStore;
  token?: string;
  defaultAccountId?: string;
  fetchImpl?: typeof fetch;
  baseUrl?: string;
  beforeRequest?: () => void;
  signal?: AbortSignal;
}

export interface CloudflareRequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  query?: Query;
  body?: unknown;
  responseType?: 'text';
  contentType?: string;
}

export interface CloudflareResponse<T> {
  result: T;
  resultInfo?: Readonly<JsonRecord>;
}

export interface TokenVerification {
  id?: string;
  status: 'active' | 'disabled' | 'expired';
  expires_on?: string;
  not_before?: string;
}

interface AccountCache {
  token: string;
  id: string;
  expiresAt: number;
}

const accountCacheByStore = new WeakMap<CredentialStore, AccountCache>();

function record(value: unknown): JsonRecord | undefined {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) return value as JsonRecord;
}

export function zoneName(value: string): string | undefined {
  const candidate = value.trim().replace(/\.$/, '');
  if (!candidate || /[\s:/?#@\\%]/u.test(candidate)) return undefined;
  const ascii = domainToASCII(candidate).toLowerCase();
  if (ascii.length > 253 || !ascii.split('.').every(label => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i.test(label))) return undefined;
  return ascii;
}

function projectedAccount(value: unknown): CachedAccount | undefined {
  const account = record(value);
  if (typeof account?.id !== 'string' || !IDENTIFIER.test(account.id)) return undefined;
  if (typeof account.name !== 'string' || account.name.length > 256) return undefined;
  return { id: account.id.toLowerCase(), name: account.name };
}

function projectedZone(value: unknown): CachedZone | undefined {
  const zone = record(value);
  if (typeof zone?.id !== 'string' || !IDENTIFIER.test(zone.id) || typeof zone.name !== 'string') return undefined;
  const name = zoneName(zone.name);
  if (!name) return undefined;
  const result: CachedZone = { id: zone.id.toLowerCase(), name };
  if (typeof zone.status === 'string' && /^[a-z_]{1,32}$/.test(zone.status)) result.status = zone.status;
  const plan = record(zone.plan)?.name;
  if (typeof plan === 'string' && plan.length <= 128) result.plan = plan;
  if (Array.isArray(zone.name_servers)) {
    result.name_servers = zone.name_servers.slice(0, 32).flatMap(value => {
      const name = typeof value === 'string' ? zoneName(value) : undefined;
      return name ? [name] : [];
    });
  }
  const account = projectedAccount(zone.account);
  if (account) result.account = account;
  return result;
}

export function zoneAllowed(zone: { id: string; name: string }, allowedZones: readonly string[] | null): boolean {
  if (allowedZones === null) return true;
  const name = zoneName(zone.name);
  return allowedZones.some(value => value.toLowerCase() === zone.id.toLowerCase()
    || (name !== undefined && zoneName(value) === name));
}

function readEnvelope(text: string): JsonRecord | undefined {
  try {
    return record(JSON.parse(text));
  } catch {
    return undefined;
  }
}

function apiFailure(status: number, envelope?: JsonRecord): HttpError {
  const errors = Array.isArray(envelope?.errors) ? envelope.errors : [];
  const codes = errors.slice(0, 5).flatMap(error => {
    const code = record(error)?.code;
    return typeof code === 'number' && Number.isInteger(code) && code >= 1000 && code <= 999_999 ? [code] : [];
  });
  const suffix = codes.length ? `（Cloudflare 错误代码 ${codes.join('、')}）` : '';
  const messages: Partial<Record<number, string>> = {
    400: 'Cloudflare API 拒绝了请求参数',
    401: 'Cloudflare API 鉴权失败，请核对 API Token',
    403: 'Cloudflare API 拒绝访问，请核对 API Token 权限与资源范围',
    404: 'Cloudflare API 找不到该资源',
    409: 'Cloudflare API 报告资源冲突',
    429: 'Cloudflare API 请求过于频繁，请稍后重试',
  };
  // 上游错误原文可能反射凭据或请求内容，只转发结构化数字错误码。
  return new HttpError(status >= 400 && status < 500 ? status : 502,
    (messages[status] ?? 'Cloudflare API 请求失败') + suffix);
}

async function readResponse(response: Response, signal: AbortSignal): Promise<string | null> {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        cancel();
        return null;
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks, size).toString('utf8');
  } catch (error) {
    cancel();
    throw error;
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

function positiveInt(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return value;
}

function canContinue(info: Readonly<JsonRecord> | undefined, page: number, count: number): boolean {
  const totalPages = positiveInt(info?.total_pages);
  if (totalPages !== undefined) return page < totalPages;
  const perPage = positiveInt(info?.per_page) ?? PAGE_SIZE;
  const total = positiveInt(info?.total_count);
  if (total !== undefined) return page * perPage < total;
  return count >= perPage;
}

export class CloudflareClient {
  private readonly baseUrl: URL;
  private readonly fetchImpl: typeof fetch;
  private accountCache?: AccountCache;

  constructor(private readonly options: CloudflareClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    try {
      this.baseUrl = new URL(options.baseUrl ?? DEFAULT_API_URL);
      if (!['http:', 'https:'].includes(this.baseUrl.protocol) || this.baseUrl.username || this.baseUrl.password
        || this.baseUrl.search || this.baseUrl.hash) throw new Error();
      this.baseUrl.pathname = this.baseUrl.pathname.replace(/\/+$/, '') || '/';
    } catch {
      throw new Error('Cloudflare API 地址必须是无凭据、查询参数和片段的 HTTP 或 HTTPS 地址');
    }
  }

  async request<T = unknown>(path: string, options: CloudflareRequestOptions = {}): Promise<CloudflareResponse<T>> {
    return this.send<T>(this.activeToken(), path, options);
  }

  async verifyToken(): Promise<TokenVerification> {
    const token = this.activeToken();
    let raw: unknown;
    if (token.startsWith('cfat_')) {
      raw = (await this.send(token, `/accounts/${await this.accountIdFor(token)}/tokens/verify`)).result;
    } else {
      try {
        raw = (await this.send(token, '/user/tokens/verify')).result;
      } catch (error) {
        // 早期的账号 Token 与用户 Token 都没有前缀。已有默认账号时可尝试账号验活接口。
        const account = this.configuredAccount(token);
        if (!/^[a-z0-9_-]{40}$/i.test(token) || !account || !(error instanceof HttpError)
          || ![400, 401, 403].includes(error.status)) throw error;
        raw = (await this.send(token, `/accounts/${this.accountIdentifier(account)}/tokens/verify`)).result;
      }
    }
    const result = record(raw);
    const status = result?.status;
    if (!result || (status !== 'active' && status !== 'disabled' && status !== 'expired')) {
      throw new HttpError(502, 'Cloudflare API 未返回有效的令牌状态');
    }
    const verification: TokenVerification = { status };
    if (typeof result.id === 'string' && IDENTIFIER.test(result.id)) verification.id = result.id;
    if (typeof result.expires_on === 'string' && Number.isFinite(Date.parse(result.expires_on))) {
      verification.expires_on = result.expires_on;
    }
    if (typeof result.not_before === 'string' && Number.isFinite(Date.parse(result.not_before))) {
      verification.not_before = result.not_before;
    }
    return verification;
  }

  listAccounts(): Promise<CachedAccount[]> {
    return this.listPages('/accounts', {}, projectedAccount);
  }

  listAllZones(): Promise<CachedZone[]> {
    return this.listPages('/zones', {}, projectedZone);
  }

  async resolveZone(zoneIdOrName: string, allowedZones: readonly string[] | null = null): Promise<CachedZone> {
    const reference = zoneIdOrName.trim();
    const byId = IDENTIFIER.test(reference);
    const normalized = byId ? reference.toLowerCase() : zoneName(reference);
    if (!normalized) throw new HttpError(400, '请提供有效的域名或 32 位 zone_id');

    const forbidden = () => new HttpError(403, '此域名不在当前链接的允许范围内');
    if (allowedZones?.length === 0) throw forbidden();
    if (allowedZones !== null && !allowedZones.some(value => byId
      ? !IDENTIFIER.test(value) || value.toLowerCase() === normalized
      : IDENTIFIER.test(value) || zoneName(value) === normalized)) throw forbidden();

    if (byId) {
      let rawZone: unknown;
      try {
        rawZone = (await this.request(`/zones/${normalized}`)).result;
      } catch (error) {
        if (allowedZones !== null && error instanceof HttpError && error.status === 404) throw forbidden();
        throw error;
      }
      const zone = projectedZone(rawZone);
      if (!zone || zone.id !== normalized) throw new HttpError(502, 'Cloudflare API 返回的域名标识无效');
      if (!zoneAllowed(zone, allowedZones)) throw forbidden();
      return zone;
    }

    const candidates = await this.listPages('/zones', { name: normalized }, projectedZone);
    const matches = candidates.filter(zone => zone.name === normalized && zoneAllowed(zone, allowedZones));
    if (matches.length === 0) {
      if (allowedZones !== null) throw forbidden();
      throw new HttpError(404, 'Cloudflare API 找不到该域名');
    }
    if (matches.length !== 1) throw new HttpError(409, '找到多个同名域名，请改用明确的 zone_id');
    return matches[0];
  }

  async resolveAccountId(explicitAccountId?: string): Promise<string> {
    if (explicitAccountId !== undefined) return this.accountIdentifier(explicitAccountId);
    return this.accountIdFor(this.activeToken());
  }

  private accountIdentifier(value: string): string {
    if (!IDENTIFIER.test(value)) throw new HttpError(400, 'Account ID 必须是 32 位十六进制标识');
    return value.toLowerCase();
  }

  private configuredAccount(token: string): string | null | undefined {
    const store = this.options.credentialStore;
    return this.options.defaultAccountId ?? (store?.getActiveToken().token === token ? store?.getDefaultAccountId() : undefined);
  }

  private async accountIdFor(token: string): Promise<string> {
    const store = this.options.credentialStore;
    const activeStore = store?.getActiveToken().token === token ? store : undefined;
    const configured = this.configuredAccount(token);
    if (configured) return this.accountIdentifier(configured);

    const cache = activeStore ? accountCacheByStore.get(activeStore) : this.accountCache;
    if (cache?.token === token && cache.expiresAt > performance.now()) return cache.id;
    const previouslyDiscovered = activeStore?.getCachedAccounts()[0]?.id;
    if (previouslyDiscovered) return this.accountIdentifier(previouslyDiscovered);

    const { result } = await this.send<unknown>(token, '/accounts', { query: { page: 1, per_page: PAGE_SIZE } });
    if (!Array.isArray(result)) throw new HttpError(502, 'Cloudflare API 账号列表格式无效');
    if (result.length === 0) throw new HttpError(400, '未找到可用的 Cloudflare 账号，请指定 Account ID');
    const account = projectedAccount(result[0]);
    if (!account) throw new HttpError(502, 'Cloudflare API 返回的账号标识无效');
    const next = { token, id: account.id, expiresAt: performance.now() + ACCOUNT_CACHE_MS };
    if (activeStore?.getActiveToken().token === token) accountCacheByStore.set(activeStore, next);
    else this.accountCache = next;
    return account.id;
  }

  private activeToken(): string {
    const token = this.options.token ?? this.options.credentialStore?.getActiveToken().token;
    if (!token) throw new HttpError(503, '尚未配置 Cloudflare API Token');
    if (!/^[A-Za-z0-9._~+/=-]{1,4096}$/.test(token)) throw new HttpError(400, 'Cloudflare API Token 格式无效');
    return token;
  }

  private async listPages<T extends { id: string }>(
    path: string, query: Query, project: (value: unknown) => T | undefined,
  ): Promise<T[]> {
    const token = this.activeToken();
    const deadline = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    const rows = new Map<string, T>();
    for (let page = 1; page <= MAX_PAGES; page += 1) {
      const { result, resultInfo } = await this.send<unknown>(token, path, {
        query: { ...query, page, per_page: PAGE_SIZE },
      }, deadline);
      if (!Array.isArray(result) || result.length > PAGE_SIZE) throw new HttpError(502, 'Cloudflare API 分页结果格式无效');
      const reportedPage = positiveInt(resultInfo?.page);
      if (reportedPage !== undefined && reportedPage !== page) throw new HttpError(502, 'Cloudflare API 返回了错误的页码');
      const previousSize = rows.size;
      for (const item of result) {
        const projected = project(item);
        if (!projected) throw new HttpError(502, 'Cloudflare API 返回了无效的列表项');
        rows.set(projected.id, projected);
      }
      if (!canContinue(resultInfo, page, result.length)) return [...rows.values()];
      if (rows.size === previousSize) throw new HttpError(502, 'Cloudflare API 分页未返回新结果');
    }
    throw new HttpError(502, 'Cloudflare API 列表超过分页上限，请缩小令牌资源范围');
  }

  private async send<T>(
    token: string, path: string, options: CloudflareRequestOptions = {}, deadline?: AbortSignal,
  ): Promise<CloudflareResponse<T>> {
    const basePath = this.baseUrl.pathname.replace(/\/$/, '');
    if (!path.startsWith('/') || path.startsWith('//') || /[?#\\\u0000-\u0020\u007f]/.test(path)) {
      throw new HttpError(500, 'Cloudflare API 路径无效');
    }
    const url = new URL(`${basePath}${path}`, this.baseUrl.origin);
    if (url.pathname !== `${basePath}${path}`) throw new HttpError(500, 'Cloudflare API 路径无效');
    for (const [key, value] of Object.entries(options.query ?? {})) {
      if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
    }

    const contentType = options.contentType ?? 'application/json';
    let body: string | undefined;
    if (options.body !== undefined) {
      body = contentType === 'application/json' ? JSON.stringify(options.body) : String(options.body);
    }
    const callerSignal = this.options.signal;
    const timeout = deadline ?? AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    const signal = callerSignal ? AbortSignal.any([timeout, callerSignal]) : timeout;
    let response: Response;
    let text: string | null;
    this.options.beforeRequest?.();
    try {
      signal.throwIfAborted();
      response = await this.fetchImpl(url, {
        method: options.method ?? 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': contentType,
          Accept: options.responseType === 'text' ? '*/*' : 'application/json',
        },
        body,
        redirect: 'error',
        signal,
      });
      text = await readResponse(response, signal);
      signal.throwIfAborted();
    } catch (error) {
      if (callerSignal?.aborted) throw new HttpError(499, 'Cloudflare API 请求已取消');
      if (timeout.aborted) throw new HttpError(504, 'Cloudflare API 请求超过 25 秒');
      throw new HttpError(502, '无法连接 Cloudflare API');
    }
    this.options.beforeRequest?.();
    if (text === null) throw new HttpError(502, 'Cloudflare API 响应超过 8 MiB 上限');

    if (response.ok && options.responseType === 'text') return { result: text as T };
    if (response.status === 204) return { result: null as T };
    const envelope = readEnvelope(text);
    if (!response.ok || envelope?.success === false) throw apiFailure(response.status, envelope);
    if (envelope?.success !== true) throw new HttpError(502, 'Cloudflare API 响应格式无效');
    const resultInfo = record(envelope.result_info);
    return { result: (envelope.result ?? null) as T, ...(resultInfo ? { resultInfo } : {}) };
  }
}
