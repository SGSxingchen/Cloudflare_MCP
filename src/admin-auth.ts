import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { join } from 'node:path';
import type { CookieOptions, Request, Response } from 'express';
import { HttpError, redactSecrets } from './errors.js';
import { prepareStateDirectory, readOrGenerate, SerializedWrites, writeStateFile } from './state-files.js';

const COOKIE_NAME = 'cf_mcp_admin';
const COOKIE_PATH = '/cloudflare-admin';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SESSIONS = 1_024;
const SESSION_TOKEN = /^[A-Za-z0-9_-]{43}$/;
const MAX_PASSWORD_BYTES = 4_096;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 10;
const MAX_FAILURE_SOURCES = 4_096;

interface FailureBucket {
  count: number;
  expiresAt: number;
}

function passwordUsable(password: unknown): password is string {
  return typeof password === 'string' && password.trim().length > 0
    && Buffer.byteLength(password) <= MAX_PASSWORD_BYTES && !/[\u0000-\u001f\u007f]/u.test(password);
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value).digest();
}

function cookieOptions(req: Request, publicOrigin?: string): CookieOptions {
  return {
    path: COOKIE_PATH,
    httpOnly: true,
    sameSite: 'strict',
    secure: req.secure || publicOrigin?.startsWith('https://') === true,
  };
}

export function readAdminCookie(req: Request): string | undefined {
  const prefix = `${COOKIE_NAME}=`;
  const field = req.get('cookie')?.split(';').find(entry => entry.trimStart().startsWith(prefix));
  const value = field?.trim().slice(prefix.length);
  return value && SESSION_TOKEN.test(value) ? value : undefined;
}

export function setAdminCookie(req: Request, res: Response, token: string, publicOrigin?: string): void {
  res.cookie(COOKIE_NAME, token, { ...cookieOptions(req, publicOrigin), maxAge: SESSION_TTL_MS });
}

export function clearAdminCookie(req: Request, res: Response, publicOrigin?: string): void {
  res.clearCookie(COOKIE_NAME, cookieOptions(req, publicOrigin));
}

export class AdminAuth {
  private readonly writes = new SerializedWrites();
  private readonly sessions = new Map<string, number>();
  private readonly failures = new Map<string, FailureBucket>();
  private nextFailureSweep = 0;
  private passwordHash: Buffer;

  private constructor(
    private readonly passwordPath: string,
    public readonly passwordSource: 'env' | 'file',
    private password: string,
  ) {
    this.passwordHash = digest(password);
  }

  static async open(stateDir: string, envPassword?: string): Promise<AdminAuth> {
    await prepareStateDirectory(stateDir);
    const path = join(stateDir, 'admin-password.txt');
    const source = envPassword === undefined ? 'file' : 'env';
    const password = envPassword ?? (await readOrGenerate(
      path, MAX_PASSWORD_BYTES + 2, () => Buffer.from(randomBytes(32).toString('base64url')),
    )).toString('utf8').replace(/\r?\n$/, '');
    if (!passwordUsable(password)) throw new HttpError(400, '管理员口令不能为空、包含控制字符或超过 4096 字节');
    return new AdminAuth(path, source, password);
  }

  login(password: unknown, key: string, previousToken?: string): string {
    const now = Date.now();
    const failures = this.getFailures(key, now);
    if ((failures?.count ?? 0) >= MAX_FAILURES
      || (!failures && this.failures.size >= MAX_FAILURE_SOURCES)) {
      throw new HttpError(429, '登录失败次数过多，请稍后重试');
    }
    if (!this.matches(password)) {
      const bucket = failures ?? { count: 0, expiresAt: now + FAILURE_WINDOW_MS };
      bucket.count += 1;
      this.failures.set(key, bucket);
      if (bucket.count >= MAX_FAILURES) throw new HttpError(429, '登录失败次数过多，请稍后重试');
      throw new HttpError(401, '管理员口令错误');
    }
    this.failures.delete(key);
    this.logout(previousToken);
    for (const [id, expiry] of this.sessions) {
      if (expiry <= now) this.sessions.delete(id);
    }
    if (this.sessions.size >= MAX_SESSIONS) {
      const oldest = this.sessions.keys().next().value;
      if (oldest !== undefined) this.sessions.delete(oldest);
    }
    const token = randomBytes(32).toString('base64url');
    this.sessions.set(digest(token).toString('hex'), now + SESSION_TTL_MS);
    return token;
  }

  isAuthenticated(token?: string): boolean {
    if (!token || !SESSION_TOKEN.test(token)) return false;
    const id = digest(token).toString('hex');
    const expiry = this.sessions.get(id);
    if (expiry === undefined) return false;
    if (expiry > Date.now()) return true;
    this.sessions.delete(id);
    return false;
  }

  logout(token?: string): void {
    if (token && SESSION_TOKEN.test(token)) this.sessions.delete(digest(token).toString('hex'));
  }

  changePassword(currentPassword: unknown, newPassword: unknown): Promise<void> {
    return this.writes.run(async () => {
      if (this.passwordSource === 'env') {
        throw new HttpError(400, '当前口令来自环境变量，无法在线修改，请更新 CLOUDFLARE_MCP_ADMIN_PASSWORD 后重启');
      }
      if (!this.matches(currentPassword)) throw new HttpError(401, '当前管理员口令错误');
      if (!passwordUsable(newPassword)) throw new HttpError(400, '新口令不能为空、包含控制字符或超过 4096 字节');
      await writeStateFile(this.passwordPath, newPassword);
      this.password = newPassword;
      this.passwordHash = digest(newPassword);
      this.sessions.clear();
      this.failures.clear();
    });
  }

  redact(text: string): string {
    return redactSecrets(text, [this.password]);
  }

  private matches(password: unknown): boolean {
    return passwordUsable(password) && timingSafeEqual(digest(password), this.passwordHash);
  }

  private getFailures(key: string, now: number): FailureBucket | undefined {
    if (now >= this.nextFailureSweep) {
      for (const [source, bucket] of this.failures) {
        if (bucket.expiresAt <= now) this.failures.delete(source);
      }
      this.nextFailureSweep = now + 60_000;
    }
    const bucket = this.failures.get(key);
    if (bucket && bucket.expiresAt > now) return bucket;
    this.failures.delete(key);
    return undefined;
  }
}
