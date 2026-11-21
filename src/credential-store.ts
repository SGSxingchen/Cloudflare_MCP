import { join } from 'node:path';
import { z } from 'zod';
import { HttpError, redactSecrets } from './errors.js';
import {
  prepareStateDirectory, readMasterKey, readStateFile, removeStateFile, sealedSecretSchema,
  sealSecret, SerializedWrites, unsealSecret, writeStateFile,
} from './state-files.js';

const MAX_CREDENTIAL_BYTES = 16 * 1024 * 1024;
const MAX_CACHE_ENTRIES = 10_000;
const TOKEN_CONTEXT = 'credentials';
const tokenSchema = z.string().trim().min(1).max(4_096).regex(/^[A-Za-z0-9._~+/=\-]+$/);
const accountIdSchema = z.string().trim().toLowerCase().regex(/^[a-f0-9]{32}$/);
const cachedAccountSchema = z.object({
  id: z.string().min(1).max(128),
  name: z.string().max(256),
});
const cachedZoneSchema = z.object({
  id: z.string().min(1).max(128),
  name: z.string().min(1).max(253),
  status: z.string().max(128).optional(),
  plan: z.string().max(128).optional(),
  name_servers: z.array(z.string().max(253)).max(32).optional(),
  account: cachedAccountSchema.optional(),
});
const verificationSchema = z.strictObject({
  defaultAccountId: accountIdSchema.nullable().optional(),
  verifiedAt: z.iso.datetime({ offset: true }).nullable().optional(),
  verifyStatus: z.enum(['unverified', 'ok', 'error', 'skipped']).nullable().optional(),
  verifyMessage: z.string().nullable().optional(),
  cachedAccounts: z.array(cachedAccountSchema).max(MAX_CACHE_ENTRIES).optional(),
  cachedZones: z.array(cachedZoneSchema).max(MAX_CACHE_ENTRIES).optional(),
});
const credentialFileSchema = verificationSchema.extend({
  version: z.literal(1),
  apiToken: sealedSecretSchema,
});

export type CachedAccount = z.infer<typeof cachedAccountSchema>;
export type CachedZone = z.infer<typeof cachedZoneSchema>;
export type VerificationDetails = z.infer<typeof verificationSchema>;
type SealedCredentials = z.infer<typeof credentialFileSchema>;

interface CredentialOptions {
  envToken?: string;
  envAccountId?: string;
}

interface ActiveToken {
  token: string | null;
  source: 'store' | 'env' | 'none';
}

function tokenHint(token: string): string {
  if (token.length <= 8) return '****';
  return `${token.startsWith('cf_') ? 'cf_' : ''}****${token.slice(-4)}`;
}

function parseToken(token: string): string {
  const parsed = tokenSchema.safeParse(token);
  if (!parsed.success) throw new HttpError(400, 'Cloudflare API 令牌格式无效');
  return parsed.data;
}

function safeDetails(details: VerificationDetails, secrets: readonly string[]): VerificationDetails {
  const parsed = verificationSchema.safeParse(details);
  if (!parsed.success) throw new HttpError(400, 'Cloudflare 凭据元数据格式无效');
  const clean = parsed.data;
  if (typeof clean.verifyMessage === 'string') {
    clean.verifyMessage = redactSecrets(clean.verifyMessage, secrets).slice(0, 600);
  }
  if (clean.defaultAccountId && secrets.some(secret => clean.defaultAccountId!.includes(secret))) {
    throw new HttpError(400, '默认账号 ID 格式无效');
  }
  if (clean.cachedAccounts) {
    clean.cachedAccounts = clean.cachedAccounts.map(account => ({
      id: account.id,
      name: redactSecrets(account.name, secrets).slice(0, 256),
    }));
  }
  if (clean.cachedZones) {
    clean.cachedZones = clean.cachedZones.map(zone => ({
      id: zone.id,
      name: redactSecrets(zone.name, secrets).slice(0, 253),
      status: zone.status === undefined ? undefined : redactSecrets(zone.status, secrets).slice(0, 128),
      plan: zone.plan === undefined ? undefined : redactSecrets(zone.plan, secrets).slice(0, 128),
      name_servers: zone.name_servers?.map(name => redactSecrets(name, secrets).slice(0, 253)),
      account: zone.account && { id: zone.account.id, name: redactSecrets(zone.account.name, secrets).slice(0, 256) },
    }));
  }
  return clean;
}

export class CredentialStore {
  private readonly writes = new SerializedWrites();
  private envVerification: VerificationDetails = {};
  private generation = 0;

  private constructor(
    private readonly path: string,
    private readonly key: Buffer,
    private readonly envToken: string | undefined,
    private readonly envAccountId: string | undefined,
    private record: SealedCredentials | undefined,
    private storedToken: string | undefined,
  ) {}

  static async open(stateDir: string, options: CredentialOptions = {}): Promise<CredentialStore> {
    const envToken = options.envToken?.trim() ? parseToken(options.envToken) : undefined;
    let envAccountId: string | undefined;
    if (options.envAccountId) {
      const parsed = accountIdSchema.safeParse(options.envAccountId);
      if (!parsed.success) throw new HttpError(400, 'CLOUDFLARE_ACCOUNT_ID 必须为 32 位十六进制账号 ID');
      envAccountId = parsed.data;
    }
    await prepareStateDirectory(stateDir);
    const path = join(stateDir, 'cf-credentials.enc.json');
    const key = await readMasterKey(stateDir);
    const raw = await readStateFile(path, MAX_CREDENTIAL_BYTES);
    if (!raw) return new CredentialStore(path, key, envToken, envAccountId, undefined, undefined);
    try {
      const record = credentialFileSchema.parse(JSON.parse(raw.toString('utf8')));
      const token = parseToken(unsealSecret(key, record.apiToken, TOKEN_CONTEXT));
      return new CredentialStore(path, key, envToken, envAccountId, record, token);
    } catch {
      throw new HttpError(500, 'Cloudflare 凭据文件损坏或无法解密');
    }
  }

  get revision(): number {
    return this.generation;
  }

  getActiveToken(): ActiveToken {
    if (this.storedToken !== undefined) return { token: this.storedToken, source: 'store' };
    if (this.envToken !== undefined) return { token: this.envToken, source: 'env' };
    return { token: null, source: 'none' };
  }

  getDefaultAccountId(): string | null {
    return this.metadata().defaultAccountId ?? this.envAccountId ?? null;
  }

  getCachedAccounts(): CachedAccount[] {
    return structuredClone(this.metadata().cachedAccounts ?? []);
  }

  getCachedZones(): CachedZone[] {
    return structuredClone(this.metadata().cachedZones ?? []);
  }

  getPublicStatus() {
    const { token, source } = this.getActiveToken();
    const metadata = this.metadata();
    const accountId = this.getDefaultAccountId();
    const secrets = this.activeSecrets();
    return {
      configured: token !== null,
      source,
      tokenHint: token === null ? null : tokenHint(token),
      defaultAccountId: accountId === null ? null : redactSecrets(accountId, secrets),
      verifiedAt: metadata.verifiedAt ?? null,
      verifyStatus: metadata.verifyStatus ?? (token === null ? null : 'unverified'),
      verifyMessage: metadata.verifyMessage == null ? null : redactSecrets(metadata.verifyMessage, secrets),
      accountCount: metadata.cachedAccounts?.length ?? 0,
      zoneCount: metadata.cachedZones?.length ?? 0,
    };
  }

  saveToken(apiToken: string, details: VerificationDetails = {}, expectedRevision?: number): Promise<void> {
    return this.writes.run(async () => {
      if (expectedRevision !== undefined && this.generation !== expectedRevision) {
        throw new HttpError(409, '验活期间凭据已更改，请重新提交');
      }
      const token = parseToken(apiToken);
      const record: SealedCredentials = {
        ...safeDetails(details, [token, ...this.activeSecrets()]),
        version: 1,
        apiToken: sealSecret(this.key, token, TOKEN_CONTEXT),
      };
      await this.persist(record);
      this.record = record;
      this.storedToken = token;
      this.generation += 1;
    });
  }

  updateVerification(
    details: VerificationDetails, expectedToken?: string, expectedRevision?: number,
  ): Promise<boolean> {
    return this.writes.run(async () => {
      const { token } = this.getActiveToken();
      if (token === null || (expectedToken !== undefined && token !== expectedToken)
        || (expectedRevision !== undefined && this.generation !== expectedRevision)) return false;
      const clean = safeDetails(details, this.activeSecrets());
      if (this.record) {
        const record = { ...this.record, ...clean };
        await this.persist(record);
        this.record = record;
      } else {
        this.envVerification = { ...this.envVerification, ...clean };
      }
      return true;
    });
  }

  clearToken(): Promise<void> {
    return this.writes.run(async () => {
      await removeStateFile(this.path);
      this.record = undefined;
      this.storedToken = undefined;
      this.envVerification = {};
      this.generation += 1;
    });
  }

  private metadata(): VerificationDetails {
    return this.record ?? this.envVerification;
  }

  private activeSecrets(): string[] {
    return [this.storedToken, this.envToken].filter((value): value is string => value !== undefined);
  }

  private persist(record: SealedCredentials): Promise<void> {
    const json = JSON.stringify(record);
    if (Buffer.byteLength(json) > MAX_CREDENTIAL_BYTES) throw new HttpError(409, 'Cloudflare 凭据缓存超出大小限制');
    return writeStateFile(this.path, json);
  }
}
