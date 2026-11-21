import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { join } from 'node:path';
import { z } from 'zod';
import { MODULES } from './catalog.js';
import { zoneName } from './cloudflare-client.js';
import { HttpError } from './errors.js';
import {
  prepareStateDirectory, readMasterKey, readStateFile, sealSecret, sealedSecretSchema,
  SerializedWrites, unsealSecret, writeStateFile,
} from './state-files.js';

const MAX_LINKS = 1_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const DAY_MS = 24 * 60 * 60 * 1_000;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const moduleIds = new Set<string>(MODULES.map(module => module.id));
const accessLevelSchema = z.enum(['read', 'write', 'admin']);
export type AccessLevel = z.infer<typeof accessLevelSchema>;

const linkName = z.string().trim().min(1).max(120).regex(/^[^\u0000-\u001f\u007f]+$/);
const modules = z.array(z.string().refine(value => moduleIds.has(value)))
  .min(1).max(moduleIds.size).transform(values => [...new Set(values)]).nullable();
const zone = z.string().trim().min(1).max(254).transform((value, context) => {
  const normalized = /^[0-9a-f]{32}$/i.test(value) ? value.toLowerCase() : zoneName(value);
  if (normalized) return normalized;
  context.issues.push({ code: 'custom', message: '域名或标识无效', input: value });
  return z.NEVER;
});
const zones = z.array(zone).min(1).max(500).transform(values => [...new Set(values)]).nullable();

const linkOptions = z.strictObject({
  name: linkName,
  accessLevel: accessLevelSchema,
  allowedModules: modules,
  allowedZones: zones,
});
export const createLinkSchema = linkOptions.partial({ allowedModules: true, allowedZones: true }).extend({
  expiresInDays: z.number().int().min(1).max(365).optional(),
});
export const updateLinkSchema = linkOptions.partial().refine(value => Object.keys(value).length > 0);

const linkMetadata = z.strictObject({
  id: z.uuid(),
  name: linkName,
  access_level: accessLevelSchema,
  allowed_modules: modules,
  allowed_zones: zones,
  created_at: z.iso.datetime(),
  expires_at: z.iso.datetime().nullable(),
  last_used_at: z.iso.datetime().nullable(),
  use_count: z.number().int().nonnegative(),
  revoked_at: z.iso.datetime().nullable(),
});
const diskSchema = linkMetadata.extend({ sealedToken: sealedSecretSchema });
const fileSchema = z.strictObject({ version: z.literal(1), links: z.array(diskSchema).max(MAX_LINKS) });
type DiskLink = z.infer<typeof diskSchema>;
type PublicLink = z.infer<typeof linkMetadata> & { url: string };

interface LinkEntry {
  data: DiskLink;
  token: Buffer;
  revision: number;
}

function sealContext(id: string): string {
  return `mcp-link:${id}`;
}

function isActive(link: DiskLink, now = Date.now()): boolean {
  return link.revoked_at === null && (link.expires_at === null || Date.parse(link.expires_at) > now);
}

function authorization(entry: LinkEntry) {
  const { id, name, access_level, allowed_modules, allowed_zones, expires_at } = entry.data;
  return {
    id, name, access_level, expires_at, revision: entry.revision,
    allowed_modules: allowed_modules?.slice() ?? null,
    allowed_zones: allowed_zones?.slice() ?? null,
  };
}
export type LinkAuthorization = ReturnType<typeof authorization>;

function publicLink({ data, token }: LinkEntry, origin: string): PublicLink {
  const { sealedToken: _sealedToken, ...metadata } = data;
  return {
    ...metadata,
    allowed_modules: metadata.allowed_modules?.slice() ?? null,
    allowed_zones: metadata.allowed_zones?.slice() ?? null,
    url: `${origin}/cloudflare-mcp/${token}/mcp`,
  };
}

export class LinkStore {
  private readonly writes = new SerializedWrites();

  private constructor(
    private readonly path: string,
    private readonly key: Buffer,
    private entries: Map<string, LinkEntry>,
  ) {}

  static async open(stateDir: string): Promise<LinkStore> {
    await prepareStateDirectory(stateDir);
    const path = join(stateDir, 'links.json');
    const key = await readMasterKey(stateDir);
    const raw = await readStateFile(path, MAX_FILE_BYTES);
    const entries = new Map<string, LinkEntry>();
    if (!raw) return new LinkStore(path, key, entries);

    try {
      const { links } = fileSchema.parse(JSON.parse(raw.toString('utf8')));
      const tokens = new Set<string>();
      for (const data of links) {
        const token = unsealSecret(key, data.sealedToken, sealContext(data.id));
        if (!TOKEN_PATTERN.test(token) || entries.has(data.id) || tokens.has(token)) throw new Error();
        tokens.add(token);
        entries.set(data.id, { data, token: Buffer.from(token, 'ascii'), revision: 0 });
      }
      return new LinkStore(path, key, entries);
    } catch {
      throw new HttpError(500, 'MCP 链接文件损坏或无法解密');
    }
  }

  list(origin = ''): PublicLink[] {
    return [...this.entries.values()].reverse().map(entry => publicLink(entry, origin));
  }

  stats() {
    let activeLinks = 0;
    let totalCalls = 0;
    const now = Date.now();
    for (const { data } of this.entries.values()) {
      if (isActive(data, now)) activeLinks += 1;
      totalCalls += data.use_count;
    }
    return { activeLinks, totalLinks: this.entries.size, totalCalls };
  }

  findActiveByToken(token: string): LinkAuthorization | undefined {
    if (!TOKEN_PATTERN.test(token)) return undefined;
    const bytes = Buffer.from(token, 'ascii');
    let matched: LinkEntry | undefined;
    for (const entry of this.entries.values()) {
      if (timingSafeEqual(bytes, entry.token)) matched = entry;
    }
    if (matched && isActive(matched.data)) return authorization(matched);
  }

  findActiveById(id: string): LinkAuthorization | undefined {
    const entry = this.entries.get(id);
    if (entry && isActive(entry.data)) return authorization(entry);
  }

  create(input: unknown, origin = ''): Promise<PublicLink> {
    const parsed = createLinkSchema.safeParse(input);
    if (!parsed.success) return Promise.reject(new HttpError(400, '链接名称、权限、白名单或有效期无效'));
    return this.writes.run(async () => {
      if (this.entries.size >= MAX_LINKS) throw new HttpError(409, '链接数量已达到上限');
      const { name, accessLevel, allowedModules, allowedZones, expiresInDays } = parsed.data;
      const id = randomUUID();
      const token = randomBytes(32).toString('base64url');
      const now = Date.now();
      const data: DiskLink = {
        id, name, access_level: accessLevel,
        allowed_modules: allowedModules ?? null, allowed_zones: allowedZones ?? null,
        created_at: new Date(now).toISOString(),
        expires_at: expiresInDays ? new Date(now + expiresInDays * DAY_MS).toISOString() : null,
        last_used_at: null, use_count: 0, revoked_at: null,
        sealedToken: sealSecret(this.key, token, sealContext(id)),
      };
      const entry = { data, token: Buffer.from(token, 'ascii'), revision: 0 };
      await this.commit(entry);
      return publicLink(entry, origin);
    });
  }

  update(id: string, patch: unknown, origin = ''): Promise<PublicLink> {
    const parsed = updateLinkSchema.safeParse(patch);
    if (!parsed.success) return Promise.reject(new HttpError(400, '链接权限变更参数无效'));
    return this.writes.run(async () => {
      const entry = this.requiredEntry(id);
      if (!isActive(entry.data)) throw new HttpError(409, '失效的链接无法调整权限');
      const { name, accessLevel, allowedModules, allowedZones } = parsed.data;
      const data: DiskLink = {
        ...entry.data,
        name: name ?? entry.data.name,
        access_level: accessLevel ?? entry.data.access_level,
        allowed_modules: allowedModules === undefined ? entry.data.allowed_modules : allowedModules,
        allowed_zones: allowedZones === undefined ? entry.data.allowed_zones : allowedZones,
      };
      const next = { ...entry, data, revision: entry.revision + 1 };
      await this.commit(next);
      return publicLink(next, origin);
    });
  }

  revoke(id: string, origin = ''): Promise<PublicLink> {
    return this.writes.run(async () => {
      let entry = this.requiredEntry(id);
      if (entry.data.revoked_at === null) {
        entry = {
          ...entry,
          data: { ...entry.data, revoked_at: new Date().toISOString() },
          revision: entry.revision + 1,
        };
        await this.commit(entry);
      }
      return publicLink(entry, origin);
    });
  }

  recordUsage(id: string): Promise<void> {
    return this.writes.run(async () => {
      const entry = this.entries.get(id);
      if (!entry || !isActive(entry.data)) return;
      const data = {
        ...entry.data,
        use_count: entry.data.use_count + 1,
        last_used_at: new Date().toISOString(),
      };
      await this.commit({ ...entry, data });
    });
  }

  private requiredEntry(id: string): LinkEntry {
    const entry = this.entries.get(id);
    if (!entry) throw new HttpError(404, '找不到该 MCP 链接');
    return entry;
  }

  private async commit(entry: LinkEntry): Promise<void> {
    const next = new Map(this.entries).set(entry.data.id, entry);
    const data = JSON.stringify({ version: 1, links: [...next.values()].map(item => item.data) });
    if (Buffer.byteLength(data) > MAX_FILE_BYTES) throw new HttpError(409, '链接文件超出大小限制');
    await writeStateFile(this.path, data);
    this.entries = next;
  }
}
