import { join } from 'node:path';
import { z } from 'zod';
import { HttpError, redactSecrets } from './errors.js';
import type { AccessLevel } from './link-store.js';
import { prepareStateDirectory, readStateFile, SerializedWrites, writeStateFile } from './state-files.js';

const MAX_RECORDS = 500;
const MAX_FILE_BYTES = 5 * 1024 * 1024;

export interface AuditEvent {
  linkId: string | null;
  linkName: string | null;
  tool: string;
  action: string | null;
  module: string | null;
  access: AccessLevel | null;
  target: string | null;
  status: 'ok' | 'preview' | 'denied' | 'error';
  durationMs: number;
  summary: string;
}

const recordSchema = z.strictObject({
  ts: z.iso.datetime(),
  linkId: z.string().max(64).nullable(),
  linkName: z.string().max(120).nullable(),
  tool: z.string().max(128),
  action: z.string().max(128).nullable(),
  module: z.string().max(40).nullable(),
  access: z.enum(['read', 'write', 'admin']).nullable(),
  target: z.string().max(320).nullable(),
  status: z.enum(['ok', 'preview', 'denied', 'error']),
  durationMs: z.number().int().nonnegative(),
  summary: z.string().max(600),
});
type AuditRecord = z.infer<typeof recordSchema>;

function serialize(records: readonly AuditRecord[]): string {
  return records.map(record => `${JSON.stringify(record)}\n`).join('');
}

function clean(value: string, maxLength: number): string {
  return redactSecrets(value).slice(0, maxLength);
}

export class AuditStore {
  private readonly writes = new SerializedWrites();

  private constructor(private readonly path: string, private records: AuditRecord[]) {}

  static async open(stateDir: string): Promise<AuditStore> {
    await prepareStateDirectory(stateDir);
    const path = join(stateDir, 'audit.jsonl');
    const raw = await readStateFile(path, MAX_FILE_BYTES);
    if (!raw) return new AuditStore(path, []);

    const lines = raw.toString('utf8').split('\n').filter(line => line.trim());
    let records: AuditRecord[];
    try {
      records = lines.slice(-MAX_RECORDS).map(line => recordSchema.parse(JSON.parse(line)));
    } catch {
      throw new HttpError(500, 'Cloudflare MCP 审计文件格式无效');
    }
    if (lines.length > MAX_RECORDS) await writeStateFile(path, serialize(records));
    return new AuditStore(path, records);
  }

  record(event: AuditEvent): Promise<void> {
    const entry: AuditRecord = {
      ts: new Date().toISOString(),
      linkId: event.linkId === null ? null : clean(event.linkId, 64),
      linkName: event.linkName === null ? null : clean(event.linkName, 120),
      tool: clean(event.tool, 128),
      action: event.action === null ? null : clean(event.action, 128),
      module: event.module === null ? null : clean(event.module, 40),
      access: event.access,
      target: event.target === null ? null : clean(event.target, 320),
      status: event.status,
      durationMs: event.durationMs,
      summary: clean(event.summary, 600),
    };
    return this.writes.run(async () => {
      const next = [...this.records.slice(1 - MAX_RECORDS), entry];
      await writeStateFile(this.path, serialize(next));
      this.records = next;
    });
  }

  list(limit = 100): AuditRecord[] {
    const count = Number.isFinite(limit) ? Math.max(0, Math.min(MAX_RECORDS, Math.trunc(limit))) : 100;
    return count === 0 ? [] : this.records.slice(-count).reverse().map(record => ({ ...record }));
  }
}
