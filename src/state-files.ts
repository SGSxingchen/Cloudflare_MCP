import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { link, mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { z } from 'zod';
import { HttpError } from './errors.js';

const FILE_TIMEOUT_MS = 10_000;
const MAX_PENDING_WRITES = 128;

export async function prepareStateDirectory(path: string): Promise<void> {
  const signal = AbortSignal.timeout(FILE_TIMEOUT_MS);
  await mkdir(path, { recursive: true, mode: 0o700 });
  signal.throwIfAborted();
  const directory = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const mode = (await directory.stat()).mode & 0o7777;
    signal.throwIfAborted();
    if (mode !== 0o700) await directory.chmod(0o700);
  } finally {
    await directory.close();
  }
}

export async function readStateFile(path: string, maxBytes: number): Promise<Buffer | undefined> {
  const signal = AbortSignal.timeout(FILE_TIMEOUT_MS);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK).catch(error => {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  });
  if (!file) return undefined;
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > maxBytes) throw new Error('状态文件无效或超出大小限制');
    signal.throwIfAborted();
    if ((info.mode & 0o7777) !== 0o600) await file.chmod(0o600);
    const data = Buffer.alloc(info.size + 1);
    let length = 0;
    while (length < data.length) {
      signal.throwIfAborted();
      const { bytesRead } = await file.read(data, length, data.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    signal.throwIfAborted();
    if (length !== info.size) throw new Error('读取期间状态文件大小发生变化');
    return data.subarray(0, length);
  } finally {
    await file.close();
  }
}

async function syncParent(path: string): Promise<void> {
  try {
    const directory = await open(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch {
    // 文件已提交，此时仍应发布新的内存快照。
    console.error('同步 Cloudflare MCP 状态目录失败');
  }
}

export async function writeStateFile(path: string, data: Buffer | string, createOnly = false): Promise<void> {
  const signal = AbortSignal.timeout(FILE_TIMEOUT_MS);
  const temporary = `${path}.${randomBytes(12).toString('hex')}.tmp`;
  const file = await open(temporary, 'wx', 0o600);
  try {
    try {
      signal.throwIfAborted();
      await file.chmod(0o600);
      await file.writeFile(data, { signal });
      signal.throwIfAborted();
      await file.sync();
    } finally {
      await file.close();
    }
    signal.throwIfAborted();
    if (createOnly) await link(temporary, path);
    else await rename(temporary, path);
  } finally {
    await unlink(temporary).catch(error => {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') console.error('清理 Cloudflare MCP 临时文件失败');
    });
  }
  await syncParent(path);
}

export async function removeStateFile(path: string): Promise<void> {
  const signal = AbortSignal.timeout(FILE_TIMEOUT_MS);
  signal.throwIfAborted();
  const removed = await unlink(path).then(() => true, error => {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    return false;
  });
  if (removed) await syncParent(path);
}

export async function readOrGenerate(path: string, maxBytes: number, generate: () => Buffer): Promise<Buffer> {
  const existing = await readStateFile(path, maxBytes);
  if (existing) return existing;
  const data = generate();
  try {
    await writeStateFile(path, data, true);
    return data;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    const concurrent = await readStateFile(path, maxBytes);
    if (!concurrent) throw error;
    return concurrent;
  }
}

export class SerializedWrites {
  private tail = Promise.resolve();
  private pending = 0;

  run<T>(operation: () => Promise<T>): Promise<T> {
    const busy = () => new HttpError(503, '本地状态写入繁忙，请稍后重试');
    if (this.pending >= MAX_PENDING_WRITES) return Promise.reject(busy());
    const dueAt = performance.now() + FILE_TIMEOUT_MS;
    this.pending += 1;
    const result = this.tail.then(() => {
      if (performance.now() >= dueAt) throw busy();
      return operation();
    }).finally(() => { this.pending -= 1; });
    this.tail = result.then(() => {}, () => {});
    return result;
  }
}

const base64url = /^[A-Za-z0-9_-]+$/;
export const sealedSecretSchema = z.strictObject({
  iv: z.string().length(16).regex(base64url),
  tag: z.string().length(22).regex(base64url),
  ciphertext: z.string().min(1).max(8_192).regex(base64url),
});
type SealedSecret = z.infer<typeof sealedSecretSchema>;

export async function readMasterKey(stateDir: string): Promise<Buffer> {
  const key = await readOrGenerate(join(stateDir, 'secret-key.bin'), 32, () => randomBytes(32));
  if (key.length !== 32) throw new Error('Cloudflare MCP 主密钥必须为 32 字节');
  return key;
}

export function sealSecret(key: Buffer, value: string, context: string): SealedSecret {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(`cloudflare-mcp:v1:${context}`));
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return {
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
  };
}

export function unsealSecret(key: Buffer, value: SealedSecret, context: string): string {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(value.iv, 'base64url'), { authTagLength: 16 });
  decipher.setAAD(Buffer.from(`cloudflare-mcp:v1:${context}`));
  decipher.setAuthTag(Buffer.from(value.tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(value.ciphertext, 'base64url')), decipher.final()]).toString('utf8');
}
