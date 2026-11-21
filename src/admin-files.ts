import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Express } from 'express';
import { HttpError } from './errors.js';

export const ADMIN_PATH = '/cloudflare-admin';
const WEB_DIR = fileURLToPath(new URL('../web', import.meta.url));
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const contentTypes = new Map(Object.entries({
  '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.json': 'application/json', '.ico': 'image/x-icon', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.avif': 'image/avif', '.woff': 'font/woff', '.woff2': 'font/woff2',
}));
const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
  + "img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

function notFound(): HttpError {
  return new HttpError(404, '找不到管理台文件');
}

async function readStaticFile(directory: string, filename: string): Promise<Buffer> {
  const signal = AbortSignal.timeout(5_000);
  try {
    if (!(await lstat(directory)).isDirectory()) throw notFound();
    signal.throwIfAborted();
    const file = await open(join(directory, filename), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const info = await file.stat();
      if (!info.isFile() || info.size > MAX_FILE_BYTES) throw notFound();
      const data = Buffer.alloc(info.size);
      for (let offset = 0; offset < data.length;) {
        signal.throwIfAborted();
        const { bytesRead } = await file.read(data, offset, data.length - offset, offset);
        if (bytesRead === 0) throw notFound();
        offset += bytesRead;
      }
      signal.throwIfAborted();
      return data;
    } finally {
      await file.close();
    }
  } catch (error) {
    if (signal.aborted) throw new HttpError(503, '读取管理台文件超时');
    if (['ENOENT', 'ENOTDIR', 'ELOOP'].includes((error as NodeJS.ErrnoException).code ?? '')) throw notFound();
    throw error;
  }
}

export function mountAdminFiles(app: Express, webDir = WEB_DIR): void {
  const directory = resolve(webDir);
  app.get(/^\/cloudflare-admin$/, (_req, res) => res.redirect(302, `${ADMIN_PATH}/`));
  app.get(/^\/cloudflare-admin\/$/, async (_req, res) => {
    res.set('Content-Security-Policy', csp);
    res.type('text/html').send(await readStaticFile(directory, 'index.html'));
  });
  app.get(`${ADMIN_PATH}/:filename`, async (req, res) => {
    const filename = req.params.filename;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(filename) || filename.includes('..')) throw notFound();
    const contentType = contentTypes.get(extname(filename).toLowerCase());
    if (!contentType) throw notFound();
    res.set('Content-Security-Policy', contentType === 'image/svg+xml' ? "default-src 'none'; style-src 'unsafe-inline'; sandbox" : csp);
    res.type(contentType).send(await readStaticFile(directory, filename));
  });
}
