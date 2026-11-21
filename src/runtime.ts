import { resolve } from 'node:path';
import { errorMessage, HttpError } from './errors.js';

export function httpOrigin(value: string | undefined): string | undefined {
  if (!value || !/^https?:\/\//i.test(value) || /[\\\u0000-\u0020\u007f]/u.test(value)) return undefined;
  try {
    const url = new URL(value);
    if (!url.username && !url.password) return url.origin;
  } catch {
    return undefined;
  }
}

export function publicOriginFrom(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const origin = httpOrigin(value);
  if (!origin || !/^https?:\/\/[^/?#]+\/?$/i.test(value)) {
    throw new HttpError(400, '公开源与允许源必须使用 HTTP 或 HTTPS 源，例如 https://api.example.com');
  }
  return origin;
}

export function allowedOriginsFrom(value: string | readonly string[] | undefined): '*' | Set<string> | undefined {
  const origins = (typeof value === 'string' ? value.split(',') : value ?? [])
    .map(origin => origin.trim())
    .filter(Boolean);
  if (origins.length === 0) return undefined;
  if (origins.length === 1 && origins[0] === '*') return '*';
  return new Set(origins.map(origin => publicOriginFrom(origin)!));
}

export function readRuntimeConfig(env: NodeJS.ProcessEnv = process.env) {
  const portText = env.CLOUDFLARE_MCP_PORT?.trim() || '3005';
  const port = Number(portText);
  if (!/^\d+$/.test(portText) || !Number.isInteger(port) || port < 0 || port > 65535) {
    throw new HttpError(400, 'CLOUDFLARE_MCP_PORT 必须为 0 至 65535 的整数');
  }
  const localMcp = env.CLOUDFLARE_MCP_ENABLE_LOCAL_MCP?.trim().toLowerCase();
  if (localMcp && localMcp !== 'true' && localMcp !== 'false') {
    throw new HttpError(400, 'CLOUDFLARE_MCP_ENABLE_LOCAL_MCP 必须为 true 或 false');
  }
  const allowedOrigins = env.CLOUDFLARE_MCP_ALLOWED_ORIGINS;
  allowedOriginsFrom(allowedOrigins);
  return {
    bindHost: env.CLOUDFLARE_MCP_BIND?.trim() || '127.0.0.1',
    port,
    stateDir: resolve(env.CLOUDFLARE_MCP_STATE_DIR?.trim() || '/var/lib/cloudflare-mcp'),
    adminPassword: env.CLOUDFLARE_MCP_ADMIN_PASSWORD,
    publicOrigin: publicOriginFrom(env.CLOUDFLARE_MCP_PUBLIC_ORIGIN?.trim()),
    allowedOrigins,
    envToken: env.CLOUDFLARE_API_TOKEN?.trim() || undefined,
    envAccountId: env.CLOUDFLARE_ACCOUNT_ID?.trim() || undefined,
    enableUnauthLocalMcp: localMcp === 'true',
  };
}

export type RuntimeConfig = ReturnType<typeof readRuntimeConfig>;

export function registerShutdown(close: () => Promise<void>): () => void {
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    void Promise.resolve().then(close).catch(error => {
      console.error('关闭 Cloudflare MCP 服务失败', errorMessage(error));
      process.exitCode = 1;
    }).finally(unregister);
  };
  const unregister = () => {
    process.off('SIGINT', stop);
    process.off('SIGTERM', stop);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  return unregister;
}
