export class HttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'HttpError';
  }
}

const HIDDEN = '[已脱敏]';

export function redactSecrets(input: string, secrets: readonly string[] = []): string {
  let output = input
    .replace(/\b(?:bearer|basic)\s+[A-Za-z0-9._~+\/=\-]+/gi, HIDDEN)
    .replace(/(\/cloudflare-mcp\/)[^\s/'"?#]+/gi, (_, path: string) => path + HIDDEN)
    .replace(/\b(?:cf_mcp_admin|(?:cloudflare_)?api[_ -]?token|secret[_ -]?key|(?:current|new)?password|access[_ -]?token)["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}"']+)/gi, HIDDEN)
    .replace(/\b(?:cf_|v1\.0-)[A-Za-z0-9_+\/=\-]{12,}/g, HIDDEN)
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, HIDDEN);

  const variants = new Set<string>();
  for (const secret of secrets) {
    if (!secret) continue;
    variants.add(secret);
    variants.add(JSON.stringify(secret).slice(1, -1));
    try {
      variants.add(encodeURIComponent(secret));
    } catch {
      // 孤立的 UTF-16 代理项只能以内存原值或 JSON 转义的形式出现。
    }
  }
  for (const secret of [...variants].sort((left, right) => right.length - left.length)) {
    output = output.replaceAll(secret, HIDDEN);
  }
  return output;
}

export function errorMessage(error: unknown, secrets?: readonly string[]): string {
  return error instanceof HttpError ? redactSecrets(error.message, secrets) : '服务处理请求时发生错误';
}
