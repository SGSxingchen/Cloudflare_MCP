#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { AuditStore } from './audit-store.js';
import { CredentialStore } from './credential-store.js';
import { errorMessage, redactSecrets } from './errors.js';
import { createMcpServer, FULL_ACCESS } from './mcp-tools.js';
import { readRuntimeConfig, registerShutdown } from './runtime.js';

async function start(): Promise<void> {
  const config = readRuntimeConfig();
  const [credentials, auditStore] = await Promise.all([
    CredentialStore.open(config.stateDir, config),
    AuditStore.open(config.stateDir),
  ]);
  const server = createMcpServer({
    credentials, auditStore, getScope: () => FULL_ACCESS,
    redact: value => redactSecrets(value, [config.envToken ?? '', config.adminPassword ?? '']),
  });
  const transport = new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 256 * 1024 });
  const close = () => server.close();
  const unregister = registerShutdown(close);
  const end = () => { void close().catch(() => console.error('关闭 Cloudflare MCP stdio 失败')); };
  server.onclose = () => {
    process.stdin.off('end', end);
    unregister();
  };
  server.onerror = () => console.error('处理 Cloudflare MCP stdio 消息失败');
  process.stdin.once('end', end);
  try {
    await server.connect(transport);
  } catch (error) {
    await close();
    throw error;
  }
}

try {
  await start();
} catch (error) {
  console.error('启动 Cloudflare MCP stdio 失败', errorMessage(error));
  process.exitCode = 1;
}
