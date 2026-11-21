import { once } from 'node:events';
import { createServer } from 'node:http';
import { errorMessage, HttpError } from './errors.js';
import { createHttpApp, isLoopbackHost } from './http-app.js';
import { readRuntimeConfig, registerShutdown } from './runtime.js';

async function start(): Promise<void> {
  const config = readRuntimeConfig();
  if (config.enableUnauthLocalMcp && !isLoopbackHost(config.bindHost)) {
    throw new HttpError(400, '启用本地 /mcp 时，CLOUDFLARE_MCP_BIND 必须为回环地址');
  }
  const service = await createHttpApp(config);
  const server = createServer({
    headersTimeout: 10_000,
    requestTimeout: 30_000,
    keepAliveTimeout: 5_000,
  }, service.app);
  server.maxConnections = 1_024;
  try {
    await once(server.listen(config.port, config.bindHost), 'listening');
  } catch (error) {
    await service.close();
    if (error && typeof error === 'object' && 'code' in error) {
      if (error.code === 'EADDRINUSE') throw new HttpError(409, 'HTTP 监听端口已被占用');
      if (error.code === 'EACCES' || error.code === 'EPERM') throw new HttpError(500, '当前进程无法监听配置的 HTTP 地址');
    }
    throw error;
  }

  const address = server.address();
  console.error(`Cloudflare MCP HTTP 已启动（${config.bindHost}，端口 ${typeof address === 'object' ? address?.port : config.port}）`);
  registerShutdown(async () => {
    const deadline = setTimeout(() => server.closeAllConnections(), 5_000);
    deadline.unref();
    try {
      await Promise.all([
        service.close(),
        new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())),
      ]);
    } finally {
      clearTimeout(deadline);
    }
  });
}

try {
  await start();
} catch (error) {
  console.error('启动 Cloudflare MCP HTTP 服务失败', errorMessage(error));
  process.exitCode = 1;
}
