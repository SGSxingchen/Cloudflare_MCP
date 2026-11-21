import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { getCatalogMetrics, listMetaTools } from '../dist/catalog.js';
import { CredentialStore } from '../dist/credential-store.js';
import { prepareReadonlySql } from '../dist/d1-readonly.js';
import { createHttpApp } from '../dist/http-app.js';

const ZONE_A_ID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ZONE_B_ID = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const ACCOUNT_ID = 'cccccccccccccccccccccccccccccccc';
const RECORD_ID = 'dddddddddddddddddddddddddddddddd';
const TEST_TOKEN = 'cf_test_token_1234567890abcdef1234567890';

function createMockFetch() {
  const calls = [];
  let dnsRecords = [
    { id: RECORD_ID, type: 'A', name: 'api.example.org', content: '203.0.113.10', ttl: 1, proxied: true },
  ];

  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.toString());
    const method = (init.method || 'GET').toUpperCase();
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: url.pathname + url.search, body });

    const json = (payload, status = 200) => new Response(JSON.stringify(payload), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });

    if (url.pathname.endsWith('/user/tokens/verify')) {
      return json({ success: true, result: { id: 'tok1', status: 'active' } });
    }
    if (url.pathname.endsWith('/accounts')) {
      return json({ success: true, result: [{ id: ACCOUNT_ID, name: 'Demo Account' }], result_info: { page: 1, total_pages: 1 } });
    }
    if (url.pathname.endsWith('/zones') && method === 'GET') {
      const nameFilter = url.searchParams.get('name');
      const all = [
        { id: ZONE_A_ID, name: 'example.org', status: 'active', account: { id: ACCOUNT_ID, name: 'Demo Account' } },
        { id: ZONE_B_ID, name: 'other.example.com', status: 'active', account: { id: ACCOUNT_ID, name: 'Demo Account' } },
      ];
      const filtered = nameFilter ? all.filter(z => z.name === nameFilter) : all;
      return json({ success: true, result: filtered, result_info: { page: 1, total_pages: 1 } });
    }
    if (url.pathname.endsWith(`/zones/${ZONE_A_ID}`)) {
      return json({ success: true, result: { id: ZONE_A_ID, name: 'example.org', status: 'active' } });
    }
    if (url.pathname.endsWith(`/zones/${ZONE_B_ID}`)) {
      return json({ success: true, result: { id: ZONE_B_ID, name: 'other.example.com', status: 'active' } });
    }
    if (url.pathname.endsWith(`/zones/${ZONE_A_ID}/dns_records`) && method === 'GET') {
      return json({ success: true, result: dnsRecords, result_info: { page: 1, total_pages: 1 } });
    }
    if (url.pathname.endsWith(`/zones/${ZONE_A_ID}/dns_records`) && method === 'POST') {
      const created = { id: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', ...body };
      dnsRecords.push(created);
      return json({ success: true, result: created });
    }
    if (url.pathname.endsWith(`/zones/${ZONE_A_ID}/dns_records/${RECORD_ID}`) && method === 'GET') {
      return json({ success: true, result: dnsRecords.find(r => r.id === RECORD_ID) });
    }
    if (url.pathname.endsWith(`/zones/${ZONE_A_ID}/dns_records/${RECORD_ID}`) && method === 'DELETE') {
      dnsRecords = dnsRecords.filter(r => r.id !== RECORD_ID);
      return json({ success: true, result: { id: RECORD_ID } });
    }
    if (url.pathname.endsWith(`/zones/${ZONE_A_ID}/purge_cache`) && method === 'POST') {
      return json({ success: true, result: { id: ZONE_A_ID } });
    }
    if (url.pathname.includes(`/accounts/${ACCOUNT_ID}/d1/database/`) && url.pathname.endsWith('/query')) {
      return json({ success: true, result: [{ results: [{ ok: 1 }], success: true }] });
    }
    return json({ success: false, errors: [{ code: 404, message: `Unhandled mock path ${method} ${url.pathname}` }] }, 404);
  };

  return { fetchImpl, calls };
}

async function startTestServer(t, extra = {}) {
  const stateDir = await mkdtemp(join(tmpdir(), 'cf-mcp-test-'));
  const mock = createMockFetch();
  const service = await createHttpApp({
    stateDir,
    adminPassword: 'test-password-1234',
    enableUnauthLocalMcp: true,
    clientOptions: { fetchImpl: mock.fetchImpl },
    ...extra,
  });
  const server = createServer(service.app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;
  t.after(async () => {
    await service.close();
    await new Promise(resolve => server.close(resolve));
    await rm(stateDir, { recursive: true, force: true });
  });
  return { baseUrl, stateDir, mock };
}

async function parseMcpResponse(res) {
  const ctype = res.headers.get('content-type') || '';
  const text = await res.text();
  if (ctype.includes('text/event-stream')) {
    const dataLine = text.split('\n').filter(line => line.startsWith('data:')).pop();
    return dataLine ? JSON.parse(dataLine.slice(5).trim()) : null;
  }
  return text ? JSON.parse(text) : null;
}

async function openMcpClient(endpoint) {
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  };
  const initRes = await fetch(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0' } },
    }),
  });
  assert.equal(initRes.status, 200);
  const sessionId = initRes.headers.get('mcp-session-id');
  assert.ok(sessionId);
  await parseMcpResponse(initRes);

  let nextId = 2;
  async function rpc(method, params = {}) {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { ...headers, 'Mcp-Session-Id': sessionId },
      body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
    });
    const body = await parseMcpResponse(res);
    return { status: res.status, body };
  }
  return { sessionId, rpc };
}

test('渐进式 3 元工具压缩率超过 85% 且严格仅暴露 3 个元工具', () => {
  const meta = listMetaTools();
  assert.deepEqual(meta.tools.map(t => t.name), ['cf_discover', 'cf_describe', 'cf_execute']);
  const metrics = getCatalogMetrics();
  assert.equal(metrics.exposedTools, 3);
  assert.ok(metrics.totalActions >= 30, `expected >=30 actions, got ${metrics.totalActions}`);
  assert.ok(metrics.estimatedSavedPercent >= 85, `expected >=85% saved, got ${metrics.estimatedSavedPercent}%`);
  console.log(`Cloudflare 渐进式披露实测：${metrics.legacyFullBytes} → ${metrics.progressiveBytes} 字节（节省 ${metrics.estimatedSavedPercent}%，覆盖 ${metrics.totalActions} 动作）`);
});

test('D1 只读 SQL 校验拦截写语句与多语句注入，放行纯 SELECT / PRAGMA 并包上限保护', () => {
  assert.equal(prepareReadonlySql('SELECT id, name FROM users LIMIT 10;'), 'SELECT * FROM (\nSELECT id, name FROM users LIMIT 10\n) LIMIT 1000');
  assert.equal(prepareReadonlySql('PRAGMA table_info(users)'), 'PRAGMA table_info(users)');
  assert.throws(() => prepareReadonlySql('DELETE FROM users WHERE id = 1'));
  assert.throws(() => prepareReadonlySql('SELECT 1; DROP TABLE users'));
  assert.throws(() => prepareReadonlySql('UPDATE users SET role = "admin"'));
  assert.throws(() => prepareReadonlySql('INSERT INTO users VALUES (1)'));
});

test('AES-256-GCM 加密保管 API Token、重启重读并严防明文泄露', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'cf-cred-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store1 = await CredentialStore.open(dir, {});
  assert.equal(store1.getPublicStatus().configured, false);
  await store1.saveToken(TEST_TOKEN, { verifyStatus: 'ok', verifyMessage: 'ok', defaultAccountId: ACCOUNT_ID }, store1.revision);
  const pub = store1.getPublicStatus();
  assert.equal(pub.configured, true);
  assert.ok(!JSON.stringify(pub).includes(TEST_TOKEN), 'public status must never expose raw token');

  const store2 = await CredentialStore.open(dir, {});
  assert.equal(store2.getActiveToken().token, TEST_TOKEN);
  assert.equal(store2.getPublicStatus().defaultAccountId, ACCOUNT_ID);
});

test('完整端到端流程：管理台登录/加密存 Token/四维权限链接/渐进式发现与执行/高危预览确认/吊销断连/审计日志', async (t) => {
  const { baseUrl, mock } = await startTestServer(t);

  // 1. 健康检查
  const healthRes = await fetch(`${baseUrl}/health`);
  assert.equal(healthRes.status, 200);
  const health = await healthRes.json();
  assert.equal(health.progressiveTools, 3);
  assert.equal(health.tokenConfigured, false);

  // 2. 管理台登录
  const loginRes = await fetch(`${baseUrl}/cloudflare-admin/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'test-password-1234' }),
  });
  assert.equal(loginRes.status, 200);
  const cookie = loginRes.headers.get('set-cookie').split(';')[0];
  const authHeaders = { 'Content-Type': 'application/json', Cookie: cookie };

  // 3. 保存并验活 API Token
  const credRes = await fetch(`${baseUrl}/cloudflare-admin/api/credentials`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ apiToken: TEST_TOKEN }),
  });
  assert.equal(credRes.status, 200);
  const credData = await credRes.json();
  assert.equal(credData.token.configured, true);
  assert.equal(credData.token.verifyStatus, 'ok');
  assert.ok(!JSON.stringify(credData).includes(TEST_TOKEN));

  // 4. 创建只读+仅限 DNS/Zones+锁域 example.org 的链接
  const roRes = await fetch(`${baseUrl}/cloudflare-admin/api/links`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      name: '只读锁域巡检',
      accessLevel: 'read',
      allowedModules: ['zones', 'dns'],
      allowedZones: ['example.org'],
    }),
  });
  assert.equal(roRes.status, 201);
  const { link: roLink } = await roRes.json();

  const roClient = await openMcpClient(roLink.url);
  const toolsResp = await roClient.rpc('tools/list');
  assert.deepEqual(toolsResp.body.result.tools.map(x => x.name), ['cf_discover', 'cf_describe', 'cf_execute']);

  // 发现接口只能看到 zones/dns 的 read 动作，绝不泄露 workers 或 write/admin 动作
  const discResp = await roClient.rpc('tools/call', { name: 'cf_discover', arguments: {} });
  const discJson = JSON.parse(discResp.body.result.content[0].text);
  assert.ok(discJson.actions.every(a => a.access === 'read' && ['zones', 'dns'].includes(a.module)));

  // 只读链接尝试调用写动作 dns.create 被拒绝
  const deniedWrite = await roClient.rpc('tools/call', {
    name: 'cf_execute',
    arguments: { action: 'dns.create', params: { zone: 'example.org', type: 'A', name: 'x.example.org', content: '1.1.1.1' } },
  });
  assert.equal(deniedWrite.body.result.isError, true);

  // 域名锁：查询未授权域名 other.example.com 被拒绝，查询 example.org 成功
  const deniedZone = await roClient.rpc('tools/call', {
    name: 'cf_execute',
    arguments: { action: 'dns.list', params: { zone: 'other.example.com' } },
  });
  assert.equal(deniedZone.body.result.isError, true);

  const descResp = await roClient.rpc('tools/call', {
    name: 'cf_describe',
    arguments: { actions: ['dns.list'], guide: 'dns' },
  });
  assert.equal(descResp.body.result.isError, undefined);
  const descJson = JSON.parse(descResp.body.result.content[0].text);
  assert.equal(descJson.actions[0].action, 'dns.list');
  assert.ok(descJson.actions[0].jsonSchema);
  assert.ok(descJson.guide?.title);

  const okZone = await roClient.rpc('tools/call', {
    name: 'cf_execute',
    arguments: { action: 'dns.list', params: { zone: 'example.org' } },
  });
  assert.equal(okZone.body.result.isError, undefined);
  const dnsData = JSON.parse(okZone.body.result.content[0].text);
  const items = dnsData.result.result ?? dnsData.result;
  assert.equal(items[0].name, 'api.example.org');

  // 5. 创建 admin 链接测试高危删除预览护栏 + 二次确认执行 + 吊销踢断会话
  const adminLinkRes = await fetch(`${baseUrl}/cloudflare-admin/api/links`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ name: '全权运维测试', accessLevel: 'admin', allowedModules: null, allowedZones: null }),
  });
  assert.equal(adminLinkRes.status, 201);
  const { link: adminLink } = await adminLinkRes.json();
  const adminClient = await openMcpClient(adminLink.url);

  // 高危删除未带 confirm -> 返回预览且未发 DELETE 请求
  const previewRes = await adminClient.rpc('tools/call', {
    name: 'cf_execute',
    arguments: { action: 'dns.delete', params: { zone: 'example.org', record_id: RECORD_ID } },
  });
  assert.equal(previewRes.body.result.isError, undefined);
  const previewBody = JSON.parse(previewRes.body.result.content[0].text);
  assert.equal(previewBody.status, 'preview');
  assert.equal(mock.calls.filter(c => c.method === 'DELETE').length, 0);

  // 带上 confirm: true -> 真正执行删除
  const execRes = await adminClient.rpc('tools/call', {
    name: 'cf_execute',
    arguments: { action: 'dns.delete', params: { zone: 'example.org', record_id: RECORD_ID }, confirm: true },
  });
  assert.equal(execRes.body.result.isError, undefined);
  assert.equal(mock.calls.filter(c => c.method === 'DELETE').length, 1);

  // 吊销链接后立即踢断活跃会话
  const revRes = await fetch(`${baseUrl}/cloudflare-admin/api/links/${encodeURIComponent(adminLink.id)}`, {
    method: 'DELETE',
    headers: authHeaders,
  });
  assert.equal(revRes.status, 200);
  const afterRevoke = await adminClient.rpc('tools/list');
  assert.equal(afterRevoke.status, 404);

  // 6. 审计日志包含 ok / preview / denied 记录且无明文 Token
  const auditRes = await fetch(`${baseUrl}/cloudflare-admin/api/audit?limit=50`, { headers: authHeaders });
  assert.equal(auditRes.status, 200);
  const auditJson = await auditRes.json();
  const statuses = new Set(auditJson.records.map(r => r.status));
  assert.ok(statuses.has('ok'));
  assert.ok(statuses.has('preview'));
  assert.ok(statuses.has('denied'));
  assert.ok(!JSON.stringify(auditJson).includes(TEST_TOKEN));
});
