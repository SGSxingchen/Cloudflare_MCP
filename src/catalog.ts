import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { type CloudflareClient, type CloudflareRequestOptions, zoneAllowed } from './cloudflare-client.js';
import { prepareReadonlySql } from './d1-readonly.js';
import { HttpError } from './errors.js';
import type { AccessLevel } from './link-store.js';

export const MODULES = [
  { id: 'account', title: '账号', summary: '查找账号标识，查看账号信息。' },
  { id: 'zones', title: '域名', summary: '查看托管域名、接入状态与域名设置。' },
  { id: 'dns', title: 'DNS', summary: '查询、新增、修改与删除解析记录。' },
  { id: 'cache', title: '缓存', summary: '查看缓存级别，按范围清理缓存。' },
  { id: 'ssl', title: 'SSL/TLS', summary: '查看加密模式与边缘证书，调整 HTTPS 设置。' },
  { id: 'security', title: '安全', summary: '查看域名规则集，维护自定义 WAF 规则。' },
  { id: 'workers', title: 'Workers', summary: '查看脚本、配置和路由，删除停用的脚本。' },
  { id: 'pages', title: 'Pages', summary: '查看站点项目和部署记录，回滚生产部署。' },
  { id: 'storage', title: '存储', summary: '管理 KV 文本值，查看 R2 与 D1，执行 D1 只读查询。' },
  { id: 'tunnels', title: '隧道', summary: '查看 Cloudflare Tunnel 及其连接状态。' },
] as const;

type ModuleId = (typeof MODULES)[number]['id'];
type ActionName = `${ModuleId}.${string}`;
type Query = NonNullable<CloudflareRequestOptions['query']>;

export const GUIDES = {
  safety: {
    title: '操作与确认',
    steps: [
      '用 cf_discover 查找当前链接可用的动作，再用 cf_describe 查看所需参数。',
      '变更前可用 cf_execute 的 dry_run: true 查看目标。高风险动作默认返回预览。',
      '核对预览后，如需执行，重发相同动作和参数并设置 confirm: true。每次调用都会重新验证当前授权。',
    ],
  },
  account: {
    title: '确认账号',
    steps: ['使用 account.list 查找账号 ID，再用 account.get 查看账号信息。多账号环境下建议显式传入 account_id。'],
  },
  zones: {
    title: '定位域名',
    steps: ['用 zones.list 查看授权范围内的域名。执行域名动作时传入域名或 zone ID。同名域名须使用 ID。'],
  },
  dns: {
    title: '修改 DNS 记录',
    steps: [
      '用 dns.list 查看现有记录，复制结果中的 id 作为 record_id。',
      '通过 dns.update 更新记录时，仅传要修改的字段。',
      '删除前，用 dns.delete 的预览核对原始名称、类型和内容。',
    ],
  },
  cache: {
    title: '清理缓存',
    steps: [
      '用 cache.get_level 查看当前缓存级别。',
      '使用 cache.purge 时，优先传 files 清理需要刷新的完整地址。全量清理可能增加源站负载，请核对预览中的范围。',
    ],
  },
  ssl: {
    title: '检查加密模式与证书',
    steps: [
      '用 ssl.get_mode 和 ssl.list_certificates 核对模式和证书状态。',
      '通过 ssl.set_mode 切换至严格模式前，确认源站证书有效且覆盖相应主机名。',
    ],
  },
  security: {
    title: '维护自定义 WAF 规则',
    steps: [
      '用 security.list_rulesets 找到自定义规则集，再通过 security.get_ruleset 核对现有表达式和动作。',
      '通过 security.update_rule 提交完整的新规则定义，检查是否会改变正常流量的处理。',
    ],
  },
  workers: {
    title: '检查脚本与域名路由',
    steps: [
      '用 workers.list_scripts 找到脚本。',
      '用 workers.list_routes 检查域名关联。',
      '在确认 workers.delete_script 前，请核对其他应用对该脚本的依赖。',
    ],
  },
  pages: {
    title: '排查站点部署',
    steps: [
      '用 pages.list_projects 查找项目名称。',
      '用 pages.list_deployments 查看对应环境下的部署，结合状态和地址定位问题。',
      '用 pages.rollback_deployment 核对当前生产版本与目标版本，确认后回滚。',
    ],
  },
  storage: {
    title: '访问 KV、R2 与 D1',
    steps: [
      '先列出资源，确认账号和目标 ID。KV 键名区分大小写，游标应使用上一页的 pagination.cursor。',
      'D1 查询仅接受单条 SELECT、白名单内的只读 PRAGMA 或 EXPLAIN SELECT。使用 params 绑定查询值。',
    ],
  },
  tunnels: {
    title: '检查隧道连接',
    steps: ['先查询隧道列表，再按 tunnel_id 查看隧道详情和当前状态。'],
  },
} as const;

interface ActionContext {
  client: CloudflareClient;
  zoneId?: string;
  accountId?: string;
  allowedZones: readonly string[] | null;
}

export interface ActionDefinition {
  action: string;
  module: ModuleId;
  title: string;
  summary: string;
  access: AccessLevel;
  destructive: boolean;
  requiresConfirm: boolean;
  zoneScoped: boolean;
  accountScoped: boolean;
  supportsZoneScope?: boolean;
  zodSchema: z.ZodType;
  jsonSchema: Tool['inputSchema'];
  examples: readonly unknown[];
  notes: readonly string[];
  handler: (context: ActionContext, params: unknown) => Promise<unknown>;
  preview?: (context: ActionContext, params: unknown) => unknown;
  confirmWhen?: (params: unknown) => boolean;
}

function inputSchema(schema: z.ZodType): Tool['inputSchema'] {
  const { $schema, properties = {}, ...fields } = z.toJSONSchema(schema, { io: 'input', target: 'draft-07' });
  return {
    ...fields,
    type: 'object',
    properties: Object.fromEntries(Object.entries(properties).map(([key, value]) =>
      [key, typeof value === 'boolean' ? (value ? {} : { not: {} }) : value])),
  };
}

type ActionOptions<S extends z.ZodType> = Pick<ActionDefinition, 'title' | 'summary' | 'supportsZoneScope'> & {
  access?: AccessLevel;
  scope?: 'zone' | 'account';
  destructive?: boolean;
  requiresConfirm?: boolean;
  example?: z.input<S>;
  notes?: readonly string[];
  handler: (context: ActionContext, params: z.output<S>) => Promise<unknown>;
  preview?: (context: ActionContext, params: z.output<S>) => unknown;
};

function defineAction<S extends z.ZodType>(name: ActionName, schema: S, options: ActionOptions<S>): ActionDefinition {
  const { access = 'read', scope, destructive = false, requiresConfirm = destructive, example = {}, notes = [],
    handler, preview, ...details } = options;
  return {
    ...details, action: name, module: name.slice(0, name.indexOf('.')) as ModuleId, access,
    destructive, requiresConfirm, zoneScoped: scope === 'zone', accountScoped: scope === 'account',
    zodSchema: schema, jsonSchema: inputSchema(schema), examples: [example], notes,
    // 调用端在将参数交给处理函数之前，已经使用本动作的 schema 完成解析。
    handler: handler as ActionDefinition['handler'],
    preview: preview as ActionDefinition['preview'],
  };
}

const moduleIds = MODULES.map(module => module.id);
const actionName = z.string().min(3).max(80).describe('发现结果中的动作名');

export const META_TOOLS = {
  cf_discover: {
    description: '查找当前链接可用的 Cloudflare 动作。可按模块或关键词筛选。',
    schema: z.strictObject({ module: z.enum(moduleIds).optional(), query: z.string().max(200).optional() }),
  },
  cf_describe: {
    description: '按需查看动作参数、示例与确认要求，或打开专题指南。',
    schema: z.strictObject({
      actions: z.array(actionName).min(1).max(6).optional(),
      guide: z.enum(['safety', ...moduleIds]).optional(),
    }),
  },
  cf_execute: {
    description: '执行一个 Cloudflare 动作。可先预览，高风险动作需要显式确认。',
    schema: z.strictObject({
      action: actionName,
      params: z.record(z.string(), z.unknown()).optional(),
      dry_run: z.boolean().optional(),
      confirm: z.boolean().optional(),
    }),
  },
};

export function listMetaTools() {
  const tools: Tool[] = Object.entries(META_TOOLS).map(([name, { description, schema }]) => ({
    name, description, inputSchema: inputSchema(schema),
  }));
  return { tools };
}

const zone = z.string().trim().min(1).max(254).describe('托管域名或 32 位 zone ID');
const hexId = z.string().trim().toLowerCase().regex(/^[a-f0-9]{32}$/u);
const uuid = z.uuid().toLowerCase();
const accountId = hexId.describe('账号 ID。省略时使用默认账号或自动识别').optional();
const empty = z.strictObject({});
const zoneInput = z.strictObject({ zone });
const accountInput = z.strictObject({ account_id: accountId });
const page = z.int().min(1).max(1_000_000).default(1).describe('从 1 开始的页码');
const perPage = z.int().min(1).max(100).default(50).describe('每页的结果数量');
const pageInput = { page, per_page: perPage };
const cursor = z.string().min(1).max(2_048).optional().describe('上一页响应的分页游标');

const EXAMPLE_ZONE = 'example.com';
const EXAMPLE_ID = '11111111111111111111111111111111';
const EXAMPLE_UUID = '11111111-1111-4111-8111-111111111111';
const zoneExample = { zone: EXAMPLE_ZONE };
const recordExample = { ...zoneExample, record_id: EXAMPLE_ID };
const rulesetExample = { ...zoneExample, ruleset_id: EXAMPLE_ID };
const ruleExample = { ...rulesetExample, rule_id: EXAMPLE_ID };
const scriptExample = { script_name: 'site-router' };
const projectExample = { project_name: 'docs' };
const namespaceExample = { namespace_id: EXAMPLE_ID };
const kvExample = { ...namespaceExample, key: 'site-title' };

function zonePath(context: ActionContext): string {
  if (!context.zoneId) throw new HttpError(500, '动作缺少域名标识');
  return `/zones/${context.zoneId}`;
}

function accountPath(context: ActionContext): string {
  if (!context.accountId) throw new HttpError(500, '动作缺少账号标识');
  return `/accounts/${context.accountId}`;
}

async function requestResult<T = unknown>(context: ActionContext, path: string, options?: CloudflareRequestOptions) {
  return (await context.client.request<T>(path, options)).result;
}

async function requestPage(context: ActionContext, path: string, query: Query) {
  const { result, resultInfo } = await context.client.request(path, { query });
  return { result, pagination: resultInfo ?? null };
}

const dnsType = z.enum([
  'A', 'AAAA', 'CAA', 'CERT', 'CNAME', 'DNSKEY', 'DS', 'HTTPS', 'LOC', 'MX',
  'NAPTR', 'NS', 'OPENPGPKEY', 'PTR', 'SMIMEA', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI',
]);
const dnsFields = {
  type: dnsType,
  name: z.string().trim().min(1).max(254).describe('DNS 记录名称'),
  content: z.string().min(1).max(8_192).optional().describe('A、CNAME、TXT 等记录的内容'),
  data: z.record(z.string(), z.unknown()).optional().describe('需要结构化数据的记录字段'),
  ttl: z.int().min(1).max(86_400).refine(value => value === 1 || value >= 30).optional()
    .describe('缓存有效期（秒），1 表示自动'),
  proxied: z.boolean().optional().describe('通过 Cloudflare 代理可代理的记录'),
  priority: z.int().min(0).max(65_535).optional().describe('MX 等记录的优先级'),
  comment: z.string().max(100).nullable().optional().describe('记录备注'),
};
const dnsRecordInput = zoneInput.extend({ record_id: hexId.describe('DNS 记录 ID') });
const dnsUpdate = dnsRecordInput.extend(z.strictObject(dnsFields).partial().shape)
  .refine(({ zone: _zone, record_id: _recordId, ...patch }) => Object.keys(patch).length > 0
    && !(patch.content !== undefined && patch.data !== undefined));
const dnsCreate = zoneInput.extend(dnsFields)
  .refine(({ content, data }) => (content !== undefined) !== (data !== undefined));

const dnsPath = (context: ActionContext, recordId?: string) => {
  const collection = `${zonePath(context)}/dns_records`;
  return recordId ? `${collection}/${recordId}` : collection;
};

const purgeInput = zoneInput.extend({
  files: z.array(z.httpUrl().max(2_048).refine(value => {
    const url = new URL(value);
    return !url.username && !url.password && !url.hash;
  })).min(1).max(30).optional().describe('待清除的完整 HTTP 或 HTTPS 地址'),
  purge_everything: z.literal(true).optional().describe('清理域名的全部边缘缓存'),
}).refine(input => Boolean(input.files) !== Boolean(input.purge_everything));

const settingPath = (context: ActionContext, setting: string) => `${zonePath(context)}/settings/${setting}`;
const sslMode = z.enum(['off', 'flexible', 'full', 'strict', 'origin_pull']);
const httpsToggle = z.enum(['on', 'off']);

const rulesetInput = zoneInput.extend({ ruleset_id: hexId.describe('规则集 ID') });
const ruleInput = rulesetInput.extend({ rule_id: hexId.describe('规则 ID') });
const ruleFields = {
  action: z.enum(['block', 'challenge', 'js_challenge', 'managed_challenge', 'log']),
  expression: z.string().trim().min(1).max(4_096).describe('Cloudflare 规则匹配表达式'),
  description: z.string().max(500).optional(),
  enabled: z.boolean().describe('启用规则'),
};
const rulesetPath = (context: ActionContext, rulesetId: string) => `${zonePath(context)}/rulesets/${rulesetId}`;

async function readWritableRuleset(context: ActionContext, rulesetId: string) {
  const ruleset = await requestResult<{ phase?: string; rules?: { id?: string }[] }>(context, rulesetPath(context, rulesetId));
  if (ruleset?.phase !== 'http_request_firewall_custom') {
    throw new HttpError(403, '该动作仅允许维护域名的自定义 WAF 规则');
  }
  return ruleset;
}

async function readWritableRule(context: ActionContext, rulesetId: string, ruleId: string) {
  const { rules } = await readWritableRuleset(context, rulesetId);
  if (!Array.isArray(rules)) throw new HttpError(502, 'Cloudflare 未返回有效的规则列表');
  const rule = rules.find(item => item?.id === ruleId);
  if (!rule) throw new HttpError(404, '规则集内找不到该规则');
  return rule;
}

const scriptInput = accountInput.extend({
  script_name: z.string().min(1).max(128).regex(/^[a-z0-9][a-z0-9_-]*$/iu).describe('Worker 脚本名称'),
});
const projectInput = accountInput.extend({
  project_name: z.string().min(1).max(128).regex(/^[a-z0-9][a-z0-9-]*$/u).describe('Pages 项目名称'),
});
const workerPath = (context: ActionContext, script: string) => `${accountPath(context)}/workers/scripts/${script}`;
const projectPath = (context: ActionContext, project: string) => `${accountPath(context)}/pages/projects/${project}`;
const workerSettingsPath = (context: ActionContext, script: string) => `${workerPath(context, script)}/settings`;

function selectFields(value: unknown, keys: readonly string[]) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new HttpError(502, 'Cloudflare 资源结构无效');
  const row = value as Record<string, unknown>;
  return Object.fromEntries(keys.filter(key => Object.hasOwn(row, key)).map(key => [key, row[key]]));
}

const projectFields = ['id', 'name', 'subdomain', 'domains', 'created_on', 'production_branch', 'uses_functions'];
const deploymentFields = ['id', 'aliases', 'created_on', 'modified_on', 'environment', 'project_name', 'url', 'latest_stage'];
const workerSettingsFields = ['compatibility_date', 'compatibility_flags', 'logpush', 'observability', 'usage_model', 'limits'];

async function readRollbackTarget(context: ActionContext, path: string, deploymentId: string) {
  const deployment = await requestResult<{
    id?: string;
    environment?: string;
    is_skipped?: boolean;
    latest_stage?: { name?: string; status?: string };
  }>(context, path);
  if (typeof deployment?.id !== 'string' || deployment.id.toLowerCase() !== deploymentId) {
    throw new HttpError(502, 'Cloudflare Pages 返回的部署标识无效');
  }
  if (deployment.environment !== 'production' || deployment.is_skipped === true
    || deployment.latest_stage?.name !== 'deploy' || deployment.latest_stage.status !== 'success') {
    throw new HttpError(409, '只能回滚至已经成功部署的生产版本');
  }
  return selectFields(deployment, deploymentFields);
}

function selectPage(page: { result: unknown; pagination: unknown }, fields: readonly string[]) {
  if (!Array.isArray(page.result)) throw new HttpError(502, 'Cloudflare 分页结果格式无效');
  return { ...page, result: page.result.map(row => selectFields(row, fields)) };
}

const namespaceInput = accountInput.extend({ namespace_id: hexId.describe('KV 命名空间 ID') });
const kvInput = namespaceInput.extend({
  key: z.string().min(1).max(512).refine(key => key !== '.' && key !== '..'
    && !/[\u0000-\u001f\u007f]/u.test(key) && !/\p{Surrogate}/u.test(key) && Buffer.byteLength(key) <= 512)
    .describe('区分大小写的 KV 键名，最多 512 字节'),
});
const kvPath = (context: ActionContext, namespaceId: string) =>
  `${accountPath(context)}/storage/kv/namespaces/${namespaceId}`;

const d1QueryInput = accountInput.extend({
  database_id: uuid.describe('D1 数据库 UUID'),
  sql: z.string().trim().min(1).max(16_384)
    .describe('单条 SELECT、白名单内的只读 PRAGMA 或 EXPLAIN SELECT')
    .transform(prepareReadonlySql),
  params: z.array(z.string().max(8_192)).max(100).optional().describe('按顺序绑定的字符串参数'),
});

export const ACTIONS: readonly ActionDefinition[] = [
  defineAction('account.list', empty, {
    title: '列出账号', summary: '列出当前凭据可访问的账号 ID 和名称。',
    handler: ({ client }) => client.listAccounts(),
  }),
  defineAction('account.get', accountInput, {
    title: '查看账号', summary: '查看指定账号及其设置。', scope: 'account', example: { account_id: EXAMPLE_ID },
    handler: context => requestResult(context, accountPath(context)),
  }),
  defineAction('zones.list', empty, {
    title: '列出域名', summary: '列出当前链接可访问的托管域名及接入状态。', supportsZoneScope: true,
    handler: async ({ client, allowedZones }) =>
      (await client.listAllZones()).filter(item => zoneAllowed(item, allowedZones)),
  }),
  defineAction('zones.get', zoneInput, {
    title: '查看域名', summary: '查看域名详情，包括状态、套餐与名称服务器。', scope: 'zone', example: zoneExample,
    handler: context => requestResult(context, zonePath(context)),
  }),
  defineAction('zones.get_setting', zoneInput.extend({
    setting: z.enum(['always_use_https', 'automatic_https_rewrites', 'browser_cache_ttl', 'cache_level',
      'development_mode', 'http2', 'http3', 'ipv6', 'min_tls_version', 'security_level', 'ssl']),
  }), {
    title: '查看域名设置', summary: '查询指定域名的一项常用配置。', scope: 'zone',
    example: { ...zoneExample, setting: 'http3' },
    handler: (context, { setting }) => requestResult(context, settingPath(context, setting)),
  }),
  defineAction('dns.list', zoneInput.extend({
    ...pageInput, type: dnsType.optional(), name: dnsFields.name.optional().describe('精确匹配的 DNS 记录名称'),
  }), {
    title: '列出 DNS 记录', summary: '按名称或类型查询一页 DNS 记录，返回分页信息。', scope: 'zone',
    example: { ...zoneExample, type: 'A', page: 1 },
    handler: (context, { zone: _zone, name, ...query }) =>
      requestPage(context, dnsPath(context), { ...query, 'name.exact': name }),
  }),
  defineAction('dns.get', dnsRecordInput, {
    title: '查看 DNS 记录', summary: '按记录 ID 查询其当前内容、缓存时间和代理状态。', scope: 'zone',
    example: recordExample,
    handler: (context, { record_id }) => requestResult(context, dnsPath(context, record_id)),
  }),
  defineAction('dns.create', dnsCreate, {
    title: '新增 DNS 记录', summary: '为指定域名新增解析记录。', access: 'write', scope: 'zone',
    example: { ...zoneExample, type: 'A', name: 'www.example.com', content: '192.0.2.10', ttl: 1 },
    notes: ['content 与 data 二选一。MX 记录应同时设置 priority。'],
    preview: (_context, { zone: _zone, ...record }) => ({ record }),
    handler: (context, { zone: _zone, ...body }) => requestResult(context, dnsPath(context), { method: 'POST', body }),
  }),
  defineAction('dns.update', dnsUpdate, {
    title: '修改 DNS 记录', summary: '按记录 ID 部分修改解析记录。', access: 'write', scope: 'zone',
    example: { ...recordExample, content: '192.0.2.20' },
    notes: ['至少提供一个要修改的字段，content 和 data 不能同时提交。'],
    preview: async (context, { zone: _zone, record_id, ...changes }) =>
      ({ record: await requestResult(context, dnsPath(context, record_id)), changes }),
    handler: (context, { zone: _zone, record_id, ...body }) =>
      requestResult(context, dnsPath(context, record_id), { method: 'PATCH', body }),
  }),
  defineAction('dns.delete', dnsRecordInput, {
    title: '删除 DNS 记录', summary: '预览原记录，确认后按 ID 删除。', access: 'admin', scope: 'zone',
    destructive: true, example: recordExample,
    notes: ['确认前核对原记录名称、类型及内容。删除可能中断服务访问。'],
    preview: async (context, { record_id }) => ({ record: await requestResult(context, dnsPath(context, record_id)) }),
    handler: (context, { record_id }) => requestResult(context, dnsPath(context, record_id), { method: 'DELETE' }),
  }),
  defineAction('cache.get_level', zoneInput, {
    title: '查看缓存级别', summary: '读取域名的缓存级别设置。', scope: 'zone', example: zoneExample,
    handler: context => requestResult(context, settingPath(context, 'cache_level')),
  }),
  defineAction('cache.purge', purgeInput, {
    title: '清理缓存', summary: '按 URL 清理缓存，或确认后清理整个域名的边缘缓存。', access: 'write', scope: 'zone',
    requiresConfirm: true, example: { ...zoneExample, files: ['https://example.com/assets/site.css'] },
    notes: ['files 与 purge_everything 二选一。全量清理可能增加源站负载。'],
    preview: (_context, { zone: _zone, ...scope }) => scope,
    handler: (context, { zone: _zone, ...body }) =>
      requestResult(context, `${zonePath(context)}/purge_cache`, { method: 'POST', body }),
  }),
  defineAction('ssl.get_mode', zoneInput, {
    title: '查看加密模式', summary: '读取域名当前使用的 SSL/TLS 加密模式。', scope: 'zone', example: zoneExample,
    handler: context => requestResult(context, settingPath(context, 'ssl')),
  }),
  defineAction('ssl.set_mode', zoneInput.extend({ value: sslMode.describe('新的 SSL/TLS 加密模式') }), {
    title: '修改加密模式', summary: '确认当前模式和所选模式后修改 SSL/TLS 加密设置。', access: 'write',
    scope: 'zone', requiresConfirm: true, example: { ...zoneExample, value: 'strict' },
    notes: ['更换模式前应核对源站证书与跳转设置，避免连接错误。'],
    preview: async (context, { value }) => ({ current: await requestResult(context, settingPath(context, 'ssl')), value }),
    handler: (context, { value }) => requestResult(context, settingPath(context, 'ssl'), { method: 'PATCH', body: { value } }),
  }),
  defineAction('ssl.set_always_use_https', zoneInput.extend({ value: httpsToggle }), {
    title: '设置始终使用 HTTPS', summary: '启用或停用域名的 HTTP 到 HTTPS 跳转。', access: 'write',
    scope: 'zone', requiresConfirm: true, example: { ...zoneExample, value: 'on' },
    preview: async (context, { value }) =>
      ({ current: await requestResult(context, settingPath(context, 'always_use_https')), value }),
    handler: (context, { value }) =>
      requestResult(context, settingPath(context, 'always_use_https'), { method: 'PATCH', body: { value } }),
  }),
  defineAction('ssl.list_certificates', zoneInput, {
    title: '列出边缘证书包', summary: '查看边缘证书包的状态和覆盖的主机名。', scope: 'zone', example: zoneExample,
    handler: context => requestResult(context, `${zonePath(context)}/ssl/certificate_packs`, { query: { status: 'all' } }),
  }),
  defineAction('security.list_rulesets', zoneInput.extend({ cursor, per_page: perPage }), {
    title: '列出规则集', summary: '分页查询指定域名上的规则集和处理阶段。', scope: 'zone', example: zoneExample,
    handler: (context, { zone: _zone, ...query }) => requestPage(context, `${zonePath(context)}/rulesets`, query),
  }),
  defineAction('security.get_ruleset', rulesetInput, {
    title: '查看规则集', summary: '查看规则集版本和其中的规则定义。', scope: 'zone', example: rulesetExample,
    handler: (context, { ruleset_id }) => requestResult(context, rulesetPath(context, ruleset_id)),
  }),
  defineAction('security.create_rule', rulesetInput.extend({ ...ruleFields, enabled: ruleFields.enabled.default(true) }), {
    title: '新增自定义 WAF 规则', summary: '将经过确认的匹配规则添加到域名自定义防火墙。', access: 'write',
    scope: 'zone', requiresConfirm: true,
    example: { ...rulesetExample, action: 'managed_challenge', expression: 'http.request.uri.path eq "/private"' },
    preview: async (context, { zone: _zone, ruleset_id, ...rule }) => {
      await readWritableRuleset(context, ruleset_id);
      return { ruleset_id, rule };
    },
    handler: async (context, { zone: _zone, ruleset_id, ...body }) => {
      await readWritableRuleset(context, ruleset_id);
      return requestResult(context, `${rulesetPath(context, ruleset_id)}/rules`, { method: 'POST', body });
    },
  }),
  defineAction('security.update_rule', ruleInput.extend(ruleFields), {
    title: '修改自定义 WAF 规则', summary: '核对现有规则后应用新的规则定义。', access: 'admin',
    scope: 'zone', requiresConfirm: true,
    example: { ...ruleExample, action: 'block', expression: 'http.request.uri.path eq "/private"', enabled: true },
    notes: ['提交完整的新规则定义，包括应保留的字段。'],
    preview: async (context, { zone: _zone, ruleset_id, rule_id, ...next }) =>
      ({ rule: await readWritableRule(context, ruleset_id, rule_id), next }),
    handler: async (context, { zone: _zone, ruleset_id, rule_id, ...body }) => {
      await readWritableRule(context, ruleset_id, rule_id);
      return requestResult(context, `${rulesetPath(context, ruleset_id)}/rules/${rule_id}`, { method: 'PATCH', body });
    },
  }),
  defineAction('security.delete_rule', ruleInput, {
    title: '删除自定义 WAF 规则', summary: '确认原规则和影响范围后将其移除。', access: 'admin',
    scope: 'zone', destructive: true, example: ruleExample,
    preview: async (context, { ruleset_id, rule_id }) =>
      ({ rule: await readWritableRule(context, ruleset_id, rule_id) }),
    handler: async (context, { ruleset_id, rule_id }) => {
      await readWritableRule(context, ruleset_id, rule_id);
      return requestResult(context, `${rulesetPath(context, ruleset_id)}/rules/${rule_id}`, { method: 'DELETE' });
    },
  }),
  defineAction('workers.list_scripts', accountInput, {
    title: '列出 Worker 脚本', summary: '查看账号中的 Worker 脚本及更新时间。', scope: 'account',
    handler: context => requestResult(context, `${accountPath(context)}/workers/scripts`),
  }),
  defineAction('workers.get_script_settings', scriptInput, {
    title: '查看 Worker 脚本设置', summary: '查询脚本的运行配置与兼容性选项。', scope: 'account', example: scriptExample,
    handler: async (context, { script_name }) =>
      selectFields(await requestResult(context, workerSettingsPath(context, script_name)), workerSettingsFields),
  }),
  defineAction('workers.list_routes', zoneInput, {
    title: '列出 Worker 路由', summary: '查看域名上关联 Worker 脚本的匹配路由。', scope: 'zone', example: zoneExample,
    handler: context => requestResult(context, `${zonePath(context)}/workers/routes`),
  }),
  defineAction('workers.delete_script', scriptInput, {
    title: '删除 Worker 脚本', summary: '预览脚本信息，确认后删除指定脚本。', access: 'admin',
    scope: 'account', destructive: true, example: scriptExample,
    notes: ['核对域名路由及其他应用对脚本的依赖，删除可能中断服务。'],
    preview: async (context, { script_name }) => ({
      script_name,
      settings: selectFields(await requestResult(context, workerSettingsPath(context, script_name)), workerSettingsFields),
    }),
    handler: (context, { script_name }) => requestResult(context, workerPath(context, script_name), { method: 'DELETE' }),
  }),
  defineAction('pages.list_projects', accountInput.extend(pageInput), {
    title: '列出 Pages 项目', summary: '分页查看账号下的 Pages 项目、域名和生产分支。', scope: 'account',
    handler: async (context, { account_id: _accountId, ...query }) =>
      selectPage(await requestPage(context, `${accountPath(context)}/pages/projects`, query), projectFields),
  }),
  defineAction('pages.list_deployments', projectInput.extend({
    ...pageInput, env: z.enum(['production', 'preview']).optional(),
  }), {
    title: '列出 Pages 部署', summary: '分页查询生产或预览部署的状态与地址。', scope: 'account',
    example: { ...projectExample, env: 'production' },
    handler: async (context, { account_id: _accountId, project_name, ...query }) =>
      selectPage(await requestPage(context, `${projectPath(context, project_name)}/deployments`, query), deploymentFields),
  }),
  defineAction('pages.rollback_deployment', projectInput.extend({ deployment_id: uuid.describe('目标部署 UUID') }), {
    title: '回滚 Pages 生产部署', summary: '预览当前生产版本与目标部署，确认后切换生产版本。',
    scope: 'account', access: 'admin', requiresConfirm: true,
    example: { ...projectExample, deployment_id: EXAMPLE_UUID },
    notes: ['目标须为已经成功部署的生产版本。回滚会立即变更生产站点。'],
    preview: async (context, { project_name, deployment_id }) => {
      const path = projectPath(context, project_name);
      const [project, deployment] = await Promise.all([
        requestResult<{ canonical_deployment?: unknown }>(context, path),
        readRollbackTarget(context, `${path}/deployments/${deployment_id}`, deployment_id),
      ]);
      const current = project?.canonical_deployment;
      return { project_name, current: current == null ? null : selectFields(current, deploymentFields), deployment };
    },
    handler: async (context, { project_name, deployment_id }) => {
      const path = `${projectPath(context, project_name)}/deployments/${deployment_id}`;
      await readRollbackTarget(context, path, deployment_id);
      return selectFields(await requestResult(context, `${path}/rollback`, { method: 'POST' }), deploymentFields);
    },
  }),
  defineAction('storage.list_kv_namespaces', accountInput.extend(pageInput), {
    title: '列出 KV 命名空间', summary: '分页查询 KV 命名空间名称及 ID。', scope: 'account',
    handler: (context, { account_id: _accountId, ...query }) =>
      requestPage(context, `${accountPath(context)}/storage/kv/namespaces`, query),
  }),
  defineAction('storage.list_kv_keys', namespaceInput.extend({
    cursor, limit: z.int().min(10).max(1_000).default(50), prefix: z.string().max(512).optional(),
  }), {
    title: '列出 KV 键名', summary: '在命名空间内按前缀和游标查找键名。', scope: 'account', example: namespaceExample,
    handler: (context, { account_id: _accountId, namespace_id, ...query }) =>
      requestPage(context, `${kvPath(context, namespace_id)}/keys`, query),
  }),
  defineAction('storage.get_kv', kvInput, {
    title: '读取 KV 文本值', summary: '读取指定命名空间内一个键的文本值。', scope: 'account', example: kvExample,
    handler: (context, { namespace_id, key }) =>
      requestResult(context, `${kvPath(context, namespace_id)}/values/${encodeURIComponent(key)}`, { responseType: 'text' }),
  }),
  defineAction('storage.put_kv', kvInput.extend({
    value: z.string().max(65_536).describe('写入的 UTF-8 文本'),
    expiration_ttl: z.int().min(60).optional().describe('从写入起计算的有效时间，单位为秒'),
  }), {
    title: '写入 KV 文本值', summary: '确认后写入一个文本值，可能覆盖已有键。', access: 'write',
    scope: 'account', requiresConfirm: true, example: { ...kvExample, value: 'Example' },
    preview: (_context, { namespace_id, key, value, expiration_ttl }) =>
      ({ namespace_id, key, bytes: Buffer.byteLength(value), expiration_ttl }),
    handler: (context, { namespace_id, key, value, expiration_ttl }) =>
      requestResult(context, `${kvPath(context, namespace_id)}/values/${encodeURIComponent(key)}`, {
        method: 'PUT', body: value, contentType: 'application/octet-stream', query: { expiration_ttl },
      }),
  }),
  defineAction('storage.list_r2_buckets', accountInput.extend({
    cursor, per_page: perPage, name_contains: z.string().max(64).optional(),
  }), {
    title: '列出 R2 存储桶', summary: '分页查询存储桶名称、区域和存储类型。', scope: 'account',
    handler: (context, { account_id: _accountId, ...query }) =>
      requestPage(context, `${accountPath(context)}/r2/buckets`, query),
  }),
  defineAction('storage.list_d1_databases', accountInput.extend({
    page, per_page: z.int().min(10).max(100).default(50).describe('每页的结果数量'),
  }), {
    title: '列出 D1 数据库', summary: '分页查询账号下的 D1 数据库名称和 UUID。', scope: 'account',
    handler: (context, { account_id: _accountId, ...query }) =>
      requestPage(context, `${accountPath(context)}/d1/database`, query),
  }),
  defineAction('storage.query_d1_readonly', d1QueryInput, {
    title: '查询 D1 数据库', summary: '执行一条经过本地校验的只读 SQL。', scope: 'account',
    example: { database_id: EXAMPLE_UUID, sql: 'SELECT name FROM items WHERE id = ? LIMIT 1', params: ['42'] },
    notes: ['SELECT 最多返回 1000 行。使用绑定参数传值，SQL 中只允许一条语句。'],
    handler: async (context, { database_id, sql, params }) => {
      const result = await requestResult<{ success?: boolean }[]>(
        context, `${accountPath(context)}/d1/database/${database_id}/query`, { method: 'POST', body: { sql, params } },
      );
      if (!Array.isArray(result) || result.length !== 1 || !result[0] || typeof result[0] !== 'object'
        || Array.isArray(result[0]) || result[0].success === false) {
        throw new HttpError(502, 'Cloudflare D1 未返回成功的查询结果');
      }
      return result;
    },
  }),
  defineAction('tunnels.list', accountInput.extend({
    ...pageInput, is_deleted: z.boolean().default(false).describe('为 true 时只查询已删除的隧道'),
  }), {
    title: '列出隧道', summary: '分页查询 Cloudflare Tunnel 的名称与状态。', scope: 'account',
    handler: (context, { account_id: _accountId, ...query }) =>
      requestPage(context, `${accountPath(context)}/cfd_tunnel`, query),
  }),
  defineAction('tunnels.get', accountInput.extend({ tunnel_id: uuid.describe('Cloudflare Tunnel UUID') }), {
    title: '查看隧道', summary: '根据隧道 UUID 查询详细信息与当前状态。', scope: 'account', example: { tunnel_id: EXAMPLE_UUID },
    handler: (context, { tunnel_id }) => requestResult(context, `${accountPath(context)}/cfd_tunnel/${tunnel_id}`),
  }),
];

export function listFlatTools() {
  const tools: Tool[] = ACTIONS.map(action => ({
    name: action.action, title: action.title, description: action.summary, inputSchema: action.jsonSchema,
  }));
  return { tools };
}

export function getCatalogMetrics() {
  const progressive = listMetaTools();
  const legacy = listFlatTools();
  const progressiveBytes = Buffer.byteLength(JSON.stringify(progressive));
  const legacyFullBytes = Buffer.byteLength(JSON.stringify(legacy));
  return {
    exposedTools: progressive.tools.length,
    totalActions: legacy.tools.length,
    progressiveBytes,
    legacyFullBytes,
    estimatedSavedPercent: Math.round((1 - progressiveBytes / legacyFullBytes) * 10_000) / 100,
  };
}
