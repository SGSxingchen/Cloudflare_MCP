import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { z } from 'zod';
import type { AuditEvent, AuditStore } from './audit-store.js';
import { ACTIONS, GUIDES, listMetaTools, META_TOOLS, MODULES, type ActionDefinition } from './catalog.js';
import { CloudflareClient, type CloudflareClientOptions } from './cloudflare-client.js';
import type { CredentialStore } from './credential-store.js';
import { errorMessage, HttpError, redactSecrets } from './errors.js';
import type { AccessLevel } from './link-store.js';

export const MCP_INFO = { name: 'cloudflare-mcp', version: '1.0.0' };
export const MCP_TOOL_COUNT = Object.keys(META_TOOLS).length;

export interface McpScope {
  access_level: AccessLevel;
  allowed_modules: readonly string[] | null;
  allowed_zones: readonly string[] | null;
  linkId?: string;
  linkName?: string;
  linkToken?: string;
}

export const FULL_ACCESS: McpScope = { access_level: 'admin', allowed_modules: null, allowed_zones: null };

interface McpOptions {
  credentials: CredentialStore;
  auditStore: AuditStore;
  getScope: () => McpScope;
  clientOptions?: Pick<CloudflareClientOptions, 'baseUrl' | 'fetchImpl'>;
  redact?: (text: string) => string;
  onToolCompleted?: () => void | Promise<unknown>;
}

const actionsByName = new Map(ACTIONS.map(action => [action.action, action]));
const accessRank: Record<AccessLevel, number> = { read: 0, write: 1, admin: 2 };
const secretField = /^(?:authorization|(?:.*[_-])?(?:api[_-]?)?token|api[_-]?key|(?:.*[_-])?secret|(?:.*[_-])?password|private[_-]?key|session[_-]?cookie)$/i;

function canAccess(action: ActionDefinition, scope: McpScope): boolean {
  if (accessRank[scope.access_level] < accessRank[action.access]) return false;
  if (scope.allowed_modules !== null && !scope.allowed_modules.includes(action.module)) return false;
  return scope.allowed_zones === null || action.zoneScoped || action.supportsZoneScope === true;
}

function requireAction(name: string, scope: McpScope): ActionDefinition {
  const action = actionsByName.get(name);
  if (!action || !canAccess(action, scope)) throw new HttpError(403, '当前链接无权访问该动作');
  return action;
}

function parse<T extends z.ZodType>(schema: T, value: unknown, message: string): z.output<T> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new HttpError(400, message);
  return parsed.data;
}

function toolResult(value: unknown, redact: (text: string) => string, isError = false): CallToolResult {
  const text = JSON.stringify(value, (key, item: unknown) => {
    if (key && secretField.test(key)) return '[已脱敏]';
    if (typeof item === 'string') return redact(item);
    return item;
  });
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) };
}

function actionSummary(action: ActionDefinition) {
  const { action: name, module, title, summary, access } = action;
  return { action: name, module, title, summary, access };
}

function discover(scope: McpScope, args: unknown) {
  const { module, query } = parse(META_TOOLS.cf_discover.schema, args, '发现参数无效');
  const term = query?.trim().toLowerCase();
  const matched = ACTIONS.filter(action => canAccess(action, scope)
    && (!module || action.module === module)
    && (!term || `${action.action} ${action.title} ${action.summary}`.toLowerCase().includes(term)));
  const modules = new Set(matched.map(action => action.module));
  return { modules: MODULES.filter(item => modules.has(item.id)), actions: matched.map(actionSummary) };
}

function describe(scope: McpScope, args: unknown) {
  const { actions = [], guide } = parse(META_TOOLS.cf_describe.schema, args, '请指定一至六个动作或一个专题指南');
  if (!actions.length && !guide) throw new HttpError(400, '请指定一至六个动作或一个专题指南');
  const definitions = [...new Set(actions)].map(name => {
    const action = requireAction(name, scope);
    const { destructive, requiresConfirm, zoneScoped, accountScoped, jsonSchema, examples, notes } = action;
    return { ...actionSummary(action), destructive, requiresConfirm, zoneScoped, accountScoped, jsonSchema, examples, notes };
  });
  if (guide) {
    const entry = Object.hasOwn(GUIDES, guide) ? GUIDES[guide as keyof typeof GUIDES] : undefined;
    if (!entry || (guide !== 'safety' && !ACTIONS.some(action => action.module === guide && canAccess(action, scope)))) {
      throw new HttpError(403, '当前链接无权访问该专题');
    }
    return { actions: definitions, guide: entry };
  }
  return { actions: definitions };
}

async function execute(options: McpOptions, scope: McpScope, args: unknown, signal: AbortSignal,
  event: AuditEvent, secrets: string[]) {
  const input = parse(META_TOOLS.cf_execute.schema, args, '执行参数无效');
  event.action = input.action;
  const action = requireAction(input.action, scope);
  event.module = action.module;
  event.access = action.access;
  const params = parse(action.zodSchema, input.params ?? {}, '动作参数无效，请先查看动作参数定义');
  const fields = params as { zone?: string; account_id?: string };
  const confirmRequired = action.destructive || action.requiresConfirm || action.confirmWhen?.(params) === true;
  const revision = options.credentials.revision;
  const beforeRequest = () => {
    const current = options.getScope();
    requireAction(action.action, current);
    if (action.zoneScoped && JSON.stringify(current.allowed_zones) !== JSON.stringify(scope.allowed_zones)) {
      throw new HttpError(403, '链接授权范围已变更，请重新调用');
    }
    if (options.credentials.revision !== revision) throw new HttpError(409, '调用期间 Cloudflare 凭据已变更');
    if (signal.aborted) throw new HttpError(409, '本次调用已取消');
  };

  const { token } = options.credentials.getActiveToken();
  if (!token) throw new HttpError(400, '尚未配置 Cloudflare API 令牌');
  secrets.push(token);
  const client = new CloudflareClient({ ...options.clientOptions, token, credentialStore: options.credentials, beforeRequest, signal });
  const zone = action.zoneScoped && fields.zone ? await client.resolveZone(fields.zone, scope.allowed_zones) : undefined;
  const accountId = action.accountScoped ? await client.resolveAccountId(fields.account_id) : undefined;
  event.target = zone?.name ?? accountId ?? null;
  const context = { client, zoneId: zone?.id, accountId, allowedZones: scope.allowed_zones };
  const target = zone ? { zone: zone.name, zone_id: zone.id } : accountId ? { account_id: accountId } : null;

  beforeRequest();
  if (input.dry_run === true || (confirmRequired && input.confirm !== true)) {
    const details = await action.preview?.(context, params);
    beforeRequest();
    event.status = 'preview';
    event.summary = confirmRequired ? '已生成预览，执行需要确认' : '已生成预览';
    return { action: action.action, status: 'preview', requiresConfirm: confirmRequired, target, details };
  }

  const result = await action.handler(context, params);
  beforeRequest();
  event.summary = '动作执行成功';
  return { action: action.action, status: 'ok', target, result };
}

export function createMcpServer(options: McpOptions): Server {
  const server = new Server(MCP_INFO, { capabilities: { tools: {} }, instructions: '先发现能力，按需查看参数，再执行动作。' });
  server.setRequestHandler(ListToolsRequestSchema, () => {
    options.getScope();
    return listMetaTools();
  });
  server.setRequestHandler(CallToolRequestSchema, async (request, { signal }) => {
    const started = performance.now();
    const { name, arguments: args = {} } = request.params;
    const secrets: string[] = [];
    const activeToken = options.credentials.getActiveToken().token;
    if (activeToken) secrets.push(activeToken);
    const redact = (text: string) => redactSecrets(options.redact?.(text) ?? text, secrets);
    const event: AuditEvent = {
      linkId: null, linkName: null, tool: name, action: null, module: null, access: null,
      target: null, status: 'ok', durationMs: 0, summary: '调用成功',
    };
    let result: CallToolResult;
    try {
      const scope = options.getScope();
      event.linkId = scope.linkId ?? null;
      event.linkName = scope.linkName ?? null;
      if (scope.linkToken) secrets.push(scope.linkToken);
      if (request.params.task) throw new HttpError(400, '工具调用不支持后台任务');
      switch (name) {
        case 'cf_discover':
          result = toolResult(discover(scope, args), redact);
          break;
        case 'cf_describe':
          result = toolResult(describe(scope, args), redact);
          break;
        case 'cf_execute':
          result = toolResult(await execute(options, scope, args, signal, event, secrets), redact);
          break;
        default:
          throw new HttpError(404, '找不到该元工具');
      }
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      if (!(error instanceof HttpError)) console.error('处理 Cloudflare MCP 工具调用失败');
      event.status = status === 401 || status === 403 || status === 404 ? 'denied' : 'error';
      event.summary = redact(errorMessage(error, secrets));
      result = toolResult({ status: event.status, code: status, error: event.summary }, redact, true);
    }

    event.durationMs = Math.round(performance.now() - started);
    event.linkName = event.linkName === null ? null : redact(event.linkName);
    event.tool = redact(event.tool);
    event.action = event.action === null ? null : redact(event.action);
    event.target = event.target === null ? null : redact(event.target);
    try {
      await options.auditStore.record(event);
    } catch {
      console.error('写入 Cloudflare MCP 审计记录失败');
    }
    try {
      await options.onToolCompleted?.();
    } catch {
      console.error('更新 Cloudflare MCP 链接用量失败');
    }
    return result;
  });
  return server;
}
