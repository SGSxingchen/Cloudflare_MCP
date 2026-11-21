# Cloudflare_MCP · 渐进式披露边缘云 MCP 服务

基于 Model Context Protocol (Streamable HTTP / stdio) 的自托管 Cloudflare 远程服务与 Web 管理台，可独立部署或反向代理挂载于 `/cloudflare-admin/` 与 `/cloudflare-mcp/<secret>/mcp`。

## 核心特性

- **统一 3 元工具渐进式披露（Progressive Disclosure）**：
  - AI 连接时仅加载 `cf_discover`、`cf_describe`、`cf_execute` 三个极简元工具，初始上下文体积较全量平铺压缩 **90%+**；
  - 完整参数 Schema 与专题操作手册按需拉取，兼容所有主流 MCP 客户端与 AI Harness。
- **全栈 10 模块覆盖**：`account`、`zones`、`dns`、`cache`、`ssl`、`security`、`workers`（含 KV）、`pages`、`storage`（R2 + 词法级只读 D1 诊断查询）、`tunnels`（Zero Trust）。
- **四维精细权限与高危防呆护栏**：
  - API Token 使用 AES-256-GCM 加密保管（本地 `0600` 权限，绝不回传前端明文）；
  - 分发链接独立配置「权限级别（read / write / admin）× 允许模块白名单 × 域名锁 × 有效期」，吊销或改权即时踢断旧会话；
  - 删除 DNS、全站清理缓存、改 SSL 模式等高危动作默认返回影响预演（Dry-Run 预览），显式传入 `confirm: true` 才会执行；
  - D1 查询经词法级只读校验，拦截任何写/DDL/多语句 SQL；每次执行与拦截均写入审计日志。

## 启动方式

```bash
npm install
npm run build
npm test
npm run start:http
```
