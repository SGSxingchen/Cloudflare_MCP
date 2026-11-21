const THEME_KEY = 'cf-mcp-color-scheme';

const ACCESS_LABELS = {
  read: { text: '只读巡检', cls: 'pill-ok' },
  write: { text: '常规读写', cls: 'pill-warn' },
  admin: { text: '高危管理', cls: 'pill-danger' },
};

const AUDIT_STATUS_LABELS = {
  ok: { text: '已执行', cls: 'pill-ok' },
  preview: { text: '高危预览拦截', cls: 'pill-warn' },
  denied: { text: '越权拒绝', cls: 'pill-danger' },
  error: { text: '执行失败', cls: 'pill-danger' },
};

const ZONE_STATUS_LABELS = {
  active: { text: '已激活', cls: 'pill-ok' },
  pending: { text: '待接入 NS', cls: 'pill-warn' },
  moved: { text: '已迁出', cls: 'pill-danger' },
  deactivated: { text: '已停用', cls: 'pill-neutral' },
};

const state = {
  activeTab: 'overview',
  overview: null,
  zones: [],
  catalog: null,
  links: [],
  audit: [],
  catalogModuleFilter: 'all',
  auditStatusFilter: 'all',
  passwordSource: 'file',
};

const $ = (id) => document.getElementById(id);
const prefersReducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function escapeHtml(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function fmtBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function toast(text, isError = false) {
  const region = $('toast-region');
  const el = document.createElement('div');
  el.className = `toast${isError ? ' is-error' : ''}`;
  el.textContent = text;
  region.appendChild(el);
  setTimeout(() => {
    el.classList.add('is-leaving');
    setTimeout(() => el.remove(), 200);
  }, 2600);
}

async function copyText(text, successMsg) {
  try {
    await navigator.clipboard.writeText(text);
    toast(successMsg);
  } catch {
    toast('复制失败，请手动选中复制', true);
  }
}

/* ========= 明暗主题切换 ========= */
function applyThemeOverride(value) {
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) meta.content = value === 'light' || value === 'dark' ? value : 'light dark';
}

function toggleTheme() {
  let stored = null;
  try { stored = localStorage.getItem(THEME_KEY); } catch {}
  const system = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  const rendered = stored === 'light' || stored === 'dark' ? stored : system;
  const target = rendered === 'dark' ? 'light' : 'dark';
  if (target === system) {
    try { localStorage.removeItem(THEME_KEY); } catch {}
    applyThemeOverride(null);
  } else {
    try { localStorage.setItem(THEME_KEY, target); } catch {}
    applyThemeOverride(target);
  }
}

window.addEventListener('storage', (e) => {
  if (e.key === THEME_KEY) applyThemeOverride(e.newValue);
});

/* ========= 动效：滑块与点击光波 ========= */
function syncSlider(container) {
  if (!container) return;
  const slider = container.querySelector(':scope > .seg-slider');
  const active = container.querySelector(':scope > .is-active');
  if (!slider || !active || active.offsetWidth === 0) return;
  slider.style.width = `${active.offsetWidth}px`;
  slider.style.transform = `translate3d(${active.offsetLeft}px, 0, 0)`;
  container.classList.add('is-slider-ready');
}

function attachRipple() {
  document.addEventListener('pointerdown', (e) => {
    if (e.button !== 0 || prefersReducedMotion()) return;
    const el = e.target.closest('.has-ripple');
    if (!el || el.disabled) return;
    const r = el.getBoundingClientRect();
    const size = Math.max(r.width, r.height) * 0.85;
    const wave = document.createElement('span');
    wave.className = 'click-ripple';
    wave.style.width = `${size}px`;
    wave.style.height = `${size}px`;
    wave.style.left = `${e.clientX - r.left - size / 2}px`;
    wave.style.top = `${e.clientY - r.top - size / 2}px`;
    el.appendChild(wave);
    setTimeout(() => wave.remove(), 500);
  });
}

/* ========= API 请求封装 ========= */
async function api(path, options = {}) {
  const init = {
    method: options.method || 'GET',
    credentials: 'same-origin',
    headers: { ...(options.headers || {}) },
  };
  if (options.body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  const res = await fetch(`./api${path}`, init);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== '/session' && path !== '/login') {
    showLogin();
    throw new Error(data.error || '会话已失效，请重新登录');
  }
  if (!res.ok) {
    throw new Error(data.error || `请求失败（状态码 ${res.status}）`);
  }
  return data;
}

function showLogin() {
  $('app-shell').hidden = true;
  $('login-view').hidden = false;
  $('login-password').value = '';
  $('login-error').hidden = true;
  $('login-password').focus();
}

function showApp() {
  $('login-view').hidden = true;
  $('app-shell').hidden = false;
  requestAnimationFrame(() => syncSlider(document.querySelector('.tab-bar')));
}

function switchTab(tab) {
  state.activeTab = tab;
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    const active = btn.dataset.tab === tab;
    btn.classList.toggle('is-active', active);
    btn.setAttribute('aria-pressed', String(active));
  });
  ['overview', 'links', 'catalog', 'audit'].forEach((id) => {
    $(`panel-${id}`).hidden = id !== tab;
  });
  syncSlider(document.querySelector('.tab-bar'));
  if (tab === 'audit') void loadAudit();
}

/* ========= 渲染模块 ========= */
function renderOverview() {
  const ov = state.overview;
  if (!ov) return;
  const tok = ov.token || {};
  const stats = ov.stats || {};

  // 顶栏状态灯
  const pill = $('nav-token-pill');
  const pillText = $('nav-token-text');
  pill.classList.remove('is-ok', 'is-warn', 'is-unconfigured');
  if (tok.configured && tok.verifyStatus === 'ok') {
    pill.classList.add('is-ok');
    pillText.textContent = `Token 已连通`;
  } else if (tok.configured) {
    pill.classList.add('is-warn');
    pillText.textContent = 'Token 待验证';
  } else {
    pill.classList.add('is-unconfigured');
    pillText.textContent = '未配置 Token';
  }

  // KPI
  $('kpi-token-state').textContent = tok.configured ? (tok.verifyStatus === 'ok' ? '已连通' : '已加密保存') : '未配置';
  $('kpi-token-sub').textContent = tok.configured
    ? `${tok.tokenHint || '已加密'} · ${tok.source === 'env' ? '环境变量回退' : 'AES-256-GCM 保管箱'}`
    : '请点击下方按钮安全配置 API Token';
  $('kpi-zone-count').textContent = String(state.zones.length);
  $('kpi-zone-sub').textContent = state.zones.length > 0
    ? `${state.zones.filter((z) => z.status === 'active').length} 个已激活域名`
    : (tok.configured ? '暂无匹配域名或未授予 Zone 读取权限' : '配置 Token 后自动同步');
  $('kpi-link-count').textContent = String(stats.activeLinks ?? 0);
  $('kpi-link-sub').textContent = `共 ${stats.totalLinks ?? 0} 条链接 · 累计 ${stats.totalCalls ?? 0} 次调用`;
  $('tab-link-count').textContent = String(stats.activeLinks ?? 0);

  const savedPct = stats.estimatedSavedPercent ?? 92;
  $('kpi-saved-pct').textContent = `-${savedPct}%`;
  $('kpi-saved-sub').textContent = `仅暴露 ${stats.exposedTools ?? 3} 个元工具，覆盖 ${stats.totalActions ?? 0} 项动作`;

  // Token 保管箱按钮与详情
  $('verify-token-btn').hidden = !tok.configured;
  $('clear-token-btn').hidden = !(tok.configured && tok.source === 'store');
  $('open-token-btn').textContent = tok.configured ? '更换 API Token' : '配置 API Token';

  const box = $('token-summary-box');
  if (!tok.configured) {
    box.innerHTML = `<p class="muted-text">尚未配置 Cloudflare API Token。点击右上角「配置 API Token」，粘贴最小权限自定义 Token 后，后端会自动验活并用 AES-256-GCM 加密写入本地权限目录，绝不向前端回传明文。</p>`;
  } else {
    const statusBadge = tok.verifyStatus === 'ok'
      ? '<span class="pill pill-ok">验活通过</span>'
      : tok.verifyStatus === 'error'
        ? `<span class="pill pill-danger">验活异常</span>`
        : '<span class="pill pill-warn">尚未验活</span>';
    box.innerHTML = `
      <div class="token-meta-grid">
        <div class="meta-pair"><span>凭证指纹（脱敏）</span><strong>${escapeHtml(tok.tokenHint || 'cf_****')}</strong></div>
        <div class="meta-pair"><span>默认 Account ID</span><strong>${escapeHtml(tok.defaultAccountId || '自动识别')}</strong></div>
        <div class="meta-pair"><span>最近验活时间</span><strong>${escapeHtml(fmtTime(tok.verifiedAt))}</strong></div>
        <div class="meta-pair"><span>凭证来源</span><strong>${tok.source === 'env' ? '环境变量' : '本地加密保管箱'}</strong></div>
      </div>
      <div>${statusBadge}</div>
    `;
  }

  // 域名列表
  const errEl = $('zones-error');
  if (ov.zonesError) {
    errEl.textContent = ov.zonesError;
    errEl.hidden = false;
  } else {
    errEl.hidden = true;
  }

  const list = $('zones-list');
  if (!tok.configured) {
    list.innerHTML = `<div class="empty-box">配置 Cloudflare API Token 后，此处将自动展示名下全部域名及快捷锁域分发入口。</div>`;
  } else if (state.zones.length === 0) {
    list.innerHTML = `<div class="empty-box">未拉取到可访问的域名，请确认 Token 具备 Zone · Read 权限后点击「刷新域名」。</div>`;
  } else {
    list.innerHTML = state.zones.map((z) => {
      const st = ZONE_STATUS_LABELS[z.status] || { text: '运行中', cls: 'pill-neutral' };
      const ns = Array.isArray(z.name_servers) && z.name_servers.length > 0 ? z.name_servers.join(', ') : '—';
      return `
        <div class="zone-row">
          <div class="zone-info">
            <div class="zone-name-line">
              <span class="zone-name">${escapeHtml(z.name)}</span>
              <span class="pill ${st.cls}">${st.text}</span>
              ${z.plan ? `<span class="pill pill-neutral">${escapeHtml(z.plan)}</span>` : ''}
            </div>
            <div class="zone-sub">ID: ${escapeHtml(z.id)} · NS: ${escapeHtml(ns)}</div>
          </div>
          <button class="btn btn-ghost btn-sm has-ripple quick-zone-link-btn" type="button" data-zone="${escapeHtml(z.name)}">为此域名签发专属链接</button>
        </div>
      `;
    }).join('');
  }
}

function renderLinks() {
  const list = $('links-list');
  const activeLinks = state.links.filter((l) => !l.revoked_at);
  $('tab-link-count').textContent = String(activeLinks.length);

  // 客户端接入示例
  const sampleUrl = activeLinks[0]?.url || `${window.location.origin}/cloudflare-mcp/<你的加密令牌>/mcp`;
  $('client-snippet').textContent = JSON.stringify({
    mcpServers: {
      cloudflare: {
        type: 'streamable-http',
        url: sampleUrl,
      },
    },
  }, null, 2);

  if (state.links.length === 0) {
    list.innerHTML = `<div class="empty-box">还没有创建任何 MCP 分发链接。点击右上角「+ 新建加密链接」即可生成按需暴露的专属链接。</div>`;
    return;
  }

  list.innerHTML = state.links.map((link) => {
    const isRevoked = Boolean(link.revoked_at);
    const acc = ACCESS_LABELS[link.access_level] || ACCESS_LABELS.read;
    const modTag = Array.isArray(link.allowed_modules) && link.allowed_modules.length > 0
      ? `<span class="pill pill-orange">限定 ${link.allowed_modules.length} 个模块</span>`
      : `<span class="pill pill-neutral">全部模块</span>`;
    const zoneTag = Array.isArray(link.allowed_zones) && link.allowed_zones.length > 0
      ? `<span class="pill pill-teal">锁域：${escapeHtml(link.allowed_zones.join(', '))}</span>`
      : `<span class="pill pill-neutral">全部域名</span>`;

    return `
      <article class="link-card${isRevoked ? ' is-revoked' : ''}">
        <div class="link-top">
          <div class="link-title-wrap">
            <span class="link-name">${escapeHtml(link.name)}</span>
            <span class="pill ${acc.cls}">${acc.text}</span>
            <span class="pill pill-teal">渐进式 3 元工具</span>
            ${isRevoked ? '<span class="pill pill-danger">已吊销</span>' : ''}
          </div>
          <div class="head-actions">
            ${!isRevoked ? `<button class="btn btn-primary btn-sm has-ripple copy-link-btn" type="button" data-url="${escapeHtml(link.url)}">复制 MCP 链接</button>` : ''}
            ${!isRevoked ? `<button class="btn btn-ghost btn-sm has-ripple edit-link-btn" type="button" data-id="${escapeHtml(link.id)}">调整权限</button>` : ''}
            ${!isRevoked ? `<button class="btn btn-danger-ghost btn-sm has-ripple revoke-link-btn" type="button" data-id="${escapeHtml(link.id)}" data-name="${escapeHtml(link.name)}">吊销</button>` : ''}
          </div>
        </div>
        <div class="link-url-box">
          <span class="link-url-text">${escapeHtml(link.url)}</span>
        </div>
        <div class="link-tags">${modTag}${zoneTag}</div>
        <div class="link-meta">
          <span>累计调用：${link.use_count ?? 0} 次</span>
          <span>最近活跃：${fmtTime(link.last_used_at)}</span>
          <span>创建于：${fmtTime(link.created_at)}</span>
          <span>到期：${link.expires_at ? fmtTime(link.expires_at) : '长期有效'}</span>
        </div>
      </article>
    `;
  }).join('');
}

function renderCatalog() {
  const cat = state.catalog;
  if (!cat) return;
  const metrics = cat.metrics || {};
  const modules = cat.modules || [];
  const actions = cat.actions || [];

  $('cmp-total-actions').textContent = String(metrics.totalActions ?? actions.length);
  $('cmp-legacy-bytes').textContent = fmtBytes(metrics.legacyFullBytes ?? 0);
  $('cmp-prog-bytes').textContent = `${fmtBytes(metrics.progressiveBytes ?? 0)}（节省 ${metrics.estimatedSavedPercent ?? 90}%）`;
  const ratio = metrics.legacyFullBytes > 0
    ? Math.max(4, Math.min(100, Math.round((metrics.progressiveBytes / metrics.legacyFullBytes) * 100)))
    : 8;
  $('cmp-prog-bar').style.width = `${ratio}%`;

  const pills = $('catalog-filter-pills');
  pills.innerHTML = [
    `<button class="mod-pill${state.catalogModuleFilter === 'all' ? ' is-active' : ''}" type="button" data-mod="all">全部模块（${actions.length}）</button>`,
    ...modules.map((m) => `<button class="mod-pill${state.catalogModuleFilter === m.module ? ' is-active' : ''}" type="button" data-mod="${escapeHtml(m.module)}">${escapeHtml(m.title)}（${m.actionCount}）</button>`),
  ].join('');

  const visibleModules = state.catalogModuleFilter === 'all'
    ? modules
    : modules.filter((m) => m.module === state.catalogModuleFilter);

  $('catalog-groups').innerHTML = visibleModules.map((m) => {
    const modActions = actions.filter((a) => a.module === m.module);
    return `
      <div class="cat-group">
        <div class="cat-group-head">
          <h3>${escapeHtml(m.title)}</h3>
          <span class="muted-text">${escapeHtml(m.summary)}</span>
        </div>
        ${modActions.map((a) => {
          const acc = ACCESS_LABELS[a.access] || ACCESS_LABELS.read;
          return `
            <div class="action-row">
              <span class="action-code">${escapeHtml(a.action)}</span>
              <span class="action-summary">${escapeHtml(a.summary)}</span>
              <span class="action-badges">
                <span class="pill ${acc.cls}">${acc.text}</span>
                ${(a.destructive || a.requiresConfirm) ? '<span class="pill pill-orange">需确认预览</span>' : ''}
              </span>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }).join('');
}

function renderAudit() {
  const list = $('audit-list');
  const rows = state.auditStatusFilter === 'all'
    ? state.audit
    : state.audit.filter((r) => r.status === state.auditStatusFilter);

  if (rows.length === 0) {
    list.innerHTML = `<div class="empty-box">暂无匹配的 AI 调用审计记录。</div>`;
    return;
  }

  list.innerHTML = rows.map((r) => {
    const st = AUDIT_STATUS_LABELS[r.status] || { text: '已记录', cls: 'pill-neutral' };
    return `
      <div class="audit-row">
        <span class="audit-time">${escapeHtml(fmtTime(r.ts))}</span>
        <div class="audit-main">
          <div class="audit-line-1">
            <strong>${escapeHtml(r.action || r.tool)}</strong>
            <span class="pill pill-neutral">${escapeHtml(r.linkName || '本地会话')}</span>
            ${r.target ? `<span class="pill pill-teal">${escapeHtml(r.target)}</span>` : ''}
          </div>
          <span class="audit-summary">${escapeHtml(r.summary || '—')}</span>
        </div>
        <div class="action-badges">
          <span class="pill ${st.cls}">${st.text}</span>
          <span class="audit-time">${Number.isFinite(r.durationMs) ? `${r.durationMs}ms` : ''}</span>
        </div>
      </div>
    `;
  }).join('');
}

/* ========= 数据拉取 ========= */
async function loadAll() {
  const [overview, catalog, links] = await Promise.all([
    api('/overview'),
    api('/catalog'),
    api('/links'),
  ]);
  state.overview = overview;
  state.zones = Array.isArray(overview.zones) ? overview.zones : [];
  state.catalog = catalog;
  state.links = Array.isArray(links.links) ? links.links : [];
  renderOverview();
  renderLinks();
  renderCatalog();
}

async function loadAudit() {
  try {
    const data = await api('/audit?limit=100');
    state.audit = Array.isArray(data.records) ? data.records : [];
    renderAudit();
  } catch (err) {
    toast(err.message, true);
  }
}

/* ========= 链接弹窗构建 ========= */
function openLinkDialog(editLink = null, prefillZone = null) {
  const isEdit = Boolean(editLink);
  $('link-dialog-title').textContent = isEdit ? `调整链接权限 · ${editLink.name}` : '新建加密 MCP 链接';
  $('link-save-btn').textContent = isEdit ? '保存权限变更' : '创建加密链接';
  $('link-edit-id').value = isEdit ? editLink.id : '';
  $('link-name-input').value = isEdit ? editLink.name : (prefillZone ? `${prefillZone} 专属运维` : '');
  $('link-access-select').value = isEdit ? editLink.access_level : 'read';
  $('link-expiry-row').hidden = isEdit;
  $('link-expiry-select').value = '';
  $('link-form-error').hidden = true;

  const modules = state.catalog?.modules || [];
  const selectedMods = isEdit ? editLink.allowed_modules : null;
  $('link-modules-picker').innerHTML = modules.map((m) => {
    const checked = !selectedMods || selectedMods.includes(m.module);
    return `
      <label class="check-chip">
        <input type="checkbox" name="mod" value="${escapeHtml(m.module)}" ${checked ? 'checked' : ''}>
        <span>${escapeHtml(m.title)}</span>
      </label>
    `;
  }).join('');

  const initialZones = isEdit
    ? (editLink.allowed_zones || [])
    : (prefillZone ? [prefillZone] : []);
  $('link-zones-input').value = initialZones.join(', ');
  renderZonePickerChips();

  $('link-dialog').showModal();
}

function getSelectedZonesFromInput() {
  return $('link-zones-input').value
    .split(/[,，\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function renderZonePickerChips() {
  const picked = new Set(getSelectedZonesFromInput());
  const box = $('link-zones-chips');
  if (state.zones.length === 0) {
    box.innerHTML = '';
    return;
  }
  box.innerHTML = state.zones.map((z) => {
    const on = picked.has(z.name.toLowerCase());
    return `<button class="zone-pick-btn${on ? ' is-picked' : ''}" type="button" data-pick-zone="${escapeHtml(z.name)}">${escapeHtml(z.name)}</button>`;
  }).join('');
}

/* ========= 事件绑定 ========= */
function bindEvents() {
  attachRipple();
  document.querySelectorAll('.theme-toggle-trigger').forEach((b) => b.addEventListener('click', toggleTheme));

  $('toggle-login-eye').addEventListener('click', () => {
    const inp = $('login-password');
    const showing = inp.type === 'text';
    inp.type = showing ? 'password' : 'text';
    $('toggle-login-eye').textContent = showing ? '显示' : '隐藏';
  });

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = $('login-error');
    const btn = $('login-submit');
    errEl.hidden = true;
    btn.disabled = true;
    try {
      await api('/login', { method: 'POST', body: { password: $('login-password').value } });
      showApp();
      await loadAll();
      toast('已解锁 Cloudflare 边缘云控制台');
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });

  $('logout-btn').addEventListener('click', async () => {
    try { await api('/logout', { method: 'POST' }); } catch {}
    showLogin();
    toast('已退出控制台');
  });

  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  document.querySelectorAll('[data-close-dialog]').forEach((btn) => {
    btn.addEventListener('click', () => $(btn.dataset.closeDialog)?.close());
  });

  // Token 配置与验活
  $('open-token-btn').addEventListener('click', () => {
    $('cf-token-input').value = '';
    $('cf-account-input').value = state.overview?.token?.defaultAccountId || '';
    $('cf-skip-verify').checked = false;
    $('token-form-error').hidden = true;
    $('token-dialog').showModal();
  });

  $('token-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = $('token-form-error');
    const btn = $('token-save-btn');
    errEl.hidden = true;
    btn.disabled = true;
    btn.textContent = '正在验活并加密保存…';
    try {
      const res = await api('/credentials', {
        method: 'POST',
        body: {
          apiToken: $('cf-token-input').value.trim(),
          defaultAccountId: $('cf-account-input').value.trim() || undefined,
          skipVerify: $('cf-skip-verify').checked,
        },
      });
      $('token-dialog').close();
      await loadAll();
      toast(res.message || 'API Token 已验活并加密保存');
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    } finally {
      btn.disabled = false;
      btn.textContent = '验活并加密保存';
    }
  });

  $('verify-token-btn').addEventListener('click', async () => {
    const btn = $('verify-token-btn');
    btn.disabled = true;
    try {
      const res = await api('/credentials/verify', { method: 'POST' });
      await loadAll();
      toast(res.message || 'Token 验活成功');
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  $('clear-token-btn').addEventListener('click', async () => {
    if (!window.confirm('确认清除本地加密保存的 Cloudflare API Token？清除后所有分发链接将暂停调用 Cloudflare API。')) return;
    try {
      await api('/credentials', { method: 'DELETE' });
      await loadAll();
      toast('已清除本地加密 Token');
    } catch (err) {
      toast(err.message, true);
    }
  });

  $('refresh-zones-btn').addEventListener('click', async () => {
    const btn = $('refresh-zones-btn');
    btn.disabled = true;
    try {
      const data = await api('/zones?refresh=1');
      state.zones = Array.isArray(data.zones) ? data.zones : [];
      if (state.overview) state.overview.zonesError = data.error || null;
      renderOverview();
      toast(`已同步 ${state.zones.length} 个域名`);
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  // 域名行快捷签发链接
  $('zones-list').addEventListener('click', (e) => {
    const btn = e.target.closest('.quick-zone-link-btn');
    if (btn) openLinkDialog(null, btn.dataset.zone);
  });

  // 分发链接管理
  $('new-link-btn').addEventListener('click', () => openLinkDialog());
  $('copy-snippet-btn').addEventListener('click', () => copyText($('client-snippet').textContent, '已复制客户端 JSON 配置'));

  $('mod-select-all').addEventListener('click', () => {
    $('link-modules-picker').querySelectorAll('input[type="checkbox"]').forEach((c) => { c.checked = true; });
  });
  $('mod-select-dns').addEventListener('click', () => {
    const dnsSet = new Set(['zones', 'dns', 'cache']);
    $('link-modules-picker').querySelectorAll('input[type="checkbox"]').forEach((c) => { c.checked = dnsSet.has(c.value); });
  });
  $('link-zones-chips').addEventListener('click', (e) => {
    const btn = e.target.closest('.zone-pick-btn');
    if (!btn) return;
    const z = btn.dataset.pickZone.toLowerCase();
    const cur = new Set(getSelectedZonesFromInput());
    if (cur.has(z)) cur.delete(z);
    else cur.add(z);
    $('link-zones-input').value = [...cur].join(', ');
    renderZonePickerChips();
  });
  $('link-zones-input').addEventListener('input', renderZonePickerChips);

  $('link-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = $('link-form-error');
    const btn = $('link-save-btn');
    errEl.hidden = true;
    const editId = $('link-edit-id').value;
    const allInputs = [...$('link-modules-picker').querySelectorAll('input[type="checkbox"]')];
    const checkedMods = allInputs.filter((c) => c.checked).map((c) => c.value);
    if (checkedMods.length === 0) {
      errEl.textContent = '请至少勾选一个允许访问的能力模块';
      errEl.hidden = false;
      return;
    }
    const allowedModules = checkedMods.length === allInputs.length ? null : checkedMods;
    const zones = getSelectedZonesFromInput();
    const allowedZones = zones.length > 0 ? zones : null;
    const payload = {
      name: $('link-name-input').value.trim(),
      accessLevel: $('link-access-select').value,
      allowedModules,
      allowedZones,
    };
    if (!editId) {
      const days = Number($('link-expiry-select').value);
      if (days > 0) payload.expiresInDays = days;
    }

    btn.disabled = true;
    try {
      if (editId) {
        await api(`/links/${encodeURIComponent(editId)}`, { method: 'PATCH', body: payload });
        toast('已更新链接权限配置');
      } else {
        const res = await api('/links', { method: 'POST', body: payload });
        if (res.link?.url) void copyText(res.link.url, '已创建并自动复制新 MCP 链接');
        else toast('已创建加密 MCP 链接');
      }
      $('link-dialog').close();
      await loadAll();
      switchTab('links');
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });

  $('links-list').addEventListener('click', async (e) => {
    const copyBtn = e.target.closest('.copy-link-btn');
    if (copyBtn) {
      void copyText(copyBtn.dataset.url, '已复制加密 MCP 链接');
      return;
    }
    const editBtn = e.target.closest('.edit-link-btn');
    if (editBtn) {
      const link = state.links.find((l) => l.id === editBtn.dataset.id);
      if (link) openLinkDialog(link);
      return;
    }
    const revokeBtn = e.target.closest('.revoke-link-btn');
    if (revokeBtn) {
      if (!window.confirm(`确认吊销链接「${revokeBtn.dataset.name}」？吊销后将立即断开所有正在使用该链接的 AI 会话。`)) return;
      try {
        await api(`/links/${encodeURIComponent(revokeBtn.dataset.id)}`, { method: 'DELETE' });
        await loadAll();
        toast('已吊销链接并断开关联会话');
      } catch (err) {
        toast(err.message, true);
      }
    }
  });

  // 能力地图筛选
  $('catalog-filter-pills').addEventListener('click', (e) => {
    const pill = e.target.closest('.mod-pill');
    if (!pill) return;
    state.catalogModuleFilter = pill.dataset.mod;
    renderCatalog();
  });

  // 审计筛选与刷新
  $('audit-status-filter').addEventListener('change', (e) => {
    state.auditStatusFilter = e.target.value;
    renderAudit();
  });
  $('refresh-audit-btn').addEventListener('click', loadAudit);

  // 修改管理员口令
  $('open-password-btn').addEventListener('click', () => {
    $('pwd-current').value = '';
    $('pwd-new').value = '';
    $('pwd-form-error').hidden = true;
    $('password-dialog').showModal();
  });
  $('password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = $('pwd-form-error');
    errEl.hidden = true;
    try {
      await api('/password', {
        method: 'POST',
        body: { currentPassword: $('pwd-current').value, newPassword: $('pwd-new').value },
      });
      $('password-dialog').close();
      toast('管理员口令已更新');
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    }
  });

  window.addEventListener('resize', () => {
    syncSlider(document.querySelector('.tab-bar'));
  }, { passive: true });
}

async function boot() {
  bindEvents();
  try {
    const sess = await api('/session');
    state.passwordSource = sess.passwordSource || 'file';
    if (sess.authenticated) {
      showApp();
      await loadAll();
    } else {
      showLogin();
    }
  } catch {
    showLogin();
  }
}

void boot();
