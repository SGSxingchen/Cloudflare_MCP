import { HttpError } from './errors.js';

const MAX_ROWS = 1_000;
const FORBIDDEN = new Set([
  'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'REPLACE',
  'ATTACH', 'DETACH', 'VACUUM', 'REINDEX', 'ANALYZE', 'TRUNCATE', 'MERGE',
  'BEGIN', 'COMMIT', 'ROLLBACK', 'SAVEPOINT', 'RELEASE', 'GRANT', 'REVOKE',
  'LOAD_EXTENSION', 'WRITEFILE', 'EVAL', 'FTS3_TOKENIZER',
]);

const PRAGMAS_WITH_ARGUMENT = new Set([
  'TABLE_INFO', 'TABLE_XINFO', 'TABLE_LIST', 'INDEX_INFO', 'INDEX_XINFO',
  'INDEX_LIST', 'FOREIGN_KEY_LIST',
]);
const READONLY_PRAGMAS = new Set([
  ...PRAGMAS_WITH_ARGUMENT, 'DATABASE_LIST', 'COLLATION_LIST', 'COMPILE_OPTIONS',
  'FUNCTION_LIST', 'PRAGMA_LIST', 'USER_VERSION', 'SCHEMA_VERSION', 'DATA_VERSION',
  'FOREIGN_KEYS', 'DEFER_FOREIGN_KEYS', 'PAGE_SIZE', 'PAGE_COUNT', 'FREELIST_COUNT',
]);

const identifier = /^[A-Za-z_][A-Za-z_0-9$]*$/;
const quotedIdentifier = /^(?:'(?:[^']|'')*'|"(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\])$/;

function validatePragma(tokens: string[]): void {
  // 模式名可以是 main 等已知标识符，PRAGMA 名必须是白名单中的裸标识符。
  const qualified = tokens[2] === '.' && identifier.test(tokens[1]);
  const nameIndex = qualified ? 3 : 1;
  const name = tokens[nameIndex]?.toUpperCase();
  const args = tokens.slice(nameIndex + 1);
  if (!READONLY_PRAGMAS.has(name)) throw new HttpError(400, '仅允许白名单中的只读 PRAGMA');
  if (args.length === 0) return;
  if (!PRAGMAS_WITH_ARGUMENT.has(name) || args.length !== 3 || args[0] !== '(' || args[2] !== ')'
    || (!identifier.test(args[1]) && !quotedIdentifier.test(args[1]))) {
    throw new HttpError(400, '只读 PRAGMA 不接受赋值或其他选项');
  }
}

export function prepareReadonlySql(input: string): string {
  if (input.includes('\0')) throw new HttpError(400, 'SQL 含有无效字符');

  // 区分注释与引号中的内容，再按 SQLite 的标识符边界识别关键字。
  const lexemes = /--[^\n]*|\/\*[\s\S]*?\*\/|'(?:[^']|'')*'|"(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\]|[A-Za-z_\u0080-\uFFFF][A-Za-z_0-9$\u0080-\uFFFF]*|[ \t\r\n\f\v]+|[^]/g;
  const parts: string[] = [];
  const tokens: string[] = [];
  let depth = 0;
  for (const match of input.matchAll(lexemes)) {
    const part = match[0];
    if (part.startsWith('--') || part.startsWith('/*')) {
      parts.push(' ');
      continue;
    }
    if (part === '/' && input[match.index + 1] === '*' || "'\"`[".includes(part)) {
      throw new HttpError(400, 'SQL 包含未闭合的注释或引号');
    }
    parts.push(part);
    if (/^\s+$/.test(part)) continue;
    if (FORBIDDEN.has(part.toUpperCase())) throw new HttpError(400, 'SQL 包含写入或结构变更指令');
    if (part === '(') depth += 1;
    if (part === ')') depth -= 1;
    if (depth < 0) throw new HttpError(400, 'SQL 括号不匹配');
    tokens.push(part);
  }
  if (depth !== 0) throw new HttpError(400, 'SQL 括号不匹配');

  const sql = parts.join('').trim().replace(/;$/, '').trimEnd();
  if (tokens.at(-1) === ';') tokens.pop();
  if (!sql || sql.includes(';')) throw new HttpError(400, '只允许提交一条 SQL，语句内部禁止分号');
  switch (tokens[0]?.toUpperCase()) {
    case 'SELECT':
      // 子查询限制返回行数，同时保留原查询绑定参数的位置和个数。
      return `SELECT * FROM (\n${sql}\n) LIMIT ${MAX_ROWS}`;
    case 'PRAGMA':
      validatePragma(tokens);
      return sql;
    case 'EXPLAIN': {
      const opcode = tokens[1]?.toUpperCase() === 'QUERY' && tokens[2]?.toUpperCase() === 'PLAN' ? 3 : 1;
      if (tokens[opcode]?.toUpperCase() === 'SELECT') return sql;
      throw new HttpError(400, 'EXPLAIN 仅允许分析 SELECT 语句');
    }
    default:
      throw new HttpError(400, '只允许 SELECT、只读 PRAGMA 或 EXPLAIN 语句');
  }
}
