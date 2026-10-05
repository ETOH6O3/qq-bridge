// 角色资料库 MCP server（stdio）。由 DSH 的 MCP 客户端 spawn（cordis.patch.yml 里 mcp-lore 行）。
//
// 工具：
//   lore_read    —— 读 roles/lore/ 下的资料库文件（只读）
//   lore_write   —— 写入 roles/lore/ 下的 .md 文件（仅 owner 私聊可用）
//
// ── 设计边界（为什么只开放 lore/ 一个目录）────────────────────────────
//
// QQ 消息是**不可信输入**：发消息的人、转发的聊天记录、甚至图片里的文字，
// 都可能带着 prompt injection。AI 一旦获得任意文件写权限，一次成功的注入
// 就可能改掉 config.json（换成攻击者的 provider/baseUrl）、改掉 agent preset
// （放开工具白名单），甚至改掉本文件（永久开后门）。
//
// 所以这里的边界是硬性的，不因为发消息的是 owner 而放宽：
//   1. 只能碰 roles/lore/ 下的 .md —— 人设卡、config、preset、src 全部不可达；
//   2. 写入只允许「整文件覆盖」，不提供删除/重命名，避免目录被清空；
//   3. 每个文件有大小上限，且写入前校验解析后的真实路径仍在 lore/ 内
//      （挡住 ../ 穿越与符号链接）；
//   4. 写入要求带来源标记（见下方 lint），没有来源的内容会被拒绝——
//      没有来源的条目等于让 AI 自己编的记忆，下次它会当成真的用。
//
// 需要 owner 完整工具面（命令执行、任意文件读写）时，请用 closed-agent 模式，
// 那是项目已有的路径：仅 owner 私聊 + DSH 默认 preset。不要在这里开后门。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const LORE_DIR = path.resolve(ROOT, 'roles', 'lore');

// 单文件上限。资料库条目是「一个话题的要点」，不是长文；超了这个值
// 说明 AI 在往里塞不该沉淀的东西（整篇百科、聊天记录）。可用 lore.maxFileKb 覆盖。
const DEFAULT_MAX_FILE_BYTES = 64 * 1024;
const ALLOWED_EXT = '.md';

// 覆盖前留几份快照。3 份够回滚（最近两次改动 + 一份更早的基线），
// 再多只是垃圾——而且 .bak-* 会被 lore_read 的目录列举当成可读条目，干扰判断。
const DEFAULT_KEEP_SNAPSHOTS = 3;

// ── 通用化：本 server 不认识任何具体作品 ─────────────────────────────────
//
// 早先这里把某个具体作品的世界观、以及它的资料来源网站硬写进了工具描述里，
// 于是这个通用目录（roles/lore/）被绑死在一部作品上：换一个类型的人设
// （小说/动画/自设世界观）就得改程序源码。
//
// 现在改成**配置驱动**：主题、来源提示、收录范围全部来自 config.json 的 `lore`
// 命名空间。程序只负责「一个受约束的 Markdown 目录的读写」，不该知道里面装什么。
//
// 配置缺省时也必须能用：默认文案是作品无关的通用表述，不点名任何来源。
const DEFAULT_LORE_CONFIG = {
  // 资料库的主题描述，用于工具描述里的「回答 X 相关问题前先读这里」。
  // 例：「某作品世界观」「本作设定」「公司内部知识库」。
  topic: '',
  // 推荐来源提示（写进 lore_write 的描述里，只是建议不是白名单）。
  // 例：['wiki.example.org', 'docs.example.com']。留空则只说「注明出处」。
  sources: [],
  // 收录范围说明，替换「只写哪些类别」那串的默认值。
  scope: '',
  // 明确**不该**收录的内容说明。
  exclude: '',
  maxFileKb: 0,        // >0 时覆盖单文件上限（KB）
  keepSnapshots: 0     // >0 时覆盖快照保留份数
};

function loadConfig() {
  try {
    let text = fs.readFileSync(path.join(ROOT, 'config.json'), 'utf8');
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    return JSON.parse(text);
  } catch {
    return {};
  }
}

/**
 * 读出资料库配置（缺省值兜底）。
 *
 * 每次调用都重读 config.json：资料库工具是常驻 stdio 进程，但主题/来源这类
 * 配置改完立刻生效比「重启 DSH 才生效」体验好得多，读一个小文件的开销可忽略。
 */
function loreConfig() {
  const raw = loadConfig().lore ?? {};
  const arr = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim()) : []);
  const num = (v) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : 0);
  return {
    topic: typeof raw.topic === 'string' ? raw.topic.trim() : DEFAULT_LORE_CONFIG.topic,
    sources: arr(raw.sources),
    scope: typeof raw.scope === 'string' ? raw.scope.trim() : DEFAULT_LORE_CONFIG.scope,
    exclude: typeof raw.exclude === 'string' ? raw.exclude.trim() : DEFAULT_LORE_CONFIG.exclude,
    maxFileBytes: num(raw.maxFileKb) ? num(raw.maxFileKb) * 1024 : DEFAULT_MAX_FILE_BYTES,
    keepSnapshots: num(raw.keepSnapshots) || DEFAULT_KEEP_SNAPSHOTS
  };
}

/**
 * 拼「回答 X 问题前先读这里」的主语片段。
 *
 * 配置了 topic 就用它（`某作品世界观` → `回答某作品世界观问题前…`），
 * 没配置就退回通用表述（`回答这个资料库覆盖的问题前…`）——**绝不写死作品名**。
 */
function topicPhrase(conf) {
  return conf.topic ? `${conf.topic}` : '这个资料库覆盖的主题';
}

/** 来源提示：配置了就给建议清单，没配就只说「注明出处」。 */
function sourceHint(conf) {
  if (conf.sources.length > 0) return `（例如 ${conf.sources.join(' / ')}）`;
  return '';
}

/**
 * 拼 lore_write 的收录范围提示。
 *
 * 有 scope/exclude 就照配置说；没有就退回通用表述（「只写稳定的事实性内容」），
 * 同样不点名任何作品。这样换人设时只改 config.json，不动程序。
 */
function scopeHint(conf) {
  const parts = [];
  if (conf.scope) parts.push(conf.scope);
  else parts.push('只写稳定的事实性内容（角色/设定/专有名词/势力/年代等）');
  if (conf.exclude) parts.push(conf.exclude);
  else parts.push('不要写日常闲聊、新闻、临时梗');
  return parts.join('；');
}

/**
 * 校验文件名并返回绝对路径。
 *
 * 只接受 `xxx.md` 这种简单文件名：`/`、`\`、`..`、盘符、协议前缀一律拒绝。
 * 之后**再**用 realpath 复核一次真实位置仍在 LORE_DIR 内 —— 双保险挡住
 * 符号链接（只做字符串检查的话，lore/x.md 指向仓库外仍会被跟着写穿）。
 */
function resolveLorePath(name) {
  const raw = String(name ?? '').trim();
  if (!raw) return { error: '缺少文件名' };
  if (raw.length > 128) return { error: '文件名过长' };
  if (/[\u0000-\u001f\u007f]/.test(raw)) return { error: '文件名含控制字符' };
  if (/[\\/]/.test(raw)) return { error: '文件名不能包含路径分隔符' };
  if (raw.includes('..')) return { error: '文件名不能包含 ..' };
  if (/^[a-zA-Z]:/.test(raw)) return { error: '文件名不能包含盘符' };
  if (!raw.toLowerCase().endsWith(ALLOWED_EXT)) return { error: `只允许 ${ALLOWED_EXT} 文件` };

  const abs = path.resolve(LORE_DIR, raw);
  if (!abs.startsWith(LORE_DIR + path.sep)) return { error: '路径越界' };
  try {
    // 解析真实路径后再复核，防止符号链接指到 lore/ 之外
    const real = fs.realpathSync(abs);
    if (!real.startsWith(fs.realpathSync(LORE_DIR) + path.sep)) {
      return { error: '目标不在资料库目录内' };
    }
  } catch {
    // 文件还不存在（写入场景）：检查父目录即可
    if (!fs.existsSync(LORE_DIR)) return { error: '资料库目录不存在' };
  }
  return { path: abs };
}

/**
 * 管理员校验（走会话令牌，不用 key）。
 *
 * 为什么不用 key：AI 在提示里拿到的是 `【会话令牌】<hex>`，**拿不到自己的 QQ 号**。
 * 让它填 `private:12345` 等于要求它凭空知道一个它没有被告知的数字。
 *
 * 所以改成和其余 MCP 工具一致的口径：AI 传 `token`，本 server 拿它去比对
 * `state/social-v2.json` 里 owner 会话（`private:<ownerQQ>`）的 agentToken。
 * 令牌对不上 = 不是管理员那条会话，直接拒。
 *
 * 这仍然是 fail-closed：
 *  - 未配置 ownerQQ → 一律拒；
 *  - 非 owner 会话的 token 与 owner 会话的 token 不同（各自随机生成）；
 *  - 令牌不存在 / 空 → 拒。
 */
function isOwnerByToken(token) {
  const cfg = loadConfig();
  const owner = String(cfg.ownerQQ ?? '').trim();
  if (!owner) return false;
  const t = String(token ?? '').trim();
  if (!t) return false;
  const ownerKey = `private:${owner}`;
  try {
    let text = fs.readFileSync(path.join(ROOT, 'state', 'social-v2.json'), 'utf8');
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    const data = JSON.parse(text);
    const entry = data?.conversations?.[ownerKey];
    const ownerToken = String(entry?.agentToken ?? '').trim();
    return !!ownerToken && ownerToken === t;
  } catch {
    return false;
  }
}

const server = new McpServer({ name: 'qq-lore', version: '0.1.0' });

// 工具描述在**注册时**定稿（SDK 不接受动态描述），所以这里读一次配置。
// 进程由 DSH 在启动时 spawn：改了 lore.topic/sources/scope 后要重启 DSH，
// 工具描述里的文案才会刷新。注意**读写行为不受此影响** —— handler 内部
// 每次都重读 config（见 loreConfig()），所以大小上限、快照份数是即时生效的。
const BOOT_CONF = loreConfig();

server.tool(
  'lore_read',
  `读取角色资料库（roles/lore/）里的一个文件。回答${topicPhrase(BOOT_CONF)}的问题前先读这里，避免重复上网查。返回文件全文。`,
  { file: z.string().describe('资料库文件名，例如 lore/README.md 索引里列出的条目名（如 xxx.md）') },
  async ({ file }) => {
    const r = resolveLorePath(file);
    if (r.error) return { content: [{ type: 'text', text: `拒绝读取：${r.error}` }], isError: true };
    if (!fs.existsSync(r.path)) {
      // 列举时排除 .bak-* 快照：它们是回滚用的历史版本，不是可读条目。
      // 混进来会让 AI 以为「xxx.md.bak-1791…」是正式资料而去读它。
      const available = fs.existsSync(LORE_DIR)
        ? fs.readdirSync(LORE_DIR).filter(
            (f) => f.toLowerCase().endsWith(ALLOWED_EXT) && !f.includes('.bak-'),
          )
        : [];
      return {
        content: [{ type: 'text', text: `文件不存在：${file}。现有条目：${available.join('、') || '（空）'}` }],
        isError: true,
      };
    }
    const text = fs.readFileSync(r.path, 'utf8');
    return { content: [{ type: 'text', text }] };
  }
);

server.tool(
  'lore_write',
  `把你查到的资料写回资料库（roles/lore/），这样下次不用重复查。${scopeHint(BOOT_CONF)}。必须带来源 URL 与核查时间——没有来源的内容会被拒绝。仅管理员可用。`,
  {
    token: z.string().describe('会话令牌（见唤醒提示中的【会话令牌】）。用于校验管理员身份，缺失或无效会被拒绝'),
    file: z.string().describe('目标文件名，例如 lore/README.md 索引里列出的条目名'),
    content: z.string().describe('文件完整内容（Markdown）'),
  },
  async ({ token, file, content }) => {
    if (!isOwnerByToken(token)) {
      return {
        content: [{ type: 'text', text: '资料库写入仅管理员可用。普通聊天里查到的资料可以照常说，只是不会存下来。' }],
        isError: true,
      };
    }
    const conf = loreConfig();
    const r = resolveLorePath(file);
    if (r.error) return { content: [{ type: 'text', text: `拒绝写入：${r.error}` }], isError: true };

    const body = String(content ?? '');
    const bytes = Buffer.byteLength(body, 'utf8');
    if (bytes > conf.maxFileBytes) {
      return {
        content: [{ type: 'text', text: `拒绝写入：内容 ${(bytes / 1024).toFixed(1)}KB，超过上限 ${conf.maxFileBytes / 1024}KB。资料库只放要点，不要整篇百科。` }],
        isError: true,
      };
    }
    // 来源是硬要求：没有出处的条目 = AI 自己编的记忆，下次会被当成事实使用。
    if (!/https?:\/\/\S+/i.test(body)) {
      return {
        content: [{ type: 'text', text: `拒绝写入：内容里没有来源 URL。查到的资料必须注明出处${sourceHint(conf)}与核查时间，否则等于让你自己编的记忆进库。请补上来源再写。` }],
        isError: true,
      };
    }

    // 防「把台词存进资料库 → 之后原样念出来」。
    //
    // 实测事故：AI 往资料库里存了一句它自己编的引号台词，下一轮对话直接把它
    // 当自己的台词念了出来。资料库一旦存了第一人称的引号台词，它就会变成台词库——
    // 而人设卡的「行为示例」那节明令禁止逐字输出，两者叠加就成了绕过出口。
    //
    // 这里拦的是**没有出处的引号台词**：从来源原文核实过的真台词带 `> ` 引用块、
    // 且同条目有来源 URL 兜底，不受影响；凭空造的第一人称引语没有来源可查，直接拒。
    //
    // 注意不能按「整个文件有没有来源」来判断：编造的台词和真实事实条款
    // 共用同一个来源 URL。所以判据落在**引号本身有没有归属**：
    //   - `> ` 引用块 → 明确是原文引证，合法；
    //   - 行内引号但前面有归属词（她说/原话/档案/台词…）→ 合法引证；
    //   - 行内引号、没有任何归属 → 拒绝（大概率是把自己的台词写进了库）。
    //
    // ⚠️ 2026-10-04 修（两处）：
    //
    // 1) 引号字符集原本是 /[""]/ ，但那个「弯引号」实际是**两个 U+0022（ASCII）**，
    //    所以只认 ASCII 引号，而 AI 实际写中文引号「」——正是要拦的那类反而漏了。
    //
    // 2) 光把字符集补全**会误杀**：实测现有 7 个资料文件里有 62 处引号，其中
    //    61 处是行内强调（`「罗德岛」号`、`「文明的存续」`、`「卡兹戴尔」`），
    //    全部会被「有引号且无归属词」误判成自撰台词 —— 判据过严会阻碍正常维护。
    //
    // 真正区分得开的是**形态**，不是「有没有引号」：
    //   · 编造台词：整行就是一个引号块，且引文是成句的长文本
    //     （实测事故句 = `「这种话，我以前可说不出口。」`，12 字）
    //   · 合法用法：引号嵌在句子中间做强调；或整行只是短术语
    //     （现有唯一的整行引号块是 pre-civilization.md 的 `「语言」`，2 字）
    //
    // 所以判据 = **整行即引号块 且 引文长度 >= 8**。对现有文件误报 0 处。
    // 归属词（她说/原话/台词/来源…）继续作为额外放行：带出处的引证不受影响。
    const OPEN_Q = '\u300c\u300e\u201c\uff02\u0022';
    const CLOSE_Q = '\u300d\u300f\u201d\uff02\u0022';
    const PAIR_RE = new RegExp(`[${OPEN_Q}]([^${OPEN_Q}${CLOSE_Q}]{1,400})[${CLOSE_Q}]`, 'g');
    const ATTRIB = /(她说|他说|原话|台词|档案|引用|自述|说过|写明|写着|记着|来源|核查时间)/;
    /** 该行是否「整行就是一个足够长的引号块」（= 像台词，而不是行内强调）。 */
    const isStandaloneQuote = (line) => {
      const s = line.trim()
        .replace(/^(?:[-*+]\s+|#{1,6}\s+|\d+\.\s+|\*\*|__)+/, '')
        .replace(/\*\*$/, '')
        .trim();
      if (!s) return false;
      const matches = [...s.matchAll(PAIR_RE)];
      if (matches.length !== 1) return false;
      const m = matches[0];
      if (s.slice(m.index, m.index + m[0].length) !== s) return false;  // 必须整行就是它
      return m[1].length >= 8;                                          // 太短的当术语/强调
    };
    const fabricatedQuote = body.split(/\r?\n/).some((line) => {
      const s = line.trim();
      if (/^>/.test(s)) return false;              // 引用块：原文引证
      if (ATTRIB.test(s)) return false;            // 带归属词：合法引证
      return isStandaloneQuote(s);                 // 整行长引号块且无归属 → 自撰台词
    });
    if (fabricatedQuote) {
      return {
        content: [{ type: 'text', text:
          '拒绝写入：检测到没有来源的引号台词。\n\n'
          + '资料库只放**事实**，不放台词。写成第三人称的事实陈述，例如：\n'
          + '  她用了石棺重塑肉身，融合率 0%，会生病也会死。\n'
          + '而不是：\n'
          + '  「她拿石棺给自己重塑了一具身体。」\n\n'
          + '原因：台词一旦进库，你下次会把它原样念出来——既像在背资料，又可能编出'
          + '来源里根本不存在的句子（实测踩过）。从来源原文核实过的引语请用 `> ` 引用块，'
          + '并在该条目里写明来源 URL。' }],
        isError: true,
      };
    }

    fs.mkdirSync(LORE_DIR, { recursive: true });
    // 覆盖前留一份带时间戳的快照，防止 AI 把核实过的好资料写坏且无法回滚。
    //
    // 快照会累积（每次覆盖一份），所以只保留最近 conf.keepSnapshots 份：
    // 时间戳命名让「旧的」很好认，按文件名排序即可拿到先后顺序。
    // 不清理的话，AI 反复改同一个文件会让 .bak-* 越堆越多，
    // 而它们本身又会被 lore_read 的目录列举当成「可读条目」，干扰判断。
    if (fs.existsSync(r.path)) {
      try {
        fs.copyFileSync(r.path, `${r.path}.bak-${Date.now()}`);
        const prefix = `${path.basename(r.path)}.bak-`;
        const snaps = fs.readdirSync(LORE_DIR).filter((f) => f.startsWith(prefix)).sort();
        for (const stale of snaps.slice(0, Math.max(0, snaps.length - conf.keepSnapshots))) {
          fs.rmSync(path.join(LORE_DIR, stale), { force: true });
        }
      } catch { /* 快照失败不阻断写入 */ }
    }
    fs.writeFileSync(r.path, body, 'utf8');
    return {
      content: [{ type: 'text', text: `已写入 ${file}（${(bytes / 1024).toFixed(1)}KB）。记住把新条目同步到 lore/README.md 的索引表里。` }],
    };
  }
);

await server.connect(new StdioServerTransport());