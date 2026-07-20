require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1); // 部署在反向代理(nginx/caddy)后，取真实客户端 IP 用于限频
const PORT = process.env.PORT || 5178;
// LLM：DeepSeek（OpenAI 兼容格式）。兼容旧的 ANTHROPIC_API_KEY 变量名。
const API_KEY = process.env.DEEPSEEK_API_KEY || process.env.LLM_API_KEY || process.env.ANTHROPIC_API_KEY;
const MODEL = process.env.LLM_MODEL || 'deepseek-chat';
const LLM_NAME = process.env.LLM_NAME || 'DeepSeek';
// 默认 DeepSeek 官方地址，可用 LLM_BASE_URL 覆盖（可带路径前缀）
const _base = new URL(process.env.LLM_BASE_URL || process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com');
const BASE_HOST = _base.hostname;
const BASE_PORT = _base.port || 443;
const BASE_PATH = _base.pathname.replace(/\/$/, ''); // 去掉结尾斜杠

app.use(express.json({ limit: '1mb' }));

// ============================================================
//  鉴权：口令制私密空间（少数熟人，各自私密）
// ============================================================
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SECRET_FILE = path.join(DATA_DIR, 'session-secret');
const SESSION_DAYS = 30;
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1'; // HTTPS 部署时置 1

// 用户表（哈希 + salt），启动时加载一次
function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
}
let USERS = loadUsers();
if (!USERS.length) {
  console.warn('\n⚠  未找到 data/users.json，任何人都无法登录。');
  console.warn('   请先运行： node scripts/gen-users.mjs\n');
}
const hashPassword = (password, salt) =>
  crypto.createHash('sha256').update(salt + ':' + password).digest('hex');

// 会话签名密钥：env 优先，否则持久化到 data/session-secret（重启后会话不失效）
function loadSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  try {
    return fs.readFileSync(SECRET_FILE, 'utf8').trim();
  } catch {
    const s = crypto.randomBytes(32).toString('hex');
    try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(SECRET_FILE, s); } catch {}
    return s;
  }
}
const SESSION_SECRET = loadSecret();

// 签名 token：base64url(payload).hmac —— payload 含 uid 和过期时间
function signToken(uid) {
  const exp = Date.now() + SESSION_DAYS * 86400000;
  const payload = Buffer.from(JSON.stringify({ uid, exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  // 定长比较，防时序侧信道
  const a = Buffer.from(sig); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.exp || data.exp < Date.now()) return null;
    return data.uid;
  } catch { return null; }
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setSessionCookie(res, uid) {
  const parts = [
    'xinji_session=' + signToken(uid),
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=' + SESSION_DAYS * 86400,
  ];
  if (COOKIE_SECURE) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function currentUser(req) {
  const uid = verifyToken(parseCookies(req).xinji_session);
  if (!uid) return null;
  return USERS.find((u) => u.id === uid) || null;
}
// 保护接口：未登录返回 401
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: '未登录' });
  req.user = user;
  next();
}

// 登录限频：同一 IP 连续失败则临时锁定，防口令爆破
const loginFails = new Map(); // ip -> {count, until}
function loginThrottle(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const rec = loginFails.get(ip);
  if (rec && rec.until > Date.now()) {
    const sec = Math.ceil((rec.until - Date.now()) / 1000);
    return res.status(429).json({ error: `尝试太频繁，请 ${sec} 秒后再试` });
  }
  req._loginIp = ip;
  next();
}
function noteLoginResult(ip, ok) {
  if (ok) { loginFails.delete(ip); return; }
  const rec = loginFails.get(ip) || { count: 0, until: 0 };
  rec.count += 1;
  if (rec.count >= 5) { rec.until = Date.now() + 5 * 60000; rec.count = 0; } // 锁 5 分钟
  loginFails.set(ip, rec);
}

// AI 接口限频：每用户滑动窗口，防有人刷爆 Claude key
const AI_MAX = Number(process.env.AI_RATE_MAX || 30);      // 每窗口最多次数
const AI_WINDOW = Number(process.env.AI_RATE_WINDOW || 60) * 1000; // 窗口秒数
const aiHits = new Map(); // uid -> [timestamps]
function aiRateLimit(req, res, next) {
  const uid = req.user.id;
  const now = Date.now();
  const arr = (aiHits.get(uid) || []).filter((t) => now - t < AI_WINDOW);
  if (arr.length >= AI_MAX) {
    const wait = Math.ceil((AI_WINDOW - (now - arr[0])) / 1000);
    return res.status(429).json({ error: `太快啦，歇 ${wait} 秒再继续好吗？` });
  }
  arr.push(now);
  aiHits.set(uid, arr);
  next();
}

app.post('/api/login', loginThrottle, (req, res) => {
  const name = (req.body.name || '').trim();
  const password = (req.body.password || '').trim();
  const user = USERS.find((u) => u.name === name);
  const ok = user && hashPassword(password, user.salt) === user.hash;
  noteLoginResult(req._loginIp, !!ok);
  if (!ok) return res.status(401).json({ error: '名字或口令不对' });
  setSessionCookie(res, user.id);
  res.json({ name: user.name, role: user.role });
});

app.post('/api/logout', (req, res) => {
  const parts = ['xinji_session=', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (COOKIE_SECURE) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: '未登录' });
  res.json({ name: user.name, role: user.role });
});

// 静态资源（登录页本身也是静态的，放在鉴权之后、数据接口之前）
app.use(express.static(path.join(__dirname, 'public')));


// ---------- 轻量 JSON 持久化 ----------
const DATA_FILE = path.join(__dirname, 'data', 'entries.json');
function readEntries() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return [];
  }
}
function writeEntries(entries) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(entries, null, 2));
}
// 内存写队列：串行化「读-改-写」，避免 /api/reflect 与 /api/chat 并发覆盖
let _writeChain = Promise.resolve();
function enqueueWrite(mutator) {
  _writeChain = _writeChain.then(() => {
    const entries = readEntries();
    const result = mutator(entries); // mutator 直接改 entries，可返回任意值
    writeEntries(entries);
    return result;
  });
  return _writeChain;
}

// ---------- 调用 LLM（DeepSeek / OpenAI 兼容格式，原生 https 无依赖） ----------
// input 可以是字符串（单轮）或 [{role,content},...]（多轮）
function callClaude(systemPrompt, input, maxTokens = 1024) {
  return new Promise((resolve, reject) => {
    const convo =
      typeof input === 'string' ? [{ role: 'user', content: input }] : input;
    // OpenAI 兼容格式：system 作为首条 message
    const messages = [{ role: 'system', content: systemPrompt }, ...convo];
    const payload = JSON.stringify({
      model: MODEL,
      max_tokens: maxTokens,
      messages,
    });
    const req = https.request(
      {
        hostname: BASE_HOST,
        port: BASE_PORT,
        path: BASE_PATH + '/chat/completions',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer ' + API_KEY,
          'content-length': Buffer.byteLength(payload),
        },
      },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          try {
            const json = JSON.parse(body);
            if (json.error) return reject(new Error(json.error.message || JSON.stringify(json.error)));
            const text = json.choices && json.choices[0] && json.choices[0].message
              && json.choices[0].message.content;
            if (typeof text !== 'string') return reject(new Error('意外的返回格式: ' + body.slice(0, 200)));
            resolve(text);
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ---------- AI 回应的人格与规则 ----------
const SYSTEM_PROMPT = `你是「心迹」——一个温暖、克制、有洞察力的内心陪伴者。用户会随手丢进来一段文字，可能是此刻的情绪，也可能是一句打动TA的摘抄/短句。

你的任务：判断这段文字属于哪一类，并给出恰到好处的回应。返回严格的 JSON（不要用 markdown 代码块包裹）：
{
  "type": "emotion" | "quote",        // emotion=用户自己的情绪心事；quote=摘抄/引用的句子/歌词/诗
  "emotion_label": "两到四个字的情绪命名，如 未被听见的委屈、松了一口气；若是 quote 则为空字符串",
  "response": "你的回应正文",
  "gentle_question": "一句轻轻的、开放式的追问，邀请TA多说一点；不要说教"
}

回应的原则（非常重要）：
- 不要急着安慰，也不要讲大道理。安慰是廉价的。
- 对情绪(emotion)：先帮TA把情绪准确地命名和看见——常常人自己说的情绪不是真正的那个（"我很烦"底下可能是"没被在乎"）。用一两句话温柔地反映，让TA觉得"被接住了"。
- 对句子(quote)：不要复述句子。轻轻点出它可能戳中了TA的什么，或替TA说出那句说不清的共鸣。
- 语气像一个懂你的、安静的朋友，不是心理咨询师，也不是鸡汤号。
- 简短。回应正文 2-4 句即可。中文。
- 若察觉到自伤、轻生等严重信号，回应里温柔地鼓励TA联系信任的人或专业帮助（如心理援助热线），不要独自硬扛这件事。`;

// 无 key 时的降级模拟：基于关键词的温暖回应
function mockReflect(text) {
  const quoteHints = ['"', '"', '"', '—', '——', '「', '『', '，'];
  // 第一人称的心事/口语，判为情绪；否则偏格言式短句，判为句子
  const firstPerson = /我|俺|自己|今天|昨天|好累|好烦|难受|emo|崩溃|想哭|不想/.test(text);
  const looksQuote =
    !firstPerson &&
    (quoteHints.some((h) => text.includes(h)) || text.length < 30);
  if (looksQuote) {
    return {
      type: 'quote',
      emotion_label: '',
      response: '这句话能被你收下来，大概是它替你说出了心里某个说不清的角落。',
      gentle_question: '它让你想起了什么，或是此刻的哪一点？',
    };
  }
  const negative = /累|烦|难过|委屈|焦虑|怕|孤独|失望|压力|哭|崩溃/.test(text);
  return {
    type: 'emotion',
    emotion_label: negative ? '需要被看见的疲惫' : '此刻的心情',
    response: negative
      ? '听起来你撑了挺久了。先不用急着好起来，能把它写下来，已经是善待自己的一步。'
      : '谢谢你愿意把这一刻记下来。它值得被留住。',
    gentle_question: '这份感觉，最早是从什么时候冒出来的？',
  };
}

// 无 key 时深聊降级：顺着刚说的话，给一句温和的接话
function mockChat(message) {
  const negative = /累|烦|难过|委屈|焦虑|怕|孤独|失望|压力|哭|崩溃|痛|难/.test(message);
  return negative
    ? '这份感觉还在，对吗？不用急着推开它。能多说一点，是什么让它更重了？'
    : '我在听着呢，你可以慢慢说，想到哪说到哪。';
}

// ---------- /api/reflect：分类 + 温暖回应 ----------
app.post('/api/reflect', requireAuth, aiRateLimit, async (req, res) => {
  const text = (req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: '内容为空' });

  let reflection;
  if (API_KEY) {
    try {
      const raw = await callClaude(SYSTEM_PROMPT, text);
      const cleaned = raw.replace(/^```json\s*/i, '').replace(/```$/i, '').trim();
      reflection = JSON.parse(cleaned);
    } catch (e) {
      console.error('Claude 调用失败，降级为模拟：', e.message);
      reflection = mockReflect(text);
    }
  } else {
    reflection = mockReflect(text);
  }

  const entry = {
    id: Date.now().toString(36) + Math.floor(performance.now()).toString(36),
    owner: req.user.id,
    text,
    type: reflection.type,
    emotion_label: reflection.emotion_label || '',
    response: reflection.response,
    gentle_question: reflection.gentle_question || '',
    createdAt: new Date().toISOString(),
    messages: [],
  };
  await enqueueWrite((entries) => entries.push(entry));
  res.json(entry);
});

// ---------- /api/entries：时间线（只返回自己的） ----------
app.get('/api/entries', requireAuth, (req, res) => {
  res.json(readEntries().filter((e) => e.owner === req.user.id).reverse());
});

app.delete('/api/entries/:id', requireAuth, async (req, res) => {
  const removed = await enqueueWrite((entries) => {
    const i = entries.findIndex((e) => e.id === req.params.id);
    if (i === -1) return false;
    if (entries[i].owner !== req.user.id) return 'forbidden'; // 不是自己的，拒绝
    entries.splice(i, 1);
    return true;
  });
  if (removed === 'forbidden') return res.status(403).json({ error: '无权删除' });
  res.json({ ok: true });
});

// ---------- /api/lookback：回望（把碎片连成一条线） ----------
const LOOKBACK_PROMPT = `你是「心迹」的回望者。下面是用户一段时间以来记录的情绪和收藏的句子（按时间顺序）。请像一个很懂TA、温柔的老朋友，写一段回望，让TA看见自己。

要求：
- 找出反复出现的情绪主题（TA在为什么反复揪心）。
- 找出TA收藏的句子里的共同渴望。
- 最动人的部分：如果某个情绪和某句摘抄其实在讲同一件事，把它们连起来指出来。
- 结尾给TA一句真诚的、看见TA成长/努力的话。不要鸡汤，要具体。
- 300字以内，温暖、第二人称"你"。直接输出正文，不要标题不要JSON。`;

app.post('/api/lookback', requireAuth, aiRateLimit, async (req, res) => {
  const entries = readEntries().filter((e) => e.owner === req.user.id);
  if (entries.length < 2) {
    return res.json({
      text: '再多记几笔吧。等这里攒下一些你的心情和喜欢的句子，我就能帮你把它们连成一条线，让你看看自己走过的路。',
    });
  }
  const digest = entries
    .map((e) => {
      const d = new Date(e.createdAt).toLocaleDateString('zh-CN');
      return e.type === 'quote'
        ? `[${d}] 收藏的句子：${e.text}`
        : `[${d}] 心情(${e.emotion_label})：${e.text}`;
    })
    .join('\n');

  if (!API_KEY) {
    const emoCount = entries.filter((e) => e.type === 'emotion').length;
    const quoteCount = entries.filter((e) => e.type === 'quote').length;
    return res.json({
      text: `这段时间，你记下了 ${emoCount} 次心情，收藏了 ${quoteCount} 句打动你的话。\n\n翻看它们的时候会发现：你并不是没有情绪，你只是一直在认真地对待自己的每一种感受。你收藏的那些句子，其实都是你想对自己说的话。\n\n能一直记录到今天，你已经比自己以为的走得更远了。（接上 Claude API 后，这里会变成真正为你量身写的回望。）`,
    });
  }
  try {
    const text = await callClaude(LOOKBACK_PROMPT, digest);
    res.json({ text });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- /api/chat：对某条记录继续深聊（多轮） ----------
const CHAT_PROMPT = `你是「心迹」——一个温暖、克制、有洞察力的内心陪伴者。用户此前记下了一段情绪或一句摘抄，你已经回应过；现在这是一段正在继续的对话。

原则：
- 顺着TA刚说的话往下轻轻接，不要重复之前说过的话，也不要重新总结。
- 不急着安慰，不讲大道理。先让TA觉得被听见、被接住。
- 常常人自己说的情绪不是真正的那个，温柔地帮TA看见底下真正的感受。
- 像一个懂你的、安静的老朋友，不是心理咨询师，也不是鸡汤号。
- 简短。每次 2-4 句即可。中文。直接说话，不要任何前缀或格式标记。
- 若察觉到自伤、轻生等严重信号，温柔地鼓励TA联系信任的人或专业帮助（如心理援助热线），不要独自硬扛。`;

const CHAT_HISTORY_LIMIT = 12; // 只带最近 N 条往返，防止上下文无限增长

app.post('/api/chat', requireAuth, aiRateLimit, async (req, res) => {
  const id = req.body.id;
  const message = (req.body.message || '').trim();
  if (!message) return res.status(400).json({ error: '内容为空' });

  const entry = readEntries().find((e) => e.id === id);
  if (!entry) return res.status(404).json({ error: '找不到这条记录' });
  if (entry.owner !== req.user.id) return res.status(403).json({ error: '无权访问' });

  // 组装多轮上下文：以原文+首次回应起头，再接最近的深聊往返
  const history = (entry.messages || []).slice(-CHAT_HISTORY_LIMIT);
  const built = [
    { role: 'user', content: entry.text },
    ...(entry.response ? [{ role: 'assistant', content: entry.response }] : []),
    ...history.map((m) => ({ role: m.role, content: m.content })),
    { role: 'user', content: message },
  ];

  let reply;
  if (API_KEY) {
    try {
      reply = (await callClaude(CHAT_PROMPT, built)).trim();
    } catch (e) {
      console.error('深聊调用失败，降级为模拟：', e.message);
      reply = mockChat(message);
    }
  } else {
    reply = mockChat(message);
  }

  const now = new Date().toISOString();
  const saved = await enqueueWrite((entries) => {
    const e = entries.find((x) => x.id === id);
    if (!e || e.owner !== req.user.id) return null;
    if (!Array.isArray(e.messages)) e.messages = [];
    e.messages.push({ role: 'user', content: message, createdAt: now });
    e.messages.push({ role: 'assistant', content: reply, createdAt: now });
    return e.messages;
  });
  if (!saved) return res.status(404).json({ error: '找不到这条记录' });
  res.json({ reply, messages: saved });
});

// 启动迁移：把没有 owner 的存量记录归给管理员（首个 admin 用户）
function migrateOwnerless() {
  const admin = USERS.find((u) => u.role === 'admin') || USERS[0];
  if (!admin) return; // 还没建用户，跳过
  const entries = readEntries();
  let n = 0;
  entries.forEach((e) => { if (!e.owner) { e.owner = admin.id; n++; } });
  if (n) { writeEntries(entries); console.log(`  已迁移 ${n} 条无主记录给管理员「${admin.name}」`); }
}
migrateOwnerless();

app.listen(PORT, () => {
  console.log(`\n  心迹 running →  http://localhost:${PORT}`);
  console.log(`  AI 模式：${API_KEY ? '已接入 ' + LLM_NAME + ' ✨' : '模拟回应（未配置 API key）'}\n`);
});
