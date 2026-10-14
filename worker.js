/**
 * Telegram Bot Worker v3.70+
 * 架构: Cloudflare Workers + D1 Database
 *
 * ✅ P0:
 * - Webhook secret_token 校验（拒绝非 Telegram）
 * - /submit_token 强制 initData 验签（不信任 userId）
 * - 管理员鉴权 Set 精确匹配（避免 includes 子串误判）
 * - 话题创建分布式幂等（D1 抢锁）
 *
 * ✅ P1:
 * - update 幂等去重（processed_updates）
 * - 全局/单用户限流（ratelimits，使用 RETURNING 降低 round trips）
 * - TG API 重试与退避（429/5xx/网络异常）
 * - 话题轮询指数退避 + 抖动，降低 D1 压力
 *
 * ✅ P2:
 * - 正则 ReDoS 缓解：限制输入长度 + 拒绝高风险 regex 形态
 * - messages 表 TTL 清理（默认保留 30 天），异步概率触发
 *
 * ✅ 修复：
 * - 屏蔽用户不再“/start 自愈解封”；屏蔽后无法再发送消息触达管理员
 * - 新增管理员私聊命令：/reset <id> 强制用户重新验证
 *
 * 需要新增环境变量：
 * - TELEGRAM_WEBHOOK_SECRET: Telegram setWebhook 的 secret_token（请求头 X-Telegram-Bot-Api-Secret-Token）
 */

// --- 1. 静态配置与常量 ---
const CACHE = {
  data: {},
  ts: 0,
  ttl: 60000,
  locks: new Set(), // isolate 内短 TTL 防抖（不用于分布式一致性）
  admin: {
    ts: 0,
    ttl: 60000,
    primarySet: new Set(),
    authSet: new Set()
  },
  // 清理节流：避免每个请求都触发清理
  cleanup: {
    processed_updates_ts: 0,
    ratelimits_ts: 0,
    messages_ts: 0
  }
};

const DEFAULTS = {
  // 基础
  welcome_msg: "欢迎 {name}！🎉",

  // 验证（初始部署：关闭，测试转发流程；面板可随时打开）
  enable_verify: "false",
  enable_qa_verify: "false",
  captcha_mode: "turnstile", // turnstile 或 recaptcha
  verif_q: "1+1=?\n提示：答案在简介中。",
  verif_a: "2",

  // 风控
  block_threshold: "5",
  enable_admin_receipt: "true", // 保留但不再使用（已按需求移除文字回执）

  // 转发开关
  enable_image_forwarding: "true",
  enable_link_forwarding: "true",
  enable_text_forwarding: "true",
  enable_channel_forwarding: "true",
  enable_forward_forwarding: "true",
  enable_audio_forwarding: "true",
  enable_sticker_forwarding: "true",

  // 话题与列表
  backup_group_id: "",
  unread_topic_id: "",
  blocked_topic_id: "",
  busy_mode: "false",
  busy_msg: "当前是非营业时间，消息已收到，管理员稍后回复。",
  block_keywords: "[]",
  keyword_responses: "[]",
  authorized_admins: "[]"
};

// 已送达 reaction
const DELIVERED_REACTION = "👍";

// 幂等/限流/锁参数
const PROCESSED_UPDATES_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7d
const RATELIMIT_CLEANUP_TTL_MS = 10 * 60 * 1000; // ratelimits 仅保留 10min

// 私聊消息限流（跨实例）
const RATELIMIT_USER_WINDOW_MS = 2000; // 2s
const RATELIMIT_USER_MAX = 6; // 每用户 2s 最多 6 条
const RATELIMIT_GLOBAL_WINDOW_MS = 10000; // 10s
const RATELIMIT_GLOBAL_MAX = 250; // 全局 10s 最多 250 条

// /submit_token 限流（防滥用）
const SUBMIT_RL_WINDOW_MS = 60000; // 60s
const SUBMIT_RL_IP_MAX = 30; // 每 IP 每分钟最多 30 次（含失败）
const SUBMIT_RL_UID_MAX = 10; // 每 uid 每分钟最多 10 次（含失败）

// 话题创建锁
const TOPIC_LOCK_STALE_MS = 60 * 1000; // 话题创建锁 1min 视为过期
const TOPIC_LOCK_POLL_MAX = 8; // 轮询次数减少
const TOPIC_LOCK_POLL_BASE_MS = 160; // 指数退避 base

// 验证 nonce
const VERIFY_NONCE_TTL_MS = 15 * 60 * 1000; // 15min

// messages TTL
const MESSAGES_TTL_DAYS = 30;

// Regex 安全策略（ReDoS 缓解）
const REGEX_MAX_PATTERN_LEN = 256;
const REGEX_MAX_TEXT_LEN = 512; // 仅对前 512 字符做 regex test，降低灾难性回溯伤害
const REGEX_REJECT_PATTERNS = [
  /\([^)]*\)\s*[+*{]/,
  /\(\s*\.\*\s*\)\s*\+/,
  /\(\s*\.\+\s*\)\s*\+/,
  /\\[1-9]/,
  /\(\?<=[\s\S]*\)/,
  /\(\?<![\s\S]*\)/
];

// 消息类型定义
const MSG_TYPES = [
  {
    check: m => m.forward_from || m.forward_from_chat,
    key: "enable_forward_forwarding",
    name: "转发消息",
    extra: m => (m.forward_from_chat?.type === "channel" ? "enable_channel_forwarding" : null)
  },
  { check: m => m.audio || m.voice, key: "enable_audio_forwarding", name: "语音/音频" },
  { check: m => m.sticker || m.animation, key: "enable_sticker_forwarding", name: "贴纸/GIF" },
  { check: m => m.photo || m.video || m.document, key: "enable_image_forwarding", name: "媒体文件" },
  { check: m => (m.entities || []).some(e => ["url", "text_link"].includes(e.type)), key: "enable_link_forwarding", name: "链接" },
  { check: m => m.text, key: "enable_text_forwarding", name: "纯文本" }
];

// --- 2. 核心入口 ---
export default {
  async fetch(req, env, ctx) {
    ctx.waitUntil(dbInit(env).catch(e => console.error("DB Init Failed:", e)));

    const url = new URL(req.url);

    try {
      if (req.method === "GET") {
        if (url.pathname === "/verify") return handleVerifyPage(url, env);
        if (url.pathname === "/") return new Response("Bot v3.70+ (Hardened + Block Fix + /reset)", { status: 200 });
      }

      if (req.method === "POST") {
        // /submit_token：外部网页回调，不走 webhook secret，但必须限流 + 强验签
        if (url.pathname === "/submit_token") return handleTokenSubmit(req, env, ctx);

        // Webhook secret_token 校验：拒绝非 Telegram
        if (!isTelegramWebhook(req, env)) {
          return new Response("Forbidden", { status: 403 });
        }

        try {
          const update = await req.json();

          // update 幂等去重（P1）
          const ok = await markUpdateOnce(update, env, ctx);
          if (!ok) return new Response("OK");

          ctx.waitUntil(handleUpdate(update, env, ctx));
          return new Response("OK");
        } catch {
          return new Response("Bad Request", { status: 400 });
        }
      }
    } catch (e) {
      console.error("Critical Worker Error:", e);
      return new Response("Internal Server Error", { status: 500 });
    }

    return new Response("404 Not Found", { status: 404 });
  }
};

// --- 3. 数据库封装 ---
const safeParse = (str, fb = {}) => {
  try {
    return JSON.parse(str);
  } catch {
    return fb;
  }
};

const sql = async (env, query, args = [], type = "run") => {
  try {
    const stmt = env.TG_BOT_DB.prepare(query).bind(...(Array.isArray(args) ? args : [args]));
    return type === "run" ? await stmt.run() : await stmt[type]();
  } catch (e) {
    console.error(`SQL Fail [${query}]:`, e);
    if (query.match(/^(INSERT|UPDATE|DELETE|REPLACE|ALTER|CREATE)/i)) throw e;
    return null;
  }
};

const tryRun = async (env, query, args = []) => {
  try {
    const stmt = env.TG_BOT_DB.prepare(query).bind(...(Array.isArray(args) ? args : [args]));
    return await stmt.run();
  } catch {
    return null;
  }
};

async function getCfg(k, env) {
  const now = Date.now();
  if (CACHE.ts && now - CACHE.ts < CACHE.ttl && CACHE.data[k] !== undefined) return CACHE.data[k];

  const rows = await sql(env, "SELECT * FROM config", [], "all");
  if (rows?.results) {
    CACHE.data = {};
    rows.results.forEach(r => (CACHE.data[r.key] = r.value));
    CACHE.ts = now;
  }

  const envK = k.toUpperCase().replace(/_MSG|_Q|_A/, m => ({ _MSG: "_MESSAGE", _Q: "_QUESTION", _A: "_ANSWER" }[m]));
  return CACHE.data[k] ?? (env[envK] || DEFAULTS[k] || "");
}

async function setCfg(k, v, env) {
  await sql(env, "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", [k, v]);
  CACHE.ts = 0;
}

async function getUser(id, env) {
  let u = await sql(env, "SELECT * FROM users WHERE user_id = ?", id, "first");
  if (!u) {
    try {
      await sql(env, "INSERT OR IGNORE INTO users (user_id, user_state, user_info_json) VALUES (?, 'new', ?)", [id, "{}"]);
    } catch {}
    u = await sql(env, "SELECT * FROM users WHERE user_id = ?", id, "first");
  }
  if (!u) {
    u = {
      user_id: id,
      user_state: "new",
      is_blocked: 0,
      block_count: 0,
      topic_id: null,
      user_info_json: "{}",
      topic_creating: 0,
      topic_create_ts: 0
    };
  }
  u.is_blocked = !!u.is_blocked;
  u.user_info = safeParse(u.user_info_json, {});
  u.topic_creating = !!u.topic_creating;
  u.topic_create_ts = u.topic_create_ts || 0;
  return u;
}

async function mergeUserInfo(id, patch, env) {
  const row = await sql(env, "SELECT user_info_json FROM users WHERE user_id = ?", id, "first");
  const cur = safeParse(row?.user_info_json || "{}", {});
  const merged = { ...(cur && typeof cur === "object" ? cur : {}), ...(patch && typeof patch === "object" ? patch : {}) };
  return JSON.stringify(merged);
}

async function updUser(id, data, env) {
  if (data.user_info) {
    data.user_info_json = await mergeUserInfo(id, data.user_info, env);
    delete data.user_info;
  }

  const keys = Object.keys(data);
  if (!keys.length) return;

  const safeKeys = keys.filter(k =>
    ["user_state", "is_blocked", "block_count", "topic_id", "user_info_json", "topic_creating", "topic_create_ts"].includes(k)
  );
  if (!safeKeys.length) return;

  const q = `UPDATE users SET ${safeKeys.map(k => `${k}=?`).join(",")} WHERE user_id=?`;
  const v = [...safeKeys.map(k => (typeof data[k] === "boolean" ? (data[k] ? 1 : 0) : data[k])), id];
  try {
    await sql(env, q, v);
  } catch (e) {
    console.error("Update User Failed:", e);
  }
}

async function dbInit(env) {
  if (!env.TG_BOT_DB) return;

  await env.TG_BOT_DB.batch([
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      user_state TEXT DEFAULT 'new',
      is_blocked INTEGER DEFAULT 0,
      block_count INTEGER DEFAULT 0,
      topic_id TEXT,
      user_info_json TEXT DEFAULT '{}',
      topic_creating INTEGER DEFAULT 0,
      topic_create_ts INTEGER DEFAULT 0
    )`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS messages (
      user_id TEXT,
      message_id TEXT,
      text TEXT,
      date INTEGER,
      PRIMARY KEY (user_id, message_id)
    )`),
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date)`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS fwd_map (
      user_id TEXT,
      admin_msg_id TEXT,
      user_msg_id INTEGER,
      PRIMARY KEY (user_id, admin_msg_id)
    )`),

    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS processed_updates (
      update_id TEXT PRIMARY KEY,
      ts INTEGER
    )`),
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_processed_updates_ts ON processed_updates(ts)`),

    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS ratelimits (
      key TEXT PRIMARY KEY,
      ts INTEGER,
      count INTEGER
    )`),
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_ratelimits_ts ON ratelimits(ts)`)
  ]);

  await ensureUserColumns(env);
}

async function ensureUserColumns(env) {
  const info = await sql(env, "PRAGMA table_info(users)", [], "all");
  const cols = new Set((info?.results || []).map(r => r.name));

  const alters = [];
  if (!cols.has("topic_creating")) alters.push(`ALTER TABLE users ADD COLUMN topic_creating INTEGER DEFAULT 0`);
  if (!cols.has("topic_create_ts")) alters.push(`ALTER TABLE users ADD COLUMN topic_create_ts INTEGER DEFAULT 0`);

  for (const q of alters) {
    try {
      await sql(env, q);
    } catch {}
  }
}

// --- 4. Telegram API（带重试退避） ---
async function api(token, method, body) {
  const maxRetries = 3;
  const baseBackoff = [200, 500, 1200];
  const totalWaitCapMs = 10000;
  let waited = 0;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const d = await r.json().catch(() => null);

      if (r.status >= 500) throw new Error(`HTTP_${r.status}`);

      if (!d || !d.ok) {
        const errCode = d?.error_code || r.status || 0;

        if (errCode === 429 && attempt < maxRetries) {
          const retryAfterSec = Number(d?.parameters?.retry_after || 0);
          const delayMs = Math.min(5000, Math.max(200, (retryAfterSec ? retryAfterSec * 1000 : baseBackoff[attempt] || 1200)));
          if (waited + delayMs > totalWaitCapMs) break;
          waited += delayMs;
          await sleep(delayMs);
          continue;
        }

        const desc = d?.description || `TG API Error (${errCode})`;
        if (method !== "setMessageReaction") console.warn(`TG API Error [${method}]:`, desc);
        throw new Error(desc);
      }

      return d.result;
    } catch (e) {
      if (attempt < maxRetries) {
        const delayMs = baseBackoff[attempt] || 1200;
        if (waited + delayMs > totalWaitCapMs) break;
        waited += delayMs;
        await sleep(delayMs);
        continue;
      }
      if (method !== "setMessageReaction") console.warn(`TG API Fail [${method}]:`, e?.message || e);
      throw e;
    }
  }

  throw new Error(`TG API Retry Exhausted: ${method}`);
}

// --- 5. Webhook 校验 / 幂等 / 限流 / 清理 ---
function isTelegramWebhook(req, env) {
  const secret = (env.TELEGRAM_WEBHOOK_SECRET || "").toString();
  if (!secret) return false;
  const hdr = req.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  return timingSafeEqualStr(hdr, secret);
}

function safeWaitUntil(ctx, p) {
  try {
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p);
    else p.catch(() => {});
  } catch {
    try {
      p.catch(() => {});
    } catch {}
  }
}

function maybeCleanup(ctx, key, fn, minIntervalMs) {
  const now = Date.now();
  const last = CACHE.cleanup[key] || 0;
  if (now - last < minIntervalMs) return;
  CACHE.cleanup[key] = now;
  safeWaitUntil(ctx, fn());
}

async function markUpdateOnce(update, env, ctx) {
  try {
    const uid = (update && (update.update_id ?? update.updateId))?.toString();
    if (!uid) return true;

    const now = Date.now();
    const res = await tryRun(env, "INSERT OR IGNORE INTO processed_updates (update_id, ts) VALUES (?,?)", [uid, now]);
    const changes = res?.meta?.changes ?? res?.changes ?? 0;
    if (!changes) return false;

    if ((now % 97) === 7) {
      maybeCleanup(ctx, "processed_updates_ts", async () => {
        const cutoff = now - PROCESSED_UPDATES_TTL_MS;
        await sql(env, "DELETE FROM processed_updates WHERE ts < ?", cutoff);
      }, 60_000);
    }

    return true;
  } catch {
    return true;
  }
}

async function bumpRateKey(env, key, now) {
  const q = `
    INSERT INTO ratelimits (key, ts, count) VALUES (?, ?, 1)
    ON CONFLICT(key) DO UPDATE SET count = ratelimits.count + 1, ts = excluded.ts
    RETURNING count
  `;
  const row = await sql(env, q, [key, now], "first");
  const c = Number(row?.count || 0);
  return c;
}

async function checkRateLimit(userId, env, ctx) {
  const now = Date.now();
  const uid = userId?.toString() || "";
  if (!uid) return { allowed: true, retryAfterMs: 0 };

  const userBucket = Math.floor(now / RATELIMIT_USER_WINDOW_MS);
  const globalBucket = Math.floor(now / RATELIMIT_GLOBAL_WINDOW_MS);

  const userKey = `u:${uid}:${userBucket}`;
  const globalKey = `g:${globalBucket}`;

  const [uc, gc] = await Promise.all([bumpRateKey(env, userKey, now), bumpRateKey(env, globalKey, now)]);

  if ((now % 101) === 13) {
    maybeCleanup(ctx, "ratelimits_ts", async () => {
      const cutoff = now - RATELIMIT_CLEANUP_TTL_MS;
      await sql(env, "DELETE FROM ratelimits WHERE ts < ?", cutoff);
    }, 60_000);
  }

  if (gc > RATELIMIT_GLOBAL_MAX) return { allowed: false, retryAfterMs: RATELIMIT_GLOBAL_WINDOW_MS };
  if (uc > RATELIMIT_USER_MAX) return { allowed: false, retryAfterMs: RATELIMIT_USER_WINDOW_MS };

  return { allowed: true, retryAfterMs: 0 };
}

async function checkSubmitRateLimit(req, env, ctx, uidMaybe) {
  const now = Date.now();
  const ip = (req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For") || "").split(",")[0].trim() || "0.0.0.0";
  const bucket = Math.floor(now / SUBMIT_RL_WINDOW_MS);

  const ipKey = `s:ip:${ip}:${bucket}`;
  const ipCount = await bumpRateKey(env, ipKey, now);
  if (ipCount > SUBMIT_RL_IP_MAX) return { allowed: false, reason: "ip" };

  if (uidMaybe) {
    const uKey = `s:u:${uidMaybe}:${bucket}`;
    const uCount = await bumpRateKey(env, uKey, now);
    if (uCount > SUBMIT_RL_UID_MAX) return { allowed: false, reason: "uid" };
  }

  if ((now % 103) === 19) {
    maybeCleanup(ctx, "ratelimits_ts", async () => {
      const cutoff = now - RATELIMIT_CLEANUP_TTL_MS;
      await sql(env, "DELETE FROM ratelimits WHERE ts < ?", cutoff);
    }, 60_000);
  }

  return { allowed: true };
}

function maybeCleanupMessages(env, ctx) {
  const now = Date.now();
  if ((now % 131) !== 11) return;
  maybeCleanup(ctx, "messages_ts", async () => {
    const cutoffSec = Math.floor(now / 1000) - MESSAGES_TTL_DAYS * 86400;
    await sql(env, "DELETE FROM messages WHERE date < ?", cutoffSec);
  }, 10 * 60_000);
}

// --- 6. 主 update 分发 ---
async function handleUpdate(update, env, ctx) {
  const msg = update.message || update.edited_message;
  if (!msg) return update.callback_query ? handleCallback(update.callback_query, env) : null;

  if (update.edited_message && msg.chat.type === "private") return handleEdit(msg, env);
  // 管理员在话题里编辑消息：原地改访客那份，不重发
  if (update.edited_message && msg.chat.id.toString() === env.ADMIN_GROUP_ID) return handleAdminEdit(msg, env);
  if (msg.chat.type === "private") await handlePrivate(msg, env, ctx);
  else if (msg.chat.id.toString() === env.ADMIN_GROUP_ID) await handleAdminReply(msg, env);
}

// --- 7. 管理员集合（Set 精确匹配） ---
function parseIdsToSet(str) {
  return new Set(
    (str || "")
      .toString()
      .split(/[,，]/)
      .map(s => s.trim())
      .filter(Boolean)
  );
}

async function getAdminSets(env) {
  const now = Date.now();
  if (CACHE.admin.ts && now - CACHE.admin.ts < CACHE.admin.ttl && CACHE.admin.primarySet.size) {
    return { primary: CACHE.admin.primarySet, auth: CACHE.admin.authSet };
  }

  const primary = parseIdsToSet(env.ADMIN_IDS || "");
  const authList = await getJsonCfg("authorized_admins", env);
  const auth = new Set([...primary, ...((Array.isArray(authList) ? authList : []).map(x => x.toString()))]);

  CACHE.admin.ts = now;
  CACHE.admin.primarySet = primary;
  CACHE.admin.authSet = auth;

  return { primary, auth };
}

async function isPrimaryAdmin(id, env) {
  const sets = await getAdminSets(env);
  return sets.primary.has(id.toString());
}

async function isAuthAdmin(id, env) {
  const sets = await getAdminSets(env);
  return sets.auth.has(id.toString());
}

// --- 8. 私聊处理（方案 S） ---
async function handlePrivate(msg, env, ctx) {
  const id = msg.chat.id.toString();
  const text = msg.text || "";
  const isStart = text.startsWith("/start");

  // ✅ 修复：屏蔽必须生效（不再 /start 自愈解封）
  // 先取用户，保证 block 生效是 DB 真实状态
  const u0 = await getUser(id, env);
  if (u0.is_blocked && !(await isAuthAdmin(id, env))) {
    // 降噪：10 秒内只提示一次（D1 时间戳，跨实例可靠）
    const nowTs = Date.now();
    const lastTs = Number((u0.user_info && u0.user_info.blocked_notice_ts) || 0);
    if (nowTs - lastTs > 10000) {
      await updUser(id, { user_info: { blocked_notice_ts: nowTs } }, env);
      // 必须 await：fire-and-forget 在 return 后可能被运行时回收，导致消息发不出去
      await api(env.BOT_TOKEN, "sendMessage", {
        chat_id: id,
        text: "🚫 您已被管理员屏蔽，无法发送消息。如有误判可申请解封。",
        reply_markup: { inline_keyboard: [[{ text: "📝 申请解封", callback_data: `appeal:${id}` }]] }
      }).catch(() => {});
    }
    return;
  }

  // 限流（非管理员）
  if (!(await isAuthAdmin(id, env))) {
    const rl = await checkRateLimit(id, env, ctx);
    if (!rl.allowed) {
      const warnKey = `rlwarn:${id}`;
      if (!CACHE.locks.has(warnKey)) {
        CACHE.locks.add(warnKey);
        setTimeout(() => CACHE.locks.delete(warnKey), 10000);
        api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "⏳ 请求过于频繁，请稍后再试。" }).catch(() => {});
      }
      return;
    }
  }

  // ✅ 新增：Primary Admin 私聊命令 /reset <id>
  if (text.startsWith("/reset") && (await isPrimaryAdmin(id, env))) {
    const parts = text.trim().split(/\s+/);
    const target = (parts[1] || "").trim();
    if (!target || !/^\d+$/.test(target)) {
      return api(env.BOT_TOKEN, "sendMessage", {
        chat_id: id,
        text: "用法：/reset <user_id>\n示例：/reset 123456789"
      });
    }
    await forceResetUserVerify(target, env);
    // 通知目标用户（失败静默）
    api(env.BOT_TOKEN, "sendMessage", {
      chat_id: target,
      text: "⚠️ 管理员要求您重新验证。\n请发送 /start 重新完成验证流程。"
    }).catch(() => {});
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `✅ 已重置用户 ${target} 的验证状态。` });
  }

  // 管理员命令优先
  if (isStart) {
    if (await isPrimaryAdmin(id, env)) {
      if (ctx) ctx.waitUntil(registerCommands(env));
      return handleAdminConfig(id, null, "menu", null, null, env);
    }
  }

  if ((text === "/del" || text.startsWith("/del ")) && (await isAuthAdmin(id, env))) {
    return api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: "请在管理群话题里回复要删除的那条消息，再发送 /del"
    });
  }

  if (text === "/help" && (await isAuthAdmin(id, env))) {
    return api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: "ℹ️ <b>帮助</b>\n• 回复消息即对话\n• /start 打开面板\n• /reset <id> 重置用户验证(仅主管理员)\n• 话题里回复消息发 /del 删除访客那份",
      parse_mode: "HTML"
    });
  }

  // 继续使用 u0，避免重复读
  const u = u0;

  // 管理员免验证
  if (await isAuthAdmin(id, env)) {
    if (u.user_state !== "verified") await updUser(id, { user_state: "verified" }, env);
  }

  // 管理员状态机输入
  if (await isPrimaryAdmin(id, env)) {
    const stateStr = await getCfg(`admin_state:${id}`, env);
    if (stateStr) {
      const state = safeParse(stateStr);
      if (state.action === "input") return handleAdminInput(id, msg, state, env);
    }
  }

  // 验证拦截
  const verifyOn = await getBool("enable_verify", env);
  const qaOn = await getBool("enable_qa_verify", env);

  if (u.user_state !== "verified" && (verifyOn || qaOn)) {
    if (u.user_state === "pending_verification" && text) return verifyAnswer(id, text, env);
    return sendStart(id, msg, env);
  }

  // 已验证：/start 不再触发验证；也不创建话题（方案 S）
  if (isStart) {
    if (u.topic_id) {
      await api(env.BOT_TOKEN, "sendMessage", {
        chat_id: id,
        text: "✅ <b>会话已连接</b>\n您可以直接发送消息，管理员会收到。",
        parse_mode: "HTML"
      });
    } else {
      await api(env.BOT_TOKEN, "sendMessage", {
        chat_id: id,
        text: "✅ 已验证。\n请直接发送消息以联系管理员。",
        parse_mode: "HTML"
      });
    }
    return;
  }

  await handleVerifiedMsg(msg, u, env, ctx);
}

// ✅ 强制重置用户验证状态（不解封、不改 topic_id）
async function forceResetUserVerify(userId, env) {
  const uid = userId.toString();
  // 清掉 nonce 并回到 new
  // user_info_json 是 JSON 字符串：用 mergeUserInfo 方式安全更新
  await updUser(uid, {
    user_state: "new",
    user_info: { verify_nonce: "", verify_nonce_ts: 0 }
  }, env);
}

// --- 9. Start 流程（确保验证弹出 + nonce） ---
async function sendStart(id, msg, env) {
  const u = await getUser(id, env);

  // 若用户被屏蔽（保险校验）
  if (u.is_blocked && !(await isAuthAdmin(id, env))) {
    return api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: "🚫 您已被管理员屏蔽，无法使用本 Bot。"
    }).catch(() => {});
  }

  if (u.user_state === "verified") {
    if (u.topic_id) {
      await api(env.BOT_TOKEN, "sendMessage", {
        chat_id: id,
        text: "✅ <b>会话已连接</b>\n您可以直接发送消息，管理员会收到。",
        parse_mode: "HTML"
      });
    } else {
      await api(env.BOT_TOKEN, "sendMessage", {
        chat_id: id,
        text: "✅ 已验证。\n请直接发送消息以联系管理员。",
        parse_mode: "HTML"
      });
    }
    return;
  }

  // 欢迎语
  let welcomeRaw = await getCfg("welcome_msg", env);
  const name = escapeHTML(msg.from.first_name || "User");
  let media = null,
    txt = welcomeRaw;
  try {
    if (welcomeRaw.trim().startsWith("{")) {
      media = safeParse(welcomeRaw, null);
      if (media) txt = media.caption || "";
    }
  } catch {}
  txt = txt.replace(/{name}|{user}/g, name);

  if (media && media.type) {
    try {
      await api(env.BOT_TOKEN, `send${media.type.charAt(0).toUpperCase() + media.type.slice(1)}`, {
        chat_id: id,
        [media.type]: media.file_id,
        caption: txt,
        parse_mode: "HTML"
      });
    } catch {
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: txt, parse_mode: "HTML" });
    }
  } else {
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: txt, parse_mode: "HTML" });
  }

  const url = (env.WORKER_URL || "").replace(/\/$/, "");
  const vOn = await getBool("enable_verify", env);
  const qaOn = await getBool("enable_qa_verify", env);

  if (vOn && url) {
    const nonce = genNonce(24);
    const now = Date.now();
    await updUser(
      id,
      {
        user_state: "pending_turnstile",
        user_info: { verify_nonce: nonce, verify_nonce_ts: now }
      },
      env
    );

    await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: "🛡️ <b>安全验证</b>\n请点击下方按钮完成人机验证以继续。",
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [
            {
              text: "点击进行验证",
              web_app: { url: `${url}/verify?user_id=${encodeURIComponent(id)}&nonce=${encodeURIComponent(nonce)}` }
            }
          ]
        ]
      }
    });
  } else if (qaOn) {
    await updUser(id, { user_state: "pending_verification" }, env);
    await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: "❓ <b>安全提问</b>\n" + (await getCfg("verif_q", env)),
      parse_mode: "HTML"
    });
  } else {
    await updUser(id, { user_state: "verified" }, env);
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "✅ 已验证。\n请直接发送消息以联系管理员。" });
  }
}

// --- 10. 已验证用户逻辑 ---
async function handleVerifiedMsg(msg, u, env, ctx) {
  const id = u.user_id;

  // 保险：若中途被屏蔽（并发情况下），直接终止
  if (u.is_blocked && !(await isAuthAdmin(id, env))) return;

  const text = msg.text || msg.caption || "";

  // A. 屏蔽词检测（ReDoS 缓解）
  if (text) {
    const kws = await getJsonCfg("block_keywords", env);
    const hit = (Array.isArray(kws) ? kws : []).some(k => safeRegexTest(k, text));
    if (hit) {
      const c = u.block_count + 1;
      const max = parseInt(await getCfg("block_threshold", env), 10) || 5;
      await updUser(id, { block_count: c, is_blocked: c >= max }, env);

      if (c >= max) {
        await manageBlacklist(env, u, msg.from, true);
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 您已被系统自动封禁" });
      }
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `⚠️ 含有违禁词，请勿发送 (${c}/${max})` });
    }
  }

  // B. 类型过滤
  for (const t of MSG_TYPES) {
    if (t.check(msg)) {
      const enabled = t.extra ? await getBool(t.extra(msg), env) : await getBool(t.key, env);
      if (!enabled && !(await isAuthAdmin(id, env))) {
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `⚠️ 系统不接收 ${t.name}` });
      }
      break;
    }
  }

  // C. 自动回复
  if (text) {
    const rules = await getJsonCfg("keyword_responses", env);
    const match = (Array.isArray(rules) ? rules : []).find(r => r && safeRegexTest(r.keywords, text));
    if (match) api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: match.response }).catch(() => {});
  }

  // D. 忙碌回复
  if (await getBool("busy_mode", env)) {
    const now = Date.now();
    if (now - (u.user_info.last_busy_reply || 0) > 300000) {
      api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🌙 " + (await getCfg("busy_msg", env)) }).catch(() => {});
      await updUser(id, { user_info: { last_busy_reply: now } }, env);
    }
  }

  // E. 转发
  await relayToTopic(msg, u, env, ctx);
}

// --- 11. 转发到话题（D1 分布式幂等 + 指数退避轮询） ---
async function relayToTopic(msg, u, env, ctx) {
  const uid = u.user_id;

  // 保险：若中途被屏蔽（并发情况下），直接终止
  if (u.is_blocked && !(await isAuthAdmin(uid, env))) return;

  const uMeta = getUMeta(msg.from, u, msg.date);
  let tid = u.topic_id;

  if (!tid) {
    const now = Date.now();
    const staleBefore = now - TOPIC_LOCK_STALE_MS;

    const lockRes = await tryRun(
      env,
      `UPDATE users
       SET topic_creating=1, topic_create_ts=?
       WHERE user_id=?
         AND (topic_id IS NULL OR topic_id='')
         AND (topic_creating=0 OR topic_create_ts < ?)`,
      [now, uid, staleBefore]
    );

    const locked = (lockRes?.meta?.changes ?? lockRes?.changes ?? 0) === 1;

    if (locked) {
      try {
        const fresh = await getUser(uid, env);
        if (fresh.topic_id) {
          tid = fresh.topic_id;
        } else {
          const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: uMeta.topicName });
          tid = t.message_thread_id.toString();

          await updUser(uid, { topic_id: tid, topic_creating: 0, topic_create_ts: 0 }, env);
          u.topic_id = tid;

          await sendInfoCardToTopic(env, u, msg.from, tid);
        }
      } catch (e) {
        console.error("Topic Create Error:", e);
        await updUser(uid, { topic_creating: 0 }, env);
        const existUser = await getUser(uid, env);
        if (existUser.topic_id) tid = existUser.topic_id;
        else return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 系统繁忙，请稍后重试" });
      }
    } else {
      for (let i = 0; i < TOPIC_LOCK_POLL_MAX; i++) {
        const delay = Math.min(1500, TOPIC_LOCK_POLL_BASE_MS * Math.pow(2, i)) + Math.floor(Math.random() * 60);
        await sleep(delay);

        const fresh = await getUser(uid, env);
        if (fresh.topic_id) {
          tid = fresh.topic_id;
          u.topic_id = tid;
          break;
        }
      }

      if (!tid) {
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 系统繁忙，请稍后重试" });
      }
    }
  }

  if (!tid) return;

  let relaySuccess = false;
  try {
    await api(env.BOT_TOKEN, "forwardMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      from_chat_id: uid,
      message_id: msg.message_id,
      message_thread_id: tid
    });
    relaySuccess = true;
  } catch {
    try {
      const extra = {};
      if (msg.text) extra.text = msg.text;
      if (msg.caption) extra.caption = msg.caption;
      await api(env.BOT_TOKEN, "copyMessage", {
        chat_id: env.ADMIN_GROUP_ID,
        from_chat_id: uid,
        message_id: msg.message_id,
        message_thread_id: tid,
        ...extra
      });
      relaySuccess = true;
    } catch (cpErr) {
      console.error("Copy Failed:", cpErr);
      if (cpErr.message && (cpErr.message.includes("thread") || cpErr.message.includes("not found"))) {
        await updUser(uid, { topic_id: null }, env);
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 会话已过期，请重发" });
      }
    }
  }

  if (relaySuccess) {
    const dk = `delivered:${uid}:${msg.message_id}`;
    if (!CACHE.locks.has(dk)) {
      CACHE.locks.add(dk);
      setTimeout(() => CACHE.locks.delete(dk), 20000);
      markDelivered(env, uid, msg.message_id);
    }

    if (msg.text) {
      try {
        await sql(env, "INSERT OR REPLACE INTO messages (user_id, message_id, text, date) VALUES (?,?,?,?)", [
          uid,
          msg.message_id,
          msg.text,
          msg.date
        ]);
      } catch {}
      maybeCleanupMessages(env, ctx);
    }

    await Promise.all([handleInbox(env, msg, u, tid, uMeta), handleBackup(msg, uMeta, env)]);
  }
}

async function markDelivered(env, chatId, messageId) {
  try {
    await api(env.BOT_TOKEN, "setMessageReaction", {
      chat_id: chatId,
      message_id: messageId,
      reaction: [{ type: "emoji", emoji: DELIVERED_REACTION }],
      is_big: false
    });
  } catch {}
}

// --- 12. 资料卡 ---
async function sendInfoCardToTopic(env, u, tgUser, tid, date) {
  const meta = getUMeta(tgUser, u, date || Date.now() / 1000);
  try {
    const card = await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      message_thread_id: tid,
      text: meta.card,
      parse_mode: "HTML",
      reply_markup: getBtns(u.user_id, u.is_blocked)
    });
    await updUser(u.user_id, { user_info: { card_msg_id: card.message_id } }, env);
    api(env.BOT_TOKEN, "pinChatMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: card.message_id, message_thread_id: tid }).catch(() => {});
    return card.message_id;
  } catch {
    return null;
  }
}

// --- 13. 未读通知（聚合话题） ---
async function handleInbox(env, msg, u, tid, uMeta) {
  const lk = `inbox:${u.user_id}`;
  if (CACHE.locks.has(lk)) return;
  CACHE.locks.add(lk);
  setTimeout(() => CACHE.locks.delete(lk), 3000);

  let inboxId = await getCfg("unread_topic_id", env);
  if (!inboxId) {
    try {
      const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: "🔔 未读消息" });
      inboxId = t.message_thread_id.toString();
      await setCfg("unread_topic_id", inboxId, env);
    } catch {
      return;
    }
  }

  const gid = env.ADMIN_GROUP_ID.toString().replace(/^-100/, "");
  const preview = msg.text ? (msg.text.length > 20 ? msg.text.substring(0, 20) + "..." : msg.text) : "[媒体消息]";
  const cardText = `<b>🔔 新消息</b>\n${uMeta.card}\n📝 <b>预览:</b> ${escapeHTML(preview)}`;
  const kb = {
    inline_keyboard: [[{ text: "🚀 直达回复", url: `https://t.me/c/${gid}/${tid}` }, { text: "✅ 已阅", callback_data: `inbox:del:${u.user_id}` }]]
  };

  try {
    if (u.user_info.inbox_msg_id) {
      try {
        await api(env.BOT_TOKEN, "editMessageText", {
          chat_id: env.ADMIN_GROUP_ID,
          message_id: u.user_info.inbox_msg_id,
          message_thread_id: inboxId,
          text: cardText,
          parse_mode: "HTML",
          reply_markup: kb
        });
        await updUser(u.user_id, { user_info: { last_notify: Date.now() } }, env);
        return;
      } catch {}
    }

    const nm = await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      message_thread_id: inboxId,
      text: cardText,
      parse_mode: "HTML",
      reply_markup: kb
    });
    await updUser(u.user_id, { user_info: { last_notify: Date.now(), inbox_msg_id: nm.message_id } }, env);
  } catch (e) {
    if (e.message && e.message.includes("thread")) await setCfg("unread_topic_id", "", env);
  }
}

// --- 14. 黑名单/备份 ---
async function manageBlacklist(env, u, tgUser, isBlocking) {
  let bid = await getCfg("blocked_topic_id", env);
  if (!bid && isBlocking) {
    try {
      const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: "🚫 黑名单" });
      bid = t.message_thread_id.toString();
      await setCfg("blocked_topic_id", bid, env);
    } catch {
      return;
    }
  }
  if (!bid) return;

  if (isBlocking) {
    const meta = getUMeta(tgUser, u, Date.now() / 1000);
    const m = await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      message_thread_id: bid,
      text: `<b>🚫 用户已屏蔽</b>\n${meta.card}`,
      parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: "✅ 解除屏蔽", callback_data: `unblock:${u.user_id}` }]] }
    }).catch(() => {});
    if (m) await updUser(u.user_id, { user_info: { blacklist_msg_id: m.message_id } }, env);
  } else {
    if (u.user_info.blacklist_msg_id) {
      api(env.BOT_TOKEN, "deleteMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: u.user_info.blacklist_msg_id }).catch(() => {});
      await updUser(u.user_id, { user_info: { blacklist_msg_id: null } }, env);
    }
  }
}

async function handleBackup(msg, meta, env) {
  const bid = await getCfg("backup_group_id", env);
  if (!bid) return;
  try {
    await api(env.BOT_TOKEN, "copyMessage", { chat_id: bid, from_chat_id: msg.chat.id, message_id: msg.message_id });
  } catch {
    if (msg.text) api(env.BOT_TOKEN, "sendMessage", { chat_id: bid, text: `<b>备份</b> ${escapeHTML(meta.name)}:\n${escapeHTML(msg.text)}`, parse_mode: "HTML" }).catch(() => {});
  }
}

// --- 15. Web 验证页（Mini App） ---
async function handleVerifyPage(url, env) {
  const uid = url.searchParams.get("user_id");
  const nonce = url.searchParams.get("nonce") || "";
  const mode = await getCfg("captcha_mode", env);
  const siteKey = mode === "recaptcha" ? env.RECAPTCHA_SITE_KEY : env.TURNSTILE_SITE_KEY;
  if (!uid || !siteKey) return new Response("Misconfigured", { status: 400 });

  const script = mode === "recaptcha" ? "https://www.google.com/recaptcha/api.js" : "https://challenges.cloudflare.com/turnstile/v0/api.js";
  const divClass = mode === "recaptcha" ? "g-recaptcha" : "cf-turnstile";

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<script src="${script}" async defer></script>
<style>body{display:flex;justify-content:center;align-items:center;height:100vh;background:#fff;font-family:sans-serif}
#c{text-align:center;padding:20px;background:#f0f0f0;border-radius:10px;max-width:92vw}
</style></head><body><div id="c"><h3>🛡️ 安全验证</h3>
<div class="${divClass}" data-sitekey="${siteKey}" data-callback="S"></div><div id="m"></div></div>
<script>
const tg=window.Telegram.WebApp;tg.ready();
const UI_USER_ID='${escapeHTML(uid)}';
const UI_NONCE='${escapeHTML(nonce)}';
function S(t){
  document.getElementById('m').innerText='Wait...';
  const initData = tg.initData || "";
  fetch('/submit_token',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({token:t,userId:UI_USER_ID,nonce:UI_NONCE,initData})
  }).then(r=>r.json()).then(d=>{
    if(d.success){
      document.getElementById('m').innerText='✅';
      setTimeout(()=>{tg.close();try{window.close()}catch(e){}},800);
    }else{
      document.getElementById('m').innerText='❌';
    }
  }).catch(e=>{document.getElementById('m').innerText='Error'});
}
</script></body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleTokenSubmit(req, env, ctx) {
  try {
    const body = await req.json();
    const token = body?.token;
    const uiUserId = (body?.userId || "").toString();
    const nonce = (body?.nonce || "").toString();
    const initData = (body?.initData || "").toString();
    const mode = await getCfg("captcha_mode", env);

    // 先做 IP 级限流
    const rlPre = await checkSubmitRateLimit(req, env, ctx, "");
    if (!rlPre.allowed) throw new Error("Rate limited");

    // 必须 initData 且验签成功
    if (!initData || initData.length < 20) throw new Error("Missing initData");
    const parsed = await verifyTelegramInitData(initData, env.BOT_TOKEN, 600);
    const uid = parsed?.userId?.toString();
    if (!uid) throw new Error("Missing uid");

    // uid 级限流
    const rlUid = await checkSubmitRateLimit(req, env, ctx, uid);
    if (!rlUid.allowed) throw new Error("Rate limited");

    if (uiUserId && uiUserId !== uid) throw new Error("uid mismatch");

    const u = await getUser(uid, env);

    // 屏蔽用户不允许验证推进
    if (u.is_blocked && !(await isAuthAdmin(uid, env))) throw new Error("blocked");

    const savedNonce = (u.user_info?.verify_nonce || "").toString();
    const savedTs = Number(u.user_info?.verify_nonce_ts || 0);
    const now = Date.now();
    const expired = !savedTs || now - savedTs > VERIFY_NONCE_TTL_MS;

    if (u.user_state === "verified") {
      return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
    }

    const vOn = await getBool("enable_verify", env);
    if (vOn) {
      if (!nonce || !savedNonce || expired || nonce !== savedNonce) throw new Error("nonce invalid");
      await updUser(uid, { user_info: { verify_nonce: "", verify_nonce_ts: 0 } }, env);
    }

    const verifyUrl =
      mode === "recaptcha"
        ? "https://www.google.com/recaptcha/api/siteverify"
        : "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    const params =
      mode === "recaptcha"
        ? new URLSearchParams({ secret: env.RECAPTCHA_SECRET_KEY, response: token })
        : JSON.stringify({ secret: env.TURNSTILE_SECRET_KEY, response: token });

    const headers =
      mode === "recaptcha"
        ? { "Content-Type": "application/x-www-form-urlencoded" }
        : { "Content-Type": "application/json" };

    const r = await fetch(verifyUrl, { method: "POST", headers, body: params });
    const d = await r.json();
    if (!d.success) throw new Error("Token Invalid");

    try {
      if (parsed?.userObj) {
        const nm = ((parsed.userObj.first_name || "") + " " + (parsed.userObj.last_name || "")).trim() || (parsed.userObj.first_name || "");
        const patch = {};
        if (nm) patch.name = nm;
        if (parsed.userObj.username) patch.username = parsed.userObj.username.toString();
        if (parsed.authDate) patch.join_date = parsed.authDate;
        if (Object.keys(patch).length) await updUser(uid, { user_info: patch }, env);
      }
    } catch {}

    const qaOn = await getBool("enable_qa_verify", env);
    if (qaOn) {
      await updUser(uid, { user_state: "pending_verification" }, env);
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 验证通过！\n请继续回答：\n" + (await getCfg("verif_q", env)) });
    } else {
      await updUser(uid, { user_state: "verified" }, env);
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 验证通过！\n请直接发送消息以联系管理员。" });
    }

    return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
  } catch {
    return new Response(JSON.stringify({ success: false }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
}

// QA 验证
async function verifyAnswer(id, ans, env) {
  if (ans.trim() === (await getCfg("verif_a", env)).trim()) {
    await updUser(id, { user_state: "verified" }, env);
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "✅ 验证通过！\n请直接发送消息以联系管理员。" });
  } else {
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 错误" });
  }
}

// --- 16. initData 验签 ---
async function verifyTelegramInitData(initData, botToken, maxAgeSec) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash") || "";
  if (!hash) throw new Error("missing hash");

  const authDateStr = params.get("auth_date") || "";
  const authDate = parseInt(authDateStr, 10);
  if (!authDate || !Number.isFinite(authDate)) throw new Error("missing auth_date");

  const nowSec = Math.floor(Date.now() / 1000);
  if (maxAgeSec && nowSec - authDate > maxAgeSec) throw new Error("expired");

  const pairs = [];
  for (const [k, v] of params.entries()) {
    if (k === "hash") continue;
    pairs.push([k, v]);
  }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join("\n");

  const secretKey = await hmacSha256Bytes(strToBytes("WebAppData"), strToBytes(botToken));
  const calc = await hmacSha256Bytes(secretKey, strToBytes(dataCheckString));
  const calcHex = bytesToHex(calc);

  if (!timingSafeEqualHex(calcHex, hash)) throw new Error("hash mismatch");

  const userJson = params.get("user");
  let userId = "";
  let userObj = null;
  try {
    if (userJson) {
      userObj = JSON.parse(userJson);
      if (userObj && (userObj.id || userObj.id === 0)) userId = userObj.id.toString();
    }
  } catch {}

  return { userId, authDate, userObj };
}

function strToBytes(s) {
  return new TextEncoder().encode(s);
}
async function hmacSha256Bytes(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}
function bytesToHex(u8) {
  let out = "";
  for (const b of u8) out += b.toString(16).padStart(2, "0");
  return out;
}
function timingSafeEqualHex(a, b) {
  const aa = (a || "").toLowerCase();
  const bb = (b || "").toLowerCase();
  if (aa.length !== bb.length) return false;
  let r = 0;
  for (let i = 0; i < aa.length; i++) r |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return r === 0;
}
function timingSafeEqualStr(a, b) {
  const aa = (a || "").toString();
  const bb = (b || "").toString();
  if (aa.length !== bb.length) return false;
  let r = 0;
  for (let i = 0; i < aa.length; i++) r |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return r === 0;
}

// --- 17. 辅助函数 ---
const getBool = async (k, e) => (await getCfg(k, e)) === "true";
const getJsonCfg = async (k, e) => safeParse(await getCfg(k, e), []);

function escapeHTML(t) {
  return (t || "")
    .toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeRegexTest(pattern, text) {
  try {
    if (!pattern || typeof pattern !== "string") return false;
    const p = pattern.trim();
    if (!p || p.length > REGEX_MAX_PATTERN_LEN) return false;

    for (const re of REGEX_REJECT_PATTERNS) {
      if (re.test(p)) return false;
    }

    const t = (text || "").toString();
    const t2 = t.length > REGEX_MAX_TEXT_LEN ? t.slice(0, REGEX_MAX_TEXT_LEN) : t;

    return new RegExp(p, "gi").test(t2);
  } catch {
    return false;
  }
}

function genNonce(len = 24) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let s = "";
  for (const b of bytes) s += (b % 36).toString(36);
  return s;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

const getUMeta = (tgUser, dbUser, d) => {
  const id = tgUser.id.toString();
  const name = (((tgUser.first_name || "") + " " + (tgUser.last_name || "")).trim() || tgUser.first_name || "User");
  const timeStr = new Date(d * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });
  const note = dbUser.user_info?.note ? `\n📝 <b>备注:</b> ${escapeHTML(dbUser.user_info.note)}` : "";
  return {
    userId: id,
    name,
    topicName: `${name} | ${id}`.substring(0, 128),
    card: `<b>🪪 用户资料</b>\n👤: <code>${escapeHTML(name)}</code>\n🆔: <code>${escapeHTML(id)}</code>${note}\n🕒: <code>${escapeHTML(timeStr)}</code>`
  };
};

const getBtns = (id, blk) => ({
  inline_keyboard: [
    [{ text: "👤 主页", url: `tg://user?id=${id}` }],
    [{ text: blk ? "✅ 解封" : "🚫 屏蔽", callback_data: `${blk ? "unblock" : "block"}:${id}` }],
    [{ text: "✏️ 备注", callback_data: `note:set:${id}` }, { text: "📌 置顶", callback_data: `pin_card:${id}` }]
  ]
});

// --- 18. Commands ---
async function registerCommands(env) {
  try {
    await api(env.BOT_TOKEN, "deleteMyCommands", { scope: { type: "default" } });
    await api(env.BOT_TOKEN, "setMyCommands", { commands: [{ command: "start", description: "开始 / Start" }], scope: { type: "default" } });

    const admins = [...(env.ADMIN_IDS || "").split(/[,，]/), ...(await getJsonCfg("authorized_admins", env))];
    const uniqueAdmins = [...new Set(admins.map(i => i.toString().trim()).filter(Boolean))];

    for (const id of uniqueAdmins) {
      await api(env.BOT_TOKEN, "setMyCommands", {
        commands: [{ command: "start", description: "面板" }, { command: "help", description: "帮助" }, { command: "reset", description: "重置用户验证(主管理员)" }, { command: "del", description: "删访客那份(话题里回复消息使用)" }],
        scope: { type: "chat", chat_id: id }
      });
    }

    // 管理群话题里只保留 /del（清掉旧 bot 残留的群指令）
    try {
      await api(env.BOT_TOKEN, "setMyCommands", {
        commands: [{ command: "del", description: "删访客那份(回复消息使用)" }],
        scope: { type: "chat", chat_id: Number(env.ADMIN_GROUP_ID) }
      });
    } catch {}
  } catch {}
}

// --- 19. 回调处理（黑名单/备注/置顶/未读已阅） ---
async function handleCallback(cb, env) {
  const { data, message: msg, from } = cb;
  const [act, p1, p2] = (data || "").split(":");

  if (act === "inbox" && p1 === "del") {
    await api(env.BOT_TOKEN, "deleteMessage", { chat_id: msg.chat.id, message_id: msg.message_id }).catch(() => {});
    if (p2) {
      const u = await getUser(p2, env);
      await updUser(p2, { user_info: { ...u.user_info, last_notify: 0 } }, env);
    }
    return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "已处理" }).catch(() => {});
  }

  if (act === "note" && p1 === "set") {
    await setCfg(`admin_state:${from.id}`, JSON.stringify({ action: "input_note", target: p2 }), env);
    return api(env.BOT_TOKEN, "sendMessage", {
      chat_id: msg.chat.id,
      message_thread_id: msg.message_thread_id,
      text: "⌨️ 请回复备注内容 (回复 /clear 清除):"
    });
  }

  if (act === "config") {
    if (!(await isPrimaryAdmin(from.id, env))) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});
    }
    await api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id }).catch(() => {});
    const [, t, k, v] = (data || "").split(":");
    return handleAdminConfig(msg.chat.id, msg.message_id, t, k, v, env);
  }

  if (msg.chat.id.toString() === env.ADMIN_GROUP_ID && ["block", "unblock"].includes(act)) {
    if (!(await isAuthAdmin(from.id, env))) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});
    }
    const isB = act === "block";
    const uid = p1;
    const u = await getUser(uid, env);
    await updUser(uid, { is_blocked: isB, block_count: 0 }, env);

    if (u.user_info.card_msg_id) {
      api(env.BOT_TOKEN, "editMessageReplyMarkup", {
        chat_id: env.ADMIN_GROUP_ID,
        message_id: u.user_info.card_msg_id,
        reply_markup: getBtns(uid, isB)
      }).catch(() => {});
    }
    await manageBlacklist(env, u, { id: uid, first_name: u.user_info.name || "User", username: u.user_info.username }, isB);
    api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: isB ? "已屏蔽" : "已解封" }).catch(() => {});
  }

  // 被屏蔽用户在私聊里点"申请解封"
  if (act === "appeal") {
    const uid = p1;
    if (from.id.toString() !== uid) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});
    }
    const au = await getUser(uid, env);
    if (!au.is_blocked) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "您当前未被屏蔽", show_alert: true }).catch(() => {});
    }
    const nowA = Date.now();
    const lastA = Number((au.user_info && au.user_info.last_appeal_ts) || 0);
    if (nowA - lastA < 3600000) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "申请已提交，请耐心等待管理员处理", show_alert: true }).catch(() => {});
    }
    await updUser(uid, { user_info: { last_appeal_ts: nowA } }, env);
    const nm = (au.user_info && au.user_info.name) || "User";
    if (au.topic_id) {
      await api(env.BOT_TOKEN, "sendMessage", {
        chat_id: env.ADMIN_GROUP_ID,
        message_thread_id: Number(au.topic_id),
        text: `📝 <b>解封申请</b>\n👤 <code>${escapeHTML(nm)}</code> ( <code>${uid}</code> ) 申请解除屏蔽`,
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "✅ 同意解封", callback_data: `appeal_ok:${uid}` }, { text: "❌ 拒绝", callback_data: `appeal_no:${uid}` }]] }
      }).catch(() => {});
    }
    return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "已提交解封申请，请等待管理员处理" }).catch(() => {});
  }

  // 管理员在话题里处理解封申请
  if ((act === "appeal_ok" || act === "appeal_no") && msg.chat.id.toString() === env.ADMIN_GROUP_ID) {
    if (!(await isAuthAdmin(from.id, env))) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});
    }
    const uid = p1;
    const ok = act === "appeal_ok";
    if (ok) {
      await updUser(uid, { is_blocked: false, block_count: 0 }, env);
      const au2 = await getUser(uid, env);
      if (au2.user_info.card_msg_id) {
        api(env.BOT_TOKEN, "editMessageReplyMarkup", {
          chat_id: env.ADMIN_GROUP_ID,
          message_id: au2.user_info.card_msg_id,
          reply_markup: getBtns(uid, false)
        }).catch(() => {});
      }
      await manageBlacklist(env, au2, { id: uid, first_name: (au2.user_info && au2.user_info.name) || "User", username: au2.user_info.username }, false);
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 管理员已解除对您的屏蔽，现在可以正常发送消息了。" }).catch(() => {});
    } else {
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "❌ 您的解封申请未通过。" }).catch(() => {});
    }
    api(env.BOT_TOKEN, "editMessageReplyMarkup", {
      chat_id: msg.chat.id, message_id: msg.message_id,
      reply_markup: { inline_keyboard: [] }
    }).catch(() => {});
    return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: ok ? "已解封" : "已拒绝" }).catch(() => {});
  }

  if (act === "pin_card") {
    if (!(await isAuthAdmin(from.id, env))) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});
    }
    api(env.BOT_TOKEN, "pinChatMessage", { chat_id: msg.chat.id, message_id: msg.message_id, message_thread_id: msg.message_thread_id }).catch(() => {});
    api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "已置顶" }).catch(() => {});
  }
}

// --- 20. 管理员回复（无文字回执） ---
async function handleAdminReply(msg, env) {
  if (!msg.message_thread_id || msg.from.is_bot || !(await isAuthAdmin(msg.from.id, env))) return;

  // /del：回复话题里的某条消息，删除访客私聊里对应的那份
  const dtext = (msg.text || "").trim();
  if (dtext === "/del" || dtext.startsWith("/del ")) {
    const repMid = msg.reply_to_message && msg.reply_to_message.message_id
      ? msg.reply_to_message.message_id.toString() : null;
    if (!repMid) {
      return api(env.BOT_TOKEN, "sendMessage", {
        chat_id: msg.chat.id, message_thread_id: msg.message_thread_id,
        text: "请先回复要删除的那条消息，再发送 /del"
      });
    }
    const uid2 = (await sql(env, "SELECT user_id FROM users WHERE topic_id = ?", msg.message_thread_id.toString(), "first"))?.user_id;
    let done = false;
    if (uid2) {
      const row = await sql(env, "SELECT user_msg_id FROM fwd_map WHERE user_id = ? AND admin_msg_id = ?",
        [uid2, repMid], "first");
      if (row && row.user_msg_id) {
        try {
          await api(env.BOT_TOKEN, "deleteMessage", { chat_id: uid2, message_id: row.user_msg_id });
          done = true;
        } catch {}
      }
    }
    // 把 /del 指令本身也删掉，保持话题干净
    try { await api(env.BOT_TOKEN, "deleteMessage", { chat_id: msg.chat.id, message_id: msg.message_id }); } catch {}
    if (!done) {
      await api(env.BOT_TOKEN, "sendMessage", {
        chat_id: msg.chat.id, message_thread_id: msg.message_thread_id,
        text: "❌ 找不到访客那份消息（只能删除本次更新后转发的消息）"
      });
    }
    return;
  }

  const stateStr = await getCfg(`admin_state:${msg.from.id}`, env);
  if (stateStr) {
    const state = safeParse(stateStr);
    if (state.action === "input_note") {
      const u = await getUser(state.target, env);
      u.user_info.note = msg.text === "/clear" || msg.text === "清除" ? "" : msg.text;
      await updUser(state.target, { user_info: u.user_info }, env);
      await setCfg(`admin_state:${msg.from.id}`, "", env);

      if (u.topic_id && u.user_info.card_msg_id) {
        const meta = getUMeta(
          { id: state.target, first_name: u.user_info.name, username: u.user_info.username },
          u,
          u.user_info.join_date || Date.now() / 1000
        );
        api(env.BOT_TOKEN, "editMessageText", {
          chat_id: env.ADMIN_GROUP_ID,
          message_id: u.user_info.card_msg_id,
          text: meta.card,
          parse_mode: "HTML",
          reply_markup: getBtns(state.target, u.is_blocked)
        }).catch(() => {});
      }
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: msg.chat.id, message_thread_id: msg.message_thread_id, text: "✅ 备注已更新" });
    }
  }

  const uid = (await sql(env, "SELECT user_id FROM users WHERE topic_id = ?", msg.message_thread_id.toString(), "first"))?.user_id;
  if (!uid) return;

  try {
    const sent = await api(env.BOT_TOKEN, "copyMessage", { chat_id: uid, from_chat_id: msg.chat.id, message_id: msg.message_id });
    // 记录 管理员消息 -> 访客消息 映射，供编辑时原地修改
    if (sent && sent.message_id) {
      try {
        await sql(env, "INSERT OR REPLACE INTO fwd_map (user_id, admin_msg_id, user_msg_id) VALUES (?,?,?)",
          [uid, msg.message_id.toString(), sent.message_id]);
      } catch {}
    }
  } catch {
    api(env.BOT_TOKEN, "sendMessage", { chat_id: msg.chat.id, message_thread_id: msg.message_thread_id, text: "❌ 发送失败 (用户可能已停止Bot)" }).catch(() => {});
  }
}

// --- 21b. 管理员在话题里编辑消息：原地改访客那份，不重发 ---
async function handleAdminEdit(msg, env) {
  if (!msg.message_thread_id || msg.from.is_bot || !(await isAuthAdmin(msg.from.id, env))) return;
  const uid = (await sql(env, "SELECT user_id FROM users WHERE topic_id = ?", msg.message_thread_id.toString(), "first"))?.user_id;
  if (!uid) return;
  const row = await sql(env, "SELECT user_msg_id FROM fwd_map WHERE user_id = ? AND admin_msg_id = ?",
    [uid, msg.message_id.toString()], "first");
  if (!row || !row.user_msg_id) return; // 此次更新前转发的老消息：无映射则不重发（与旧版一致）
  try {
    if (msg.text !== undefined) {
      await api(env.BOT_TOKEN, "editMessageText", { chat_id: uid, message_id: row.user_msg_id, text: msg.text });
    } else if (msg.caption !== undefined) {
      await api(env.BOT_TOKEN, "editMessageCaption", { chat_id: uid, message_id: row.user_msg_id, caption: msg.caption || "" });
    }
  } catch {}
}

// --- 21. 编辑消息提示 ---
async function handleEdit(msg, env) {
  const u = await getUser(msg.from.id.toString(), env);
  if (u.topic_id) {
    const txt = msg.text || msg.caption || "[非文本]";
    api(env.BOT_TOKEN, "sendMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      message_thread_id: u.topic_id,
      text: `✏️ <b>用户修改了消息:</b>\n${escapeHTML(txt)}`,
      parse_mode: "HTML"
    }).catch(() => {});
  }
}

// --- 22. 面板（移除回执功能项） ---
async function handleAdminConfig(cid, mid, type, key, val, env) {
  const render = (txt, kb) =>
    api(env.BOT_TOKEN, mid ? "editMessageText" : "sendMessage", {
      chat_id: cid,
      message_id: mid,
      text: txt,
      parse_mode: "HTML",
      reply_markup: kb
    });
  const back = { text: "🔙 返回", callback_data: "config:menu" };

  try {
    if (!type || type === "menu") {
      if (!key)
        return render("⚙️ <b>控制面板</b>", {
          inline_keyboard: [
            [{ text: "📝 基础", callback_data: "config:menu:base" }, { text: "🤖 自动回复", callback_data: "config:menu:ar" }],
            [{ text: "🚫 屏蔽词", callback_data: "config:menu:kw" }, { text: "🛠 过滤", callback_data: "config:menu:fl" }],
            [{ text: "👮 协管", callback_data: "config:menu:auth" }, { text: "💾 备份/通知", callback_data: "config:menu:bak" }],
            [{ text: "🌙 营业状态", callback_data: "config:menu:busy" }]
          ]
        });

      if (key === "base") {
        const mode = await getCfg("captcha_mode", env);
        const captchaOn = await getBool("enable_verify", env);
        const qaOn = await getBool("enable_qa_verify", env);
        let statusText = "❌ 已关闭";
        if (captchaOn) statusText = mode === "recaptcha" ? "Google" : "Cloudflare";

        return render(`基础配置\n验证码模式: ${statusText}\n问题验证: ${qaOn ? "✅" : "❌"}`, {
          inline_keyboard: [
            [{ text: "欢迎语", callback_data: "config:edit:welcome_msg" }, { text: "问题", callback_data: "config:edit:verif_q" }, { text: "答案", callback_data: "config:edit:verif_a" }],
            [{ text: `验证码模式: ${statusText} (点击切换)`, callback_data: `config:rotate_mode` }],
            [{ text: `问题验证: ${qaOn ? "✅ 开启" : "❌ 关闭"}`, callback_data: `config:toggle:enable_qa_verify:${!qaOn}` }],
            [back]
          ]
        });
      }

      if (key === "fl") return render("🛠 <b>过滤设置</b> (点击切换)", await getFilterKB(env));
      if (["ar", "kw", "auth"].includes(key)) return render(`列表: ${key}`, await getListKB(key, env));

      if (key === "bak") {
        const bid = await getCfg("backup_group_id", env),
          uid = await getCfg("unread_topic_id", env),
          blk = await getCfg("blocked_topic_id", env);
        return render(`💾 <b>备份与通知</b>\n备份群: ${bid || "无"}\n未读话题: ${uid ? `✅ (${uid})` : "⏳"}\n黑名单话题: ${blk ? `✅ (${blk})` : "⏳"}`, {
          inline_keyboard: [
            [{ text: "设备份群", callback_data: "config:edit:backup_group_id" }, { text: "清备份", callback_data: "config:cl:backup_group_id" }],
            [{ text: "重置聚合话题", callback_data: "config:cl:unread_topic_id" }, { text: "重置黑名单", callback_data: "config:cl:blocked_topic_id" }],
            [back]
          ]
        });
      }

      if (key === "busy") {
        const on = await getBool("busy_mode", env),
          msgText = await getCfg("busy_msg", env);
        return render(`🌙 <b>营业状态</b>\n当前: ${on ? "🔴 休息中" : "🟢 营业中"}\n回复语: ${escapeHTML(msgText)}`, {
          inline_keyboard: [
            [{ text: `切换为 ${on ? "🟢 营业" : "🔴 休息"}`, callback_data: `config:toggle:busy_mode:${!on}` }],
            [{ text: "✏️ 修改回复语", callback_data: "config:edit:busy_msg" }],
            [back]
          ]
        });
      }
    }

    if (type === "toggle") {
      await setCfg(key, val, env);
      return key === "busy_mode"
        ? handleAdminConfig(cid, mid, "menu", "busy", null, env)
        : key === "enable_qa_verify"
          ? handleAdminConfig(cid, mid, "menu", "base", null, env)
          : render("🛠 <b>过滤设置</b>", await getFilterKB(env));
    }

    if (type === "cl") {
      await setCfg(key, key === "authorized_admins" ? "[]" : "", env);
      return handleAdminConfig(
        cid,
        mid,
        "menu",
        key === "unread_topic_id" || key === "blocked_topic_id" ? "bak" : key === "authorized_admins" ? "auth" : "bak",
        null,
        env
      );
    }

    if (type === "del") {
      const realK = key === "kw" ? "block_keywords" : key === "auth" ? "authorized_admins" : "keyword_responses";
      let l = await getJsonCfg(realK, env);
      l = (Array.isArray(l) ? l : []).filter(i => (i.id || i).toString() !== val);
      await setCfg(realK, JSON.stringify(l), env);
      return render(`列表: ${key}`, await getListKB(key, env));
    }

    if (type === "edit" || type === "add") {
      await setCfg(`admin_state:${cid}`, JSON.stringify({ action: "input", key: key + (type === "add" ? "_add" : "") }), env);

      let promptText = `请输入 ${key} 的值 (/cancel 取消):`;
      if (key === "ar" && type === "add") promptText = `请输入自动回复规则，格式：\n<b>关键词===回复内容</b>\n\n例如：价格===请联系人工客服\n(/cancel 取消)`;
      if (key === "welcome_msg") promptText = `请发送新的欢迎语 (/cancel 取消):\n\n• 支持 <b>文字</b> 或 <b>图片/视频/GIF</b>\n• 支持占位符: {name}\n• 直接发送媒体即可`;
      return api(env.BOT_TOKEN, "editMessageText", { chat_id: cid, message_id: mid, text: promptText, parse_mode: "HTML" });
    }

    if (type === "rotate_mode") {
      const currentMode = await getCfg("captcha_mode", env);
      const isEnabled = await getBool("enable_verify", env);
      let nextMode = "turnstile",
        nextEnable = "true",
        toast = "已切换: Cloudflare";
      if (isEnabled) {
        if (currentMode === "turnstile") {
          nextMode = "recaptcha";
          toast = "已切换: Google";
        } else {
          nextEnable = "false";
          nextMode = currentMode;
          toast = "验证已关闭";
        }
      }
      await setCfg("captcha_mode", nextMode, env);
      await setCfg("enable_verify", nextEnable, env);
      return render(`基础配置已更新\n${toast}`, { inline_keyboard: [[back]] });
    }
  } catch (e) {
    console.error("handleAdminConfig error:", e);
  }
}

async function getFilterKB(env) {
  const s = async k => ((await getBool(k, env)) ? "✅" : "❌");
  const b = (t, k, v) => ({ text: `${t} ${v}`, callback_data: `config:toggle:${k}:${v === "❌"}` });

  const keys = [
    "enable_forward_forwarding",
    "enable_image_forwarding",
    "enable_audio_forwarding",
    "enable_sticker_forwarding",
    "enable_link_forwarding",
    "enable_channel_forwarding",
    "enable_text_forwarding"
  ];
  const vals = await Promise.all(keys.map(k => s(k)));

  return {
    inline_keyboard: [
      [b("转发", keys[0], vals[0])],
      [b("媒体", keys[1], vals[1]), b("语音", keys[2], vals[2])],
      [b("贴纸", keys[3], vals[3]), b("链接", keys[4], vals[4])],
      [b("频道", keys[5], vals[5]), b("文本", keys[6], vals[6])],
      [{ text: "🔙 返回", callback_data: "config:menu" }]
    ]
  };
}

async function getListKB(type, env) {
  const k = type === "ar" ? "keyword_responses" : type === "kw" ? "block_keywords" : "authorized_admins";
  const l = await getJsonCfg(k, env);
  const btns = (Array.isArray(l) ? l : []).map(i => [{ text: `🗑 ${type === "ar" ? i.keywords : i}`, callback_data: `config:del:${type}:${i.id || i}` }]);
  btns.push([{ text: "➕ 添加", callback_data: `config:add:${type}` }], [{ text: "🔙 返回", callback_data: "config:menu" }]);
  return { inline_keyboard: btns };
}

async function handleAdminInput(id, msg, state, env) {
  const txt = msg.text || "";
  if (txt === "/cancel") {
    await sql(env, "DELETE FROM config WHERE key=?", `admin_state:${id}`);
    return handleAdminConfig(id, null, "menu", null, null, env);
  }

  let k = state.key,
    val = txt;
  try {
    if (k === "welcome_msg") {
      if (msg.photo || msg.video || msg.animation) {
        let fileId, type;
        if (msg.photo) {
          type = "photo";
          fileId = msg.photo[msg.photo.length - 1].file_id;
        } else if (msg.video) {
          type = "video";
          fileId = msg.video.file_id;
        } else if (msg.animation) {
          type = "animation";
          fileId = msg.animation.file_id;
        }
        val = JSON.stringify({ type: type, file_id: fileId, caption: msg.caption || "" });
      } else {
        val = txt;
      }
    } else if (k.endsWith("_add")) {
      k = k.replace("_add", "");
      const realK = k === "ar" ? "keyword_responses" : k === "kw" ? "block_keywords" : "authorized_admins";
      const list = await getJsonCfg(realK, env);
      const arr = Array.isArray(list) ? list : [];
      if (k === "ar") {
        const [kk, rr] = txt.split("===");
        if (kk && rr) arr.push({ keywords: kk, response: rr, id: Date.now() });
        else return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 格式错误，请使用：关键词===回复内容" });
      } else arr.push(txt);
      val = JSON.stringify(arr);
      k = realK;
    } else if (k === "authorized_admins") {
      val = JSON.stringify(txt.split(/[,，]/).map(s => s.trim()).filter(Boolean));
    }

    await setCfg(k, val, env);
    await sql(env, "DELETE FROM config WHERE key=?", `admin_state:${id}`);
    const displayVal = val.startsWith("{") && k === "welcome_msg" ? "[媒体配置]" : val.substring(0, 100);
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `✅ ${k} 已更新:\n${displayVal}` }).catch(() => {});
    await handleAdminConfig(id, null, "menu", null, null, env);
  } catch (e) {
    api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `❌ 失败: ${e.message}` }).catch(() => {});
  }
}
