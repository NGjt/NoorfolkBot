# 🚀 NoorfolkBot - Telegram 双向机器人

![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)
![Telegram Bot API](https://img.shields.io/badge/Telegram-Bot_API-26A5E4?logo=telegram&logoColor=white)
![D1 Database](https://img.shields.io/badge/D1-Database-F38020?logo=cloudflare&logoColor=white)

> 企业级私聊托管与风控解决方案 —— 基于 Cloudflare Worker + D1 数据库构建的高性能 Telegram 双向机器人，支持多模态验证、可视化协管与智能 CRM 管理。单文件，开箱即用。

## ✨ 项目简介

NoorfolkBot 是一个**单文件** Cloudflare Worker 应用。访客私聊机器人发消息，管理群自动为每人创建一个独立话题；管理员在话题里直接回复，消息自动转回给对应访客。

私聊机器人发送 `/start`（管理员身份）即可打开**可视化管理面板**：验证开关、欢迎语、自动回复、屏蔽词、消息过滤、营业状态、备份、协管，所有配置即时生效，无需重新部署。

## 🔥 版本特性

| 特性 | 说明 |
|---|---|
| 🛡️ 混合验证架构 | 验证码模式面板热切换，支持 Cloudflare Turnstile、Google Recaptcha 及关闭模式，无需重新部署 |
| 🧩 模块化风控 | "人机验证"与"问题验证"逻辑解耦，可双重开启加强防护，或只开问答降低门槛 |
| 👮 可视化协管 | 主管理员可添加多名协管，拥有回复消息、查看面板、管理黑名单权限 |
| ⚡ CRM 增强 | 资料卡备注 + 回复 `/clear` 快速清除，备注全局同步到所有历史卡片 |
| 🧠 智能同步 | 管理员编辑消息访客那份原地修改；`/del` 删除访客那份；数据库自动初始化 |
| 📥 聚合收件箱 | 单人单卡聚合未读消息，阅后即焚，一键直达对应话题 |
| 📝 解封申诉 | 被屏蔽用户可申请解封，管理员在话题里一键同意/拒绝 |

## 🧰 核心功能详解

### 1. 🛡️ 多维安全验证系统

- **三模态一键切换**：在控制面板中随时切换 Cloudflare / Google Recaptcha / 关闭验证模式，无需重新部署
- **独立问答验证**：即使关闭人机验证码，也能单独开启自定义问答，拦截基础脚本攻击
- **组合防御**：支持"验证码 + 问答"双重验证，只有全部通过后用户才能发送消息
- **默认关闭**：开箱即用不打扰，按需开启

### 2. 👮 协管权限系统

- **权限下放**：主管理员可添加多名协管员，拥有回复消息、查看面板、管理黑名单权限
- **可视化管理**：在面板中增删协管，一目了然

### 3. 📨 双向消息中继

- **自动话题**：每个用户的私聊消息自动在管理群创建独立话题（Topic）
- **无感回复**：管理员在话题内直接回复，机器人自动转发给用户
- **编辑同步**：管理员在话题里编辑消息，访客那份**原地修改**，不重发新消息
- **`/del`**：在话题里回复某条消息发送，删除访客私聊里对应的那份

### 4. 🗄️ CRM 客户管理系统

- **智能备注**：管理员点击资料卡 ✏️ 按钮为用户打标签
- **快速清除**：备注模式下回复 `/clear` 可直接删除当前备注
- **全局同步**：修改备注后，该用户所有历史资料卡（话题顶部、通知消息）自动同步更新
- **资料卡追踪**：话题顶部始终置顶最新用户资料卡（含 ID、用户名、注册时间及备注）

### 5. 📥 聚合收件箱

- **防刷屏机制**：无论用户发送多少消息，"🔔 未读消息"话题中每个用户只保留一张最新通知卡片
- **阅后即焚**：点击 ✅ 已阅/删除，卡片即刻消失
- **一键直达**：通知卡片包含跳转按钮，点击直达用户专属聊天话题

### 6. 🚫 黑名单隔离系统

- **双向同步**：手动屏蔽或触发关键词自动封禁后，在"🚫 黑名单"话题生成卡片
- **一键解封**：在用户资料卡或黑名单卡片上点击解封，状态双向同步
- **解封申诉**：被屏蔽用户会收到提示，可点"📝 申请解封"；申请发到其专属话题，管理员一键同意/拒绝（1 小时限申请一次，防骚扰）
- **无自助解封**：被屏蔽后发送 `/start` 不会自动解封，杜绝绕过；管理员身份豁免验证、屏蔽与限流

### 7. 🌙 营业状态管理

- **一键切换**：在面板中切换"营业中"或"休息中"
- **自动回复**：休息模式下用户发消息收到预设忙碌提示（内置防抖机制避免重复打扰）

### 8. 🧰 更多能力

- **关键词自动回复**：如"价格"自动回复一段预设话术
- **屏蔽词**：命中屏蔽词自动封禁
- **消息过滤**：图片、链接、转发消息、频道消息、音频、贴纸分别可禁
- **消息备份**：指定一个备份群，所有往来消息自动抄一份过去
- **`/reset <用户ID>`**：主管理员重置某人的验证状态（重新走验证流程）

## 🛠️ 部署指南（保姆级教程）

### 📋 准备工作

1. **Cloudflare 账号**（免费版够用）：https://dash.cloudflare.com
2. **Telegram Bot Token**（通过 [@BotFather](https://t.me/BotFather) 获取）
3. **Telegram 管理群组 ID**（必须是**开启话题功能**的超级群组，ID 以 `-100` 开头，通过 [@userinfobot](https://t.me/userinfobot) 获取）
4. **管理员 ID**（你自己的 TG 数字 ID，通过 [@userinfobot](https://t.me/userinfobot) 获取）

> 💡 **话题群开启技巧**：将群组的"新成员是否可见消息记录"设置为可见，即可开启话题功能。机器人拉进群后设为管理员。

### 1. 建数据库

Cloudflare 后台 → 左侧 **D1** → **创建数据库**（名字比如叫 `relay-bot-db`）→ 点进去记下 `database_id`。
表结构不用手动建，代码第一次运行时会自动创建。

### 2. 填配置文件

打开 `wrangler.toml`，把这几处换成你的：

- `database_id` → 上一步记下的那串
- `ADMIN_IDS` → 你的数字 ID（多个人用英文逗号隔开）
- `ADMIN_GROUP_ID` → 群 ID
- `WORKER_URL` → 先随便填，部署完拿到真实地址再改回来也行
- `TURNSTILE_SITE_KEY` → 不开人机验证就不用管（用 Google Recaptcha 才需要另配 `RECAPTCHA_SITE_KEY` / `RECAPTCHA_SECRET_KEY`）

### 3. 部署

> 📱 **手机也能部署**：不想用电脑的话，直接看下面的"手机部署（不用终端）"，全程在手机浏览器里点一点就行。

**电脑上**打开终端，一个一个跑：

```bash
npm i -g wrangler
wrangler login
wrangler secret put BOT_TOKEN
# 会让你粘贴 @BotFather 给你的 token，粘贴后回车

wrangler secret put TELEGRAM_WEBHOOK_SECRET
# 让你输入一串密钥：随便打一串字母+数字就行，比如 a1b2c3x9yz，记下来后面要用

wrangler secret put TURNSTILE_SECRET_KEY
# 不开人机验证就随便打一串

wrangler deploy
# 看到 Success 就成功了，会显示你的 worker 地址（https://xxx.workers.dev），记下来
```

### 4. 绑定 webhook

把下面这行里的三处换成你的，直接粘贴到浏览器地址栏打开：

```
https://api.telegram.org/bot<机器人token>/setWebhook?url=<worker地址>/&secret_token=<第3步设的那串密钥>&allowed_updates=["message","edited_message","callback_query"]
```

页面显示 `{"ok":true}` 就是成功了。

### 5. 收尾验证

私聊你的机器人发 `/start`，管理面板弹出来就表示全通了。验证、欢迎语、自动回复这些都在面板里按需开关就行。

### 📱 手机部署（不用终端）

全程在手机浏览器里操作，不用电脑、不用装任何东西：

1. 打开 https://dash.cloudflare.com 登录 → **Workers 和 Pages** → **创建** → **创建 Worker** → 起个名字 → **部署**
2. 点 **编辑代码** → 把本仓库 `worker.js` 的全文复制粘贴进去 → **保存并部署**（右上角）
3. 回到 Cloudflare 首页 → **存储和数据库** → **D1** → **创建数据库**（比如叫 `relay-bot-db`）
4. 回到你的 Worker → **设置** → **绑定** → **添加绑定** → **D1 数据库** → 变量名称填 `TG_BOT_DB` → 选择上一步建的数据库 → 添加
5. **设置** → **变量和机密** → 逐个添加：
   - 文本变量：`ADMIN_IDS`（你的数字 ID）、`ADMIN_GROUP_ID`（群 ID）、`WORKER_URL`（你的 worker 地址）、`TURNSTILE_SITE_KEY`（不用验证可不填）
   - 机密：`BOT_TOKEN`（@BotFather 给的 token）、`TELEGRAM_WEBHOOK_SECRET`（随便打一串字母数字，记下来）、`TURNSTILE_SECRET_KEY`（不用验证随便填）
   - 每加完一个点**保存**（机密加完要点部署或等自动重新部署生效）
6. 在浏览器打开 webhook 链接（同上面第 4 步），显示 `{"ok":true}` 即成功
7. 私聊机器人发 `/start` 验证

## ⚙️ 配置说明

| 变量 | 位置 | 说明 |
|---|---|---|
| `BOT_TOKEN` | secret | 机器人 token（@BotFather 获取） |
| `TELEGRAM_WEBHOOK_SECRET` | secret | webhook 校验密钥，防伪造请求，随便设一串 |
| `TURNSTILE_SECRET_KEY` | secret | Turnstile secret key（不开验证可随便填） |
| `ADMIN_IDS` | 明文变量 | 管理员数字 ID，英文逗号分隔 |
| `ADMIN_GROUP_ID` | 明文变量 | 管理群 ID（`-100` 开头） |
| `WORKER_URL` | 明文变量 | Worker 地址（验证页面用） |
| `TURNSTILE_SITE_KEY` | 明文变量 | Turnstile site key（公开的） |
| `TG_BOT_DB` | D1 绑定 | D1 数据库 |

## 📌 说明

- 访客消息是经机器人**转发**到管理群的独立消息，访客删除自己私聊里的消息不影响话题内存档
- 管理员身份豁免验证、屏蔽与限流（写死在代码里）
- 免费额度下日常用量很低：Workers 每天 10 万次请求，D1 每天读 500 万行 / 写 10 万行
