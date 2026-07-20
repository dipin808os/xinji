# 心迹 · 部署指南

一个口令制的私密情绪日记。少数熟人各自登录、各自私密，数据互不可见。
单进程 Node（Express + 原生 https 调 Claude），JSON 文件存储，零额外依赖。

---

## 1. 准备用户与口令

```bash
node scripts/gen-users.mjs                 # 生成默认 5 人：admin, user2..user5
# 或自定义名字（第一个是管理员，存量数据会归给他）：
node scripts/gen-users.mjs 我 阿伟 小林 圆圆 大师兄
```

- 口令**只在运行时打印一次**，请立刻复制、私下分发。
- 只存 `salt + sha256` 哈希到 `data/users.json`，不存明文。丢了只能重置。
- 重置 / 新增某人的口令：`node scripts/reset-password.mjs <名字>`
- `data/users.json` 已在 `.gitignore` 中，**绝不要提交**。

## 2. 配置 .env

```bash
cp .env.example .env
```

关键项：
| 变量 | 说明 |
|---|---|
| `ANTHROPIC_API_KEY` | 你的 Claude key（留空则用降级模拟回应） |
| `SESSION_SECRET` | 会话签名密钥。留空会自动生成并存 `data/session-secret` |
| `COOKIE_SECURE` | **HTTPS 部署时必须置 `1`** |
| `AI_RATE_MAX` / `AI_RATE_WINDOW` | 每用户 AI 调用限频，默认 60 秒内 30 次 |

## 3. 跑起来

```bash
npm install
npm start          # 监听 127.0.0.1:5178
```

生产环境建议用 pm2 / systemd 守护：
```bash
pm2 start server.js --name xinji
pm2 save
```

## 4. 套 HTTPS（必做）

传口令和私密日记，**明文 HTTP 等于没设防**。用反向代理终止 TLS，Node 只监听本地。

### Caddy（最省事，自动签证书）
```
xinji.你的域名.com {
    reverse_proxy 127.0.0.1:5178
}
```
配好后 `.env` 里设 `COOKIE_SECURE=1` 再重启。

### Nginx（手动配证书，用 certbot 签）
```nginx
server {
    listen 443 ssl;
    server_name xinji.你的域名.com;
    ssl_certificate     /etc/letsencrypt/live/xinji.你的域名.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/xinji.你的域名.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5178;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
> 服务端已开 `trust proxy`，会从 `X-Forwarded-For` 取真实 IP 做登录限频。

## 5. 安全须知

- 口令强度就是全部防线（无账号锁定），**别用弱口令**，用脚本生成的随机串。
- 登录失败同一 IP 连续 5 次 → 锁 5 分钟，防爆破。
- AI 接口按用户限频，防有人刷爆你的 Claude key。
- 想彻底踢掉所有人（比如疑似口令泄露）：删掉 `data/session-secret` 或改 `SESSION_SECRET` 后重启，所有已发 cookie 立即失效。

## 6. 备份

真正的资产是两个文件，定期备份：
- `data/entries.json` —— 所有人的记录
- `data/users.json` —— 用户与口令哈希

```bash
# 例：每天备份一次
cp data/entries.json backups/entries-$(date +%F).json
```

## 7. 数据说明

- 每条记录带 `owner` 字段，接口层按登录用户过滤，不是前端假隔离。
- 首次启动会把**没有 owner 的存量记录**自动归给管理员，不会暴露给新用户。
- 人变多、或将来要开放注册时，再把 JSON 存储迁到 SQLite（当前规模无需）。
