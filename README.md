# 听写侠后端

这是听写侠的第一版账号同步后端，使用 Express、SQLite、JWT 和 bcrypt。

## 本地运行

```bash
cd server
cp .env.example .env
npm install
npm run dev
```

启动后访问：

- `GET http://localhost:3000/health`
- 前端账号面板里的后端地址填 `http://localhost:3000`

## Render/Railway 部署

需要配置环境变量：

- `JWT_SECRET`: 一段足够长的随机字符串。
- `DATABASE_PATH`: 默认可用 `./data/dictation.sqlite`。如果平台磁盘会重置，请使用持久化磁盘或改用数据库服务。
- `CORS_ORIGINS`: 允许访问后端的前端地址，例如 `https://jinllin.github.io,http://localhost:3000`。

部署命令：

```bash
npm install
npm start
```

Root directory 选择 `server`。

## API

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/sync`
- `PUT /api/sync`

同步数据是一个完整快照，包含现有本地键：`ds4`、`eb4`、`cu4`、`fv4`、`sho4`、`dk4`、`sm4`、`pet4`。
