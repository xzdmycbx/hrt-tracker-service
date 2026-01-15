# HRT Tracker Service - 部署指南

## 环境要求

- Go 1.21 或更高版本
- Git

## 快速开始

### 1. 安装 Go

从 https://golang.org/dl/ 下载并安装 Go

验证安装：
```bash
go version
```

### 2. 克隆并配置

```bash
cd hrt-tracker-service
```

### 3. 配置环境变量

复制示例环境变量文件：
```bash
cp .env.example .env
```

编辑 `.env` 并更新配置（可选，默认值适用于开发环境）：
```env
PORT=8080
DB_PATH=./data/hrt-tracker.db
JWT_ACCESS_SECRET=你的访问令牌密钥-生产环境请修改
JWT_REFRESH_SECRET=你的刷新令牌密钥-生产环境请修改
ACCESS_TOKEN_EXPIRE_HOURS=1
```

**生产环境重要提示：**
- 将 `JWT_ACCESS_SECRET` 和 `JWT_REFRESH_SECRET` 改为安全的随机字符串
- 设置 `GIN_MODE=release`

### 4. 安装依赖

```bash
go mod download
```

### 5. 运行服务器

```bash
go run main.go
```

服务器将在 `http://localhost:8080` 启动

### 6. 验证

测试健康检查接口：
```bash
curl http://localhost:8080/health
```

预期响应：
```json
{"status":"ok"}
```

## 生产环境构建

### 编译二进制文件

```bash
go build -o hrt-tracker-service
```

### 运行二进制文件

Windows：
```bash
hrt-tracker-service.exe
```

Linux/Mac：
```bash
./hrt-tracker-service
```

## 项目结构

```
hrt-tracker-service/
├── main.go              # 应用程序入口
├── go.mod               # Go 模块依赖
├── .env                 # 环境变量配置
├── config/              # 配置加载
│   └── config.go
├── models/              # 数据库模型
│   └── models.go
├── handlers/            # HTTP 请求处理器
│   ├── auth.go          # 认证接口
│   ├── user.go          # 用户管理接口
│   ├── share.go         # 分享管理接口
│   └── authorization.go # 授权接口（已停用）
├── middleware/          # HTTP 中间件
│   └── auth.go          # JWT 认证中间件
├── utils/               # 工具函数
│   ├── crypto.go        # 加密和哈希
│   ├── token.go         # JWT 令牌生成
│   └── response.go      # HTTP 响应辅助函数
├── database/            # 数据库初始化
│   └── database.go
├── data/                # SQLite 数据库（自动创建）
│   └── hrt-tracker.db
└── docs/                # 文档
    ├── API.md           # API 文档
    └── SETUP.md         # 本文件
```

## 环境变量说明

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `PORT` | 服务器端口 | `8080` |
| `GIN_MODE` | Gin 模式 (debug/release) | `release` |
| `DB_PATH` | SQLite 数据库路径 | `./data/hrt-tracker.db` |
| `JWT_ACCESS_SECRET` | 访问令牌密钥 | （必须设置） |
| `JWT_REFRESH_SECRET` | 刷新令牌密钥 | （必须设置） |
| `ACCESS_TOKEN_EXPIRE_HOURS` | 访问令牌过期时间 | `1` |

## 数据库

应用程序使用 SQLite 存储数据。数据库文件将在 `DB_PATH` 指定的路径自动创建。

### 数据库架构

以下表将自动创建：
- `users` - 用户账号
- `user_data` - 用户 JSON 数据（如设置安全密码则加密）
- `refresh_tokens` - 用于认证的刷新令牌
- `shares` - 数据分享（实时和副本）
- `authorizations` - 用户授权（已停用）

### 重置数据库

要重置数据库，只需删除数据库文件：
```bash
rm ./data/hrt-tracker.db
```

数据库将在下次服务器启动时重新创建。

## API 文档

完整的 API 文档请查看 [API.md](./API.md)。

## 开发

### 使用热重载运行

安装 `air` 用于开发时热重载：
```bash
go install github.com/cosmtrek/air@latest
```

创建 `.air.toml`：
```toml
root = "."
tmp_dir = "tmp"

[build]
cmd = "go build -o ./tmp/main ."
bin = "tmp/main"
include_ext = ["go"]
exclude_dir = ["tmp", "vendor", "data"]
```

使用热重载运行：
```bash
air
```

### 运行测试

```bash
go test ./...
```

## 故障排除

### 端口已被占用

如果 8080 端口已被占用，在 `.env` 中修改 `PORT`：
```env
PORT=8081
```

### 数据库锁定

如果遇到"database is locked"错误，请确保只有一个服务器实例在运行。

### 权限被拒绝（Linux/Mac）

使二进制文件可执行：
```bash
chmod +x hrt-tracker-service
```

## 生产环境部署

### 使用 systemd（Linux）

创建 `/etc/systemd/system/hrt-tracker.service`：
```ini
[Unit]
Description=HRT Tracker Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/hrt-tracker-service
ExecStart=/opt/hrt-tracker-service/hrt-tracker-service
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

启用并启动：
```bash
sudo systemctl enable hrt-tracker
sudo systemctl start hrt-tracker
```

### 使用 Docker

创建 `Dockerfile`：
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o hrt-tracker-service

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/hrt-tracker-service .
COPY .env .
EXPOSE 8080
CMD ["./hrt-tracker-service"]
```

构建并运行：
```bash
docker build -t hrt-tracker-service .
docker run -p 8080:8080 -v $(pwd)/data:/app/data hrt-tracker-service
```

## 安全建议

1. **修改默认密钥** - 生产环境中修改 `.env` 中的默认密钥
2. **使用 HTTPS** - 生产环境使用反向代理（nginx/caddy）启用 HTTPS
3. **定期备份** - 定期备份数据库文件
4. **保持更新** - 将 Go 更新到最新稳定版本
5. **设置生产模式** - 生产环境设置 `GIN_MODE=release`

## 技术支持

遇到问题或有疑问，请查看：
- API 文档：[docs/API.md](./API.md)
- 前端仓库：../Oyama-s-HRT-Tracker
