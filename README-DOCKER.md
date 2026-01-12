# Docker 部署指南

## 快速开始

### 1. 环境准备

确保已安装：
- Docker
- Docker Compose

### 2. 配置环境变量

编辑 `.env` 文件，配置必要的环境变量：

```bash
# 服务器配置
PORT=8080
GIN_MODE=release

# 数据库配置
DB_PATH=./data/hrt-tracker.db

# JWT 配置（请修改为强密钥）
JWT_ACCESS_SECRET=your-strong-access-secret-change-in-production
JWT_REFRESH_SECRET=your-strong-refresh-secret-change-in-production
ACCESS_TOKEN_EXPIRE_HOURS=1

# 服务端主密钥（请使用 openssl rand -hex 32 生成）
MASTER_KEY_SERVER_V1=your-256-bit-hex-key-here-64-characters-long
MASTER_KEY_SERVER_CURRENT_VERSION=1
```

### 3. 生成服务端密钥

使用以下命令生成安全的 256-bit 密钥：

```bash
# Linux/macOS
openssl rand -hex 32

# Windows (PowerShell)
-join ((1..32) | ForEach-Object { '{0:X2}' -f (Get-Random -Maximum 256) })
```

将生成的密钥设置到 `.env` 文件的 `MASTER_KEY_SERVER_V1` 字段。

### 4. 启动服务

```bash
# 构建并启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 查看服务状态
docker-compose ps
```

### 5. 停止服务

```bash
# 停止服务
docker-compose down

# 停止服务并删除数据卷（谨慎使用！）
docker-compose down -v
```

## 数据持久化

数据库文件自动持久化到 Docker 卷 `hrt-data`，即使容器删除，数据也不会丢失。

### 查看数据卷

```bash
docker volume ls
docker volume inspect hrt-tracker-service_hrt-data
```

### 备份数据

```bash
# 创建数据卷备份
docker run --rm \
  -v hrt-tracker-service_hrt-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/hrt-data-backup.tar.gz -C /data .
```

### 恢复数据

```bash
# 从备份恢复数据
docker run --rm \
  -v hrt-tracker-service_hrt-data:/data \
  -v $(pwd):/backup \
  alpine sh -c "cd /data && tar xzf /backup/hrt-data-backup.tar.gz"
```

## 健康检查

服务包含健康检查端点：

```bash
curl http://localhost:8080/health
```

预期响应：
```json
{"status":"ok"}
```

Docker Compose 会自动进行健康检查（每30秒一次）。

## 日志管理

### 查看日志

```bash
# 实时查看日志
docker-compose logs -f hrt-tracker-service

# 查看最后100行日志
docker-compose logs --tail=100 hrt-tracker-service
```

### 日志轮转

在生产环境中，建议配置日志驱动：

```yaml
# docker-compose.yml
services:
  hrt-tracker-service:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

## 更新服务

```bash
# 拉取最新代码
git pull

# 重新构建并重启服务
docker-compose up -d --build

# 或者分步执行
docker-compose build
docker-compose up -d
```

## 端口配置

默认端口为 `8080`，可通过 `.env` 文件的 `PORT` 变量修改：

```bash
PORT=3000  # 修改为其他端口
```

然后重启服务：

```bash
docker-compose down
docker-compose up -d
```

## 故障排查

### 1. 容器无法启动

```bash
# 查看详细日志
docker-compose logs hrt-tracker-service

# 检查容器状态
docker-compose ps
```

### 2. 端口被占用

修改 `.env` 文件中的 `PORT` 或 `docker-compose.yml` 中的端口映射。

### 3. 数据库文件权限问题

```bash
# 检查数据卷权限
docker-compose exec hrt-tracker-service ls -la /app/data

# 如有问题，重置权限
docker-compose exec hrt-tracker-service chown -R appuser:appgroup /app/data
```

### 4. 环境变量未生效

确保：
1. `.env` 文件存在于项目根目录
2. `docker-compose.yml` 中配置了 `env_file`
3. 修改 `.env` 后重启容器：`docker-compose restart`

## 生产环境建议

1. **使用强密钥**：
   - 为 JWT 密钥和服务端主密钥生成强随机值
   - 不要使用示例中的默认值

2. **启用 HTTPS**：
   - 使用 Nginx 或 Traefik 作为反向代理
   - 配置 SSL/TLS 证书

3. **限制网络访问**：
   ```yaml
   # docker-compose.yml
   services:
     hrt-tracker-service:
       ports:
         - "127.0.0.1:8080:8080"  # 仅允许本地访问
   ```

4. **定期备份数据**：
   - 设置定时任务备份数据卷
   - 将备份存储到安全位置

5. **监控和告警**：
   - 监控容器健康状态
   - 设置日志告警规则

6. **资源限制**：
   ```yaml
   # docker-compose.yml
   services:
     hrt-tracker-service:
       deploy:
         resources:
           limits:
             cpus: '0.5'
             memory: 512M
           reservations:
             cpus: '0.25'
             memory: 256M
   ```

## API 访问

服务启动后，API 可通过以下地址访问：

```
http://localhost:8080/api
```

健康检查端点：
```
http://localhost:8080/health
```

详细 API 文档请查看 `docs/API.md`。
