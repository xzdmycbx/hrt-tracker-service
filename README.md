# HRT Tracker Service

一个专为 HRT（激素替代治疗）追踪设计的安全后端服务。

## 功能特性

- ✅ 用户注册和认证（基于 JWT）
- ✅ 6位安全密码用于数据加密
- ✅ 加密的用户数据存储
- ✅ 数据分享（实时同步或快照副本）
- ✅ 分享密码保护和访问控制
- ✅ 用户授权系统
- ✅ SQLite 数据库
- ✅ RESTful API

## 快速开始

```bash
# 安装依赖
go mod download

# 复制环境配置
cp .env.example .env

# 运行服务器
go run main.go
```

服务器运行在 `http://localhost:8080`

## 文档

- **[部署指南](docs/SETUP.md)** - 安装和配置说明
- **[API 文档](docs/API.md)** - 完整的 API 参考文档

## 技术栈

- **Go 1.21+** - 编程语言
- **Gin** - HTTP Web 框架
- **GORM** - ORM 库
- **SQLite** - 数据库
- **JWT** - 身份认证
- **AES-256-GCM** - 数据加密

## 项目结构

```
├── main.go              # 入口文件
├── config/              # 配置
├── models/              # 数据库模型
├── handlers/            # API 处理器
├── middleware/          # HTTP 中间件
├── utils/               # 工具函数（加密、令牌、响应）
├── database/            # 数据库初始化
└── docs/                # 文档
```

## 许可证

MIT
