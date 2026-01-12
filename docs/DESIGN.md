# 新功能设计文档

## 1. 双重密钥包裹的自动更新方案

### 1.1 背景与问题
**当前问题**：
- 用户数据使用安全密码加密后，后台无法自动更新数据
- 只能在用户主动提供密码时才能操作数据
- 这与"查看是自发行为，更新是自动行为"的需求冲突

**解决方案**：采用双重密钥包裹（Key Wrapping）机制

### 1.2 密钥体系设计

#### 密钥层次结构
```
用户数据
    ↑ 加密/解密
主密钥 (Ku, Master Key)
    ↑ 双重包裹
├─ wrap_user(Ku)    ← 用户密码派生的 KEK_user 包裹
└─ wrap_server(Ku)  ← 服务端密钥 KEK_server 包裹
```

#### 密钥详细说明

1. **主密钥 Ku (Master Key)**
   - 每个用户一个，随机生成
   - 256-bit AES 密钥
   - 永不存储明文，只存储包裹后的版本

2. **用户包裹密钥 KEK_user**
   - 从用户安全密码派生
   - `KEK_user = Argon2id(security_password, salt_user, memory=64MB, iterations=3, parallelism=4, keylen=32)`
   - **改进**：使用 Argon2id 替代 PBKDF2，提供内存硬度防护
   - 用于包裹/解包 Ku

3. **服务端包裹密钥 KEK_server**
   - 从环境变量 `MASTER_KEY_SERVER` 读取
   - 256-bit 固定密钥
   - **版本控制**：支持多版本密钥，便于轮换
   - 生产环境建议使用 AWS KMS、Google Cloud KMS 等
   - 用于包裹/解包 Ku

#### 包裹格式规范（AES-256-GCM）

**包裹操作**：
```
输入：plaintext (Ku), KEK, AAD (用户ID等)
1. 生成随机 96-bit nonce (12 bytes)
2. AES-GCM 加密：ciphertext, tag = AES-256-GCM(KEK, nonce, plaintext, AAD)
3. 输出：base64(nonce || ciphertext || tag)
```

**解包操作**：
```
输入：wrapped (base64), KEK, AAD
1. 解码：blob = base64_decode(wrapped)
2. 拆分：nonce = blob[0:12], ciphertext = blob[12:-16], tag = blob[-16:]
3. AES-GCM 解密：plaintext = AES-256-GCM-Decrypt(KEK, nonce, ciphertext, tag, AAD)
4. 输出：plaintext (Ku)
```

**AAD (Additional Authenticated Data)**：
- 用户包裹：`"user:" + user_id`
- 服务端包裹：`"server:" + user_id + ":" + key_version`

### 1.3 数据库模型变更

#### User 表新增字段
```go
type User struct {
    // ... 现有字段

    // 密钥包裹相关（仅当设置了安全密码时有值）
    MasterKeyUserWrapped   string // Ku 的用户包裹版本 (base64)
    MasterKeyServerWrapped string // Ku 的服务端包裹版本 (base64)
    MasterKeySalt          string // 用户包裹时使用的 salt (base64)
    MasterKeyVersion       int    // 服务端密钥版本号（用于轮换）
}
```

**说明**：
- 所有密钥字段同时为空表示未设置安全密码
- 所有密钥字段必须同时设置或同时为空
- `MasterKeyVersion` 记录使用的 KEK_server 版本，便于密钥轮换

### 1.4 工作流程

#### 1.4.1 设置安全密码时
```
1. 生成随机主密钥 Ku (32 bytes)
2. 生成 salt_user (16 bytes)
3. 派生用户包裹密钥：
   KEK_user = Argon2id(security_password, salt_user, memory=64MB, iterations=3, parallelism=4, keylen=32)
4. 用户包裹 Ku：
   AAD = "user:" + user_id
   wrapped_user = WrapKey(Ku, KEK_user, AAD)  // 见包裹格式规范
5. 从环境变量获取当前版本的 KEK_server（version=1）
6. 服务端包裹 Ku：
   AAD = "server:" + user_id + ":1"
   wrapped_server = WrapKey(Ku, KEK_server_v1, AAD)
7. 保存到数据库：
   - MasterKeyUserWrapped = base64(wrapped_user)
   - MasterKeyServerWrapped = base64(wrapped_server)
   - MasterKeySalt = base64(salt_user)
   - MasterKeyVersion = 1
8. 如果已有未加密数据，使用 Ku 加密
```

#### 1.4.2 用户读取数据时
```
1. 用户提供安全密码
2. 从数据库读取 MasterKeyUserWrapped 和 MasterKeySalt
3. 派生 KEK_user = Argon2id(password, salt_user, memory=64MB, iterations=3, parallelism=4, keylen=32)
4. 解包主密钥：
   AAD = "user:" + user_id
   Ku = UnwrapKey(wrapped_user, KEK_user, AAD)
5. 使用 Ku 解密用户数据
6. 返回明文数据
```

#### 1.4.3 后台自动更新数据时
```
1. 从数据库读取 MasterKeyVersion（例如：version=1）
2. 从环境变量获取对应版本的 KEK_server_v1
3. 从数据库读取 MasterKeyServerWrapped
4. 解包主密钥：
   AAD = "server:" + user_id + ":1"
   Ku = UnwrapKey(wrapped_server, KEK_server_v1, AAD)
5. 使用 Ku 加密/解密数据
6. 保存加密后的数据
```

#### 1.4.4 修改安全密码时
```
1. 用户提供旧密码和新密码
2. 使用旧密码解包得到 Ku（见 1.4.2）
3. 生成新的 salt_user
4. 使用新密码重新包裹 Ku：
   KEK_user_new = Argon2id(new_password, salt_user_new, memory=64MB, iterations=3, parallelism=4, keylen=32)
   AAD = "user:" + user_id
   wrapped_user_new = WrapKey(Ku, KEK_user_new, AAD)
5. 更新数据库：
   - MasterKeyUserWrapped = wrapped_user_new
   - MasterKeySalt = salt_user_new
   - MasterKeyServerWrapped 保持不变
   - MasterKeyVersion 保持不变
```

### 1.5 API 变更

#### 修改接口：PUT /user/data

**⚠️ 重要变更**：保持需要安全密码的要求，但改变验证逻辑

**新行为**：
```json
{
  "password": "123456",  // 如果设置了安全密码则必填
  "data": {...}
}
```

**处理逻辑**：
1. 如果用户已设置安全密码（`MasterKeyServerWrapped != ""`）：
   - 必须提供 `password`
   - 验证密码，解包得到 Ku
   - 使用 Ku 加密数据
2. 如果用户未设置安全密码：
   - 不需要 `password`
   - 直接存储明文 JSON

**原因**：保持高安全性，防止持有 Access Token 的攻击者随意修改加密数据

#### 保持接口：POST /user/data
**行为不变**：用户读取时仍需提供密码
```json
{
  "password": "123456"  // 如果数据已加密则必填
}
```

### 1.6 安全考虑

#### 优点
1. ✅ 用户可用密码控制自己的数据访问
2. ✅ 后台可自动更新数据，无需用户密码
3. ✅ 主密钥 Ku 从不以明文存储
4. ✅ 即使数据库泄露，没有 KEK_server 也无法解密

#### 风险与缓解
1. **风险**：KEK_server 泄露导致所有用户数据可解密
   - **缓解**：使用专业 KMS 服务（AWS KMS、Google Cloud KMS）
   - **缓解**：KEK_server 定期轮换
   - **缓解**：严格的服务器访问控制

2. **风险**：服务器被入侵，攻击者获取 KEK_server
   - **缓解**：服务器安全加固
   - **缓解**：监控异常数据访问
   - **缓解**：数据访问审计日志

3. **风险**：用户忘记密码无法恢复数据
   - **缓解**：明确告知用户安全密码无法找回
   - **缓解**：建议用户自行备份重要数据

#### 环境变量配置
新增环境变量：
```env
# 服务端主密钥（用于包裹用户的主密钥）
# 支持多版本，便于轮换
MASTER_KEY_SERVER_V1=your-256-bit-hex-key-here-64-chars
# MASTER_KEY_SERVER_V2=new-key-after-rotation
# ... 可继续添加新版本

# 当前活跃版本（新用户使用此版本）
MASTER_KEY_SERVER_CURRENT_VERSION=1
```

生成方法：
```bash
# 生成 256-bit 随机密钥
openssl rand -hex 32
```

#### KEK_server 轮换计划

**轮换触发条件**：
- 定期轮换（建议每年）
- 密钥泄露风险
- 合规要求

**轮换步骤**：
1. 生成新的 KEK_server_v2
2. 添加到环境变量 `MASTER_KEY_SERVER_V2`
3. 更新 `MASTER_KEY_SERVER_CURRENT_VERSION=2`
4. 新用户自动使用 v2
5. 旧用户继续使用各自的版本（v1）
6. **可选**：后台任务重新包裹旧用户的 Ku
   ```
   FOR EACH user WHERE MasterKeyVersion = 1:
     1. 使用 KEK_server_v1 解包得到 Ku
     2. 使用 KEK_server_v2 重新包裹 Ku
     3. 更新 MasterKeyServerWrapped 和 MasterKeyVersion = 2
   ```
7. 确认所有用户迁移后，移除旧的 `MASTER_KEY_SERVER_V1`

**密钥加载逻辑**：
```go
func GetServerKey(version int) ([]byte, error) {
    key := os.Getenv(fmt.Sprintf("MASTER_KEY_SERVER_V%d", version))
    if key == "" {
        return nil, fmt.Errorf("key version %d not found", version)
    }
    return hex.DecodeString(key)
}
```

---

### 1.7 限流规范

#### 数据访问接口
- **POST /user/data（读取）**：200 次/分钟
- **PUT /user/data（更新）**：100 次/分钟

#### 会话管理接口
- **GET /auth/sessions**：150 次/分钟
- **DELETE /auth/sessions/:id**：50 次/5分钟
- **DELETE /auth/sessions（批量）**：25 次/5分钟

#### 限流策略
- 基于：用户 ID + IP 地址
- 超限响应：`429 Too Many Requests`
- 锁定时长：15 分钟（会话撤销），5 分钟（数据访问）

---

## 2. 登录状态管理

### 2.1 背景与问题
**当前问题**：
- 用户无法查看自己在哪些设备上登录
- 无法踢出可疑设备
- 只能通过修改密码来强制下线所有设备

**解决方案**：登录会话管理系统

### 2.2 数据库模型变更

#### RefreshToken 表新增字段
```go
type RefreshToken struct {
    // ... 现有字段

    // 会话管理相关
    SessionID  string    // 会话标识符 (UUIDv4)
    DeviceInfo string    // 设备信息（从 User-Agent 解析）
    IPAddress  string    // 登录 IP 地址
    LastUsedAt time.Time // 最后使用时间（刷新 token 时更新）
}
```

**SessionID 生成规则**：
- 使用 UUID v4 随机生成
- 格式：`550e8400-e29b-41d4-a716-446655440000`
- 避免碰撞风险，不泄露 token 信息

### 2.3 新增 API 接口

#### 2.3.1 GET /auth/sessions
获取当前用户的所有登录会话列表

**需要认证**：是（Bearer Token）

**请求**：无请求体

**成功响应 (200)**：
```json
{
  "success": true,
  "data": {
    "current_session_id": "a1b2c3d4e5f6",
    "sessions": [
      {
        "session_id": "a1b2c3d4e5f6",
        "device_info": "Chrome 120 on Windows 10",
        "ip_address": "192.168.1.100",
        "created_at": "2024-01-01T10:00:00Z",
        "last_used_at": "2024-01-02T15:30:00Z",
        "is_current": true
      },
      {
        "session_id": "b2c3d4e5f6a1",
        "device_info": "Safari 17 on iPhone",
        "ip_address": "192.168.1.101",
        "created_at": "2023-12-31T20:00:00Z",
        "last_used_at": "2024-01-01T12:00:00Z",
        "is_current": false
      }
    ]
  }
}
```

**说明**：
- `current_session_id`：当前请求使用的会话 ID
- `is_current`：标记当前设备，防止误踢自己

#### 2.3.2 DELETE /auth/sessions/:session_id
踢出指定设备（撤销其 Refresh Token）

**需要认证**：是（Bearer Token）

**URL 参数**：
- `session_id`：要踢出的会话 ID

**请求体**：
```json
{
  "password": "your_login_password"  // 登录密码（所有用户都有）
}
```

**成功响应 (200)**：
```json
{
  "success": true,
  "message": "设备已踢出"
}
```

**错误响应**：
- `400` - 请求体无效 / 不能踢出当前设备
- `401` - 未授权 / 密码错误
- `404` - 会话不存在
- `429` - 请求过于频繁（限流）

**说明**：
- 不允许踢出当前设备（防止误操作）
- **改进**：使用登录密码验证，而非安全密码（所有用户都有登录密码）
- **限流**：5 分钟内最多 50 次尝试，超过则锁定 15 分钟

#### 2.3.3 DELETE /auth/sessions
踢出所有其他设备（只保留当前设备）

**需要认证**：是（Bearer Token）

**请求体**：
```json
{
  "password": "your_login_password"  // 登录密码（所有用户都有）
}
```

**成功响应 (200)**：
```json
{
  "success": true,
  "message": "已踢出 2 个其他设备",
  "data": {
    "revoked_count": 2
  }
}
```

**错误响应**：
- `400` - 请求体无效
- `401` - 未授权 / 密码错误
- `429` - 请求过于频繁（限流）

**说明**：
- 删除除当前设备外的所有 refresh token
- **改进**：使用登录密码验证，而非安全密码
- **限流**：5 分钟内最多 25 次尝试，超过则锁定 15 分钟

### 2.4 设备信息解析

#### User-Agent 解析策略
使用 `user-agent` 库解析 User-Agent 字符串：
```go
// 示例输出
"Chrome 120 on Windows 10"
"Safari 17 on iPhone"
"Firefox 121 on macOS"
"Unknown Browser on Unknown OS"
```

#### IP 地址获取
从请求头获取真实 IP：
```go
// 优先级
1. X-Forwarded-For (取第一个)
2. X-Real-IP
3. RemoteAddr
```

### 2.5 安全考虑

#### 为什么使用登录密码而非安全密码？
1. **普适性**：所有用户都有登录密码，而安全密码是可选的
2. **不阻塞安全功能**：未设置安全密码的用户也能踢出可疑设备
3. **足够的安全性**：验证登录密码 + Bearer Token 双重验证

#### 限流机制
- **单设备踢出**：5 分钟内最多 50 次尝试
- **批量踢出**：5 分钟内最多 5 次尝试
- **锁定时长**：超限后锁定 15 分钟
- **计数器**：基于用户 ID + IP 地址

#### 边界情况
1. **踢出当前设备**：禁止操作，返回 400 错误
2. **会话已过期**：正常删除，返回成功
3. **密码错误多次**：触发限流，锁定 15 分钟

### 2.6 刷新令牌时更新 LastUsedAt
修改 `POST /auth/refresh` 接口：
- 成功刷新后，更新 `LastUsedAt` 为当前时间
- 便于用户识别活跃会话

---

## 3. 实现优先级

### 第一阶段：双重密钥包裹
1. 修改 `utils/crypto.go` - 添加密钥包裹/解包函数
2. 修改 `models/models.go` - User 表新增字段
3. 修改 `handlers/user.go` - SetSecurityPassword、UpdateSecurityPassword
4. 修改 `handlers/user.go` - UpdateUserData（移除密码要求）
5. 更新 API 文档

### 第二阶段：登录状态管理
1. 修改 `models/models.go` - RefreshToken 表新增字段
2. 修改 `handlers/auth.go` - 登录/注册时记录设备信息
3. 新增 `handlers/session.go` - 会话管理接口
4. 修改 `main.go` - 注册新路由
5. 更新 API 文档

---

## 4. 向后兼容性

### 双重密钥包裹
- **兼容策略**：检测 `MasterKeyServerWrapped` 是否为空
  - 为空：旧方案（直接用密码加密数据）
  - 不为空：新方案（双重密钥包裹）
- **迁移**：用户下次修改安全密码或更新数据时自动迁移

### 登录状态管理
- **兼容策略**：旧的 refresh token 没有设备信息
  - DeviceInfo 显示为 "Unknown Device"
  - 仍可正常踢出

---

## 5. 测试计划

### 双重密钥包裹
1. 测试设置安全密码后的数据加密
2. 测试用户读取数据（提供密码）
3. 测试后台更新数据（无需密码）
4. 测试修改安全密码后数据仍可访问
5. 测试 KEK_server 错误时的处理

### 登录状态管理
1. 测试获取会话列表
2. 测试踢出指定设备
3. 测试踢出所有其他设备
4. 测试安全密码验证
5. 测试禁止踢出当前设备
