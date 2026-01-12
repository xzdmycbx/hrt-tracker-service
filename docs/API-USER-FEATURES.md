# 用户功能 API 文档

本文档专门介绍用户头像管理和密码管理相关的 API 接口。

---

## 1. 头像管理

### 1.1 上传头像

上传或更新用户头像图片。

**接口：** `POST /api/user/avatar`

**需要认证：** 是

**请求类型：** `multipart/form-data`

**请求参数：**
- `avatar`：图片文件（字段名）
  - 支持格式：PNG、GIF、JPEG
  - 最大大小：5MB
  - 文件会自动转换为 JPEG 格式

**速率限制：** 15次/10分钟，超限后锁定30分钟

**成功响应 (200)：**
```json
{
  "success": true,
  "data": {
    "avatar": "user_123.jpg",
    "original_size": 2048576,
    "final_size": 524288,
    "compressed": true
  }
}
```

**响应字段说明：**
- `avatar`：头像文件名
- `original_size`：原始文件大小（字节）
- `final_size`：压缩后大小（字节）
- `compressed`：是否进行了压缩

**错误响应：**
- `400` - 请求格式错误 / 文件太大（超过5MB）/ 无效的图片文件
- `401` - 未授权（令牌无效）
- `404` - 用户不存在
- `429` - 请求过于频繁（超过速率限制）
- `500` - 服务器内部错误（创建目录、压缩或保存失败）

**说明：**
- 上传新头像会自动替换旧头像
- 所有头像统一转换为 JPEG 格式
- 智能压缩策略：
  - 原图 < 1MB：保持原质量，仅转换格式
  - 原图 >= 1MB：先降低质量（85→50），如仍超过1MB则缩小尺寸
  - 最终大小不超过 1MB
- 文件存储路径：`/app/avatars/user_{用户ID}.jpg`
- Docker 部署时头像数据持久化到 `hrt-avatars` 数据卷

**cURL 示例：**
```bash
curl -X POST http://localhost:8080/api/user/avatar \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -F "avatar=@/path/to/image.png"
```

---

### 1.2 获取头像

获取指定用户的头像图片（公开接口）。

**接口：** `GET /api/avatars/:username`

**需要认证：** 否

**URL 参数：**
- `username` - 用户名

**速率限制：** 150次/分钟，超限后锁定10分钟

**成功响应 (200)：**
- 返回图片文件（JPEG格式）
- Content-Type: `image/jpeg`
- 缓存头：`Cache-Control: public, max-age=86400`（缓存1天）
- ETag：基于用户更新时间

**错误响应：**
- `404` - 用户不存在 / 头像未设置 / 头像文件不存在 / 无效的头像路径
- `429` - 请求过于频繁（超过速率限制）

**说明：**
- 此接口为公开访问，无需登录
- 通过用户名获取头像，而非用户ID
- 浏览器会自动缓存24小时
- 防路径遍历：严格验证文件名格式（只允许 `user_数字.jpg`）

**浏览器访问示例：**
```
http://localhost:8080/api/avatars/john_doe
```

**cURL 示例：**
```bash
curl -o avatar.jpg http://localhost:8080/api/avatars/john_doe
```

---

### 1.3 删除头像

删除当前用户的头像。

**接口：** `DELETE /api/user/avatar`

**需要认证：** 是

**请求体：** 无

**速率限制：** 25次/5分钟，超限后锁定15分钟

**成功响应 (200)：**
```json
{
  "success": true,
  "message": "Avatar deleted successfully"
}
```

**错误响应：**
- `400` - 没有头像可删除
- `401` - 未授权（令牌无效）
- `404` - 用户不存在
- `429` - 请求过于频繁（超过速率限制）
- `500` - 服务器内部错误（删除文件或更新数据库失败）

**说明：**
- 同时删除文件系统中的文件和数据库中的记录
- 删除操作具有原子性：文件删除失败则不更新数据库

**cURL 示例：**
```bash
curl -X DELETE http://localhost:8080/api/user/avatar \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 2. 密码管理

### 2.1 修改登录密码

修改用户的登录密码（非安全密码）。

**接口：** `PUT /api/user/password`

**需要认证：** 是

**请求体：**
```json
{
  "old_password": "string（旧密码）",
  "new_password": "string（新密码）"
}
```

**速率限制：** 5次/5分钟，超限后锁定15分钟

**成功响应 (200)：**
```json
{
  "success": true,
  "data": {
    "message": "Password changed successfully",
    "other_sessions_logged_out": 2
  }
}
```

**响应字段说明：**
- `message`：操作结果消息
- `other_sessions_logged_out`：被登出的其他会话数量

**错误响应：**
- `400` - 请求体无效 / 新密码长度不足（少于8位）/ 密码复杂度不够 / 新旧密码相同
- `401` - 未授权（令牌无效或旧密码错误）
- `404` - 用户不存在
- `429` - 请求过于频繁（超过速率限制）
- `500` - 服务器内部错误（生成盐值或更新密码失败）

**密码要求：**
1. **最小长度**：8个字符
2. **复杂度要求**：
   - 必须包含至少一个字母（a-z 或 A-Z）
   - 必须包含至少一个数字（0-9）
3. **不能与旧密码相同**

**安全特性：**
- ✅ 修改密码后，**所有其他设备的登录会话自动失效**
- ✅ 当前设备的会话保持登录状态
- ✅ 强制密码复杂度验证
- ✅ 速率限制防止暴力破解

**说明：**
- 此接口修改的是**登录密码**（用于注册、登录）
- 安全密码的修改请使用 `PUT /api/user/security-password`
- 修改密码不会影响用户数据加密（加密使用的是安全密码，不是登录密码）
- 操作成功后，其他设备的 refresh token 会被删除，access token 会在验证时失效

**cURL 示例：**
```bash
curl -X PUT http://localhost:8080/api/user/password \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "MyOldPass123",
    "new_password": "MyNewSecurePass456"
  }'
```

---

## 3. 安全说明

### 3.1 头像安全
- **路径遍历防护**：严格验证文件名格式，使用白名单验证
- **文件权限**：目录权限 0750，文件权限 0640
- **格式验证**：检查图片文件签名，防止恶意文件上传
- **大小限制**：上传限制5MB，压缩后不超过1MB
- **自动清理**：上传新头像时自动删除旧头像

### 3.2 密码安全
- **密码复杂度**：强制8位以上，包含字母和数字
- **会话管理**：修改密码后其他会话自动失效
- **速率限制**：防止暴力破解
- **密码存储**：使用 PBKDF2 + 随机盐值哈希存储
- **错误消息**：使用通用错误消息，防止信息泄露

### 3.3 速率限制
所有接口都配置了速率限制，防止滥用和攻击：

| 接口 | 限制 | 窗口 | 锁定时间 |
|-----|------|------|---------|
| 上传头像 | 3次 | 10分钟 | 30分钟 |
| 删除头像 | 5次 | 5分钟 | 15分钟 |
| 获取头像（公开） | 30次 | 1分钟 | 10分钟 |
| 修改密码 | 5次 | 5分钟 | 15分钟 |

---

## 4. 使用场景示例

### 场景 1：用户设置头像

```bash
# 1. 上传头像
curl -X POST http://localhost:8080/api/user/avatar \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -F "avatar=@profile.jpg"

# 响应：
# {
#   "success": true,
#   "data": {
#     "avatar": "user_123.jpg",
#     "original_size": 3145728,
#     "final_size": 987654,
#     "compressed": true
#   }
# }

# 2. 其他用户访问头像
curl http://localhost:8080/api/avatars/your_username -o avatar.jpg
```

### 场景 2：修改密码并登出其他设备

```bash
# 修改密码
curl -X PUT http://localhost:8080/api/user/password \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "OldPassword123",
    "new_password": "NewSecurePass456"
  }'

# 响应：
# {
#   "success": true,
#   "data": {
#     "message": "Password changed successfully",
#     "other_sessions_logged_out": 2
#   }
# }

# 结果：其他2个设备的登录会话已失效，当前设备仍然登录
```

### 场景 3：更换头像

```bash
# 直接上传新头像即可，旧头像会自动删除
curl -X POST http://localhost:8080/api/user/avatar \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -F "avatar=@new_avatar.png"
```

### 场景 4：移除头像

```bash
# 删除头像
curl -X DELETE http://localhost:8080/api/user/avatar \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# 响应：
# {
#   "success": true,
#   "message": "Avatar deleted successfully"
# }
```

---

## 5. 与其他 API 的区别

### 登录密码 vs 安全密码

| 特性 | 登录密码 | 安全密码 |
|-----|---------|---------|
| **用途** | 登录认证 | 数据加密 |
| **修改接口** | `PUT /api/user/password` | `PUT /api/user/security-password` |
| **格式要求** | 8位以上，包含字母和数字 | 6位数字 |
| **修改后影响** | 其他会话失效 | 数据重新加密 |
| **存储方式** | PBKDF2 哈希 | Argon2id 哈希 |
| **是否必需** | 是（注册时必须） | 否（可选设置） |

### 头像 API vs 其他文件上传

此 API 的特点：
- ✅ 自动格式转换（统一为 JPEG）
- ✅ 智能压缩（保证不超过1MB）
- ✅ 公开访问（无需认证即可查看）
- ✅ 自动缓存（浏览器缓存1天）
- ✅ 一人一头像（自动覆盖旧头像）

---

## 6. 常见问题 (FAQ)

**Q1：可以上传 GIF 动图吗？**
A：可以上传，但会被转换为静态 JPEG 图片（取第一帧）。

**Q2：头像压缩后质量会很差吗？**
A：不会。如果原图小于1MB，只转换格式不压缩。大于1MB时，先尝试降低质量（85→50），质量下降有限。只有在质量降低仍超过1MB时才会缩小尺寸。

**Q3：修改密码后为什么其他设备会被登出？**
A：这是安全特性。修改密码通常意味着账户可能被盗，因此强制登出其他设备以保护账户安全。

**Q4：可以获取其他用户的头像吗？**
A：可以，头像是公开的，任何人都可以通过用户名访问。

**Q5：删除头像后能恢复吗？**
A：不能。删除操作会永久删除文件，无法恢复。

**Q6：为什么获取头像不需要登录？**
A：头像被设计为公开信息，用于在社交功能中显示用户头像。如果需要私密头像，可以不设置。

**Q7：修改密码的复杂度要求能关闭吗？**
A：不能。密码复杂度是强制的安全要求，无法关闭。

---

## 7. 技术实现细节

### 头像压缩算法
```
1. 检查原图大小
   - 如果 < 1MB：仅转换为 JPEG（质量85），不压缩
   - 如果 >= 1MB：进入压缩流程

2. 降低质量压缩
   - 从质量85开始，每次降低5
   - 直到大小 <= 1MB 或质量 <= 50

3. 如果仍超过1MB，缩小尺寸
   - 计算缩放比例：目标0.8MB / 当前大小
   - 按比例缩小宽度，高度等比缩放
   - 使用 Lanczos3 算法（高质量缩放）

4. 最终输出 JPEG（质量85）
```

### 密码哈希方式
```
登录密码存储格式：salt:hash
- salt: base64编码的16字节随机值
- hash: PBKDF2(password, salt, 100000次迭代, SHA256)

安全密码存储格式：分开存储
- SecurityPasswordSalt: base64编码的16字节随机值
- SecurityPasswordHash: Argon2id(password, salt, 64MB内存, 4次迭代, 4线程)
```

### Docker 持久化配置
```yaml
volumes:
  - hrt-data:/app/data        # 数据库
  - hrt-avatars:/app/avatars  # 头像文件
```

---

如有其他问题，请参考主 API 文档：`docs/API.md`
