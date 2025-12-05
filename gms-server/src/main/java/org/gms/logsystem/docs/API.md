# 日志系统 REST API 文档

## API 基础信息

- **基础URL**: `/api/logsystem`
- **响应格式**: JSON
- **字符编码**: UTF-8

## 响应格式

所有API响应统一使用以下格式：

```json
{
  "code": 200,
  "message": "成功",
  "data": {},
  "timestamp": 1700000000000
}
```

### 状态码说明

| 状态码 | 含义 |
|--------|------|
| 200 | 请求成功 |
| 400 | 客户端错误 |
| 500 | 服务器错误 |

---

## 分类管理 API

### 获取所有大类

**请求**
```
GET /api/logsystem/categories/major
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": ["player", "item", "economy", "quest", "dungeon", "equipment", "skill", "pet", "guild", "social", "system", "packet"],
  "timestamp": 1700000000000
}
```

---

### 获取指定大类的所有小类

**请求**
```
GET /api/logsystem/categories/minor/{majorCategory}
```

**参数**
- `majorCategory` (path) - 大类名称，例如：player

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": [
    {
      "categoryId": "player.login",
      "majorCategory": "player",
      "minorCategory": "login",
      "description": "玩家登录日志",
      "level": "HIGH",
      "enabled": true,
      "consoleOutput": false,
      "fileOutput": true,
      "createdTime": 1700000000000,
      "modifiedTime": 1700000000000
    },
    {
      "categoryId": "player.logout",
      "majorCategory": "player",
      "minorCategory": "logout",
      "description": "玩家登出日志",
      "level": "HIGH",
      "enabled": true,
      "consoleOutput": false,
      "fileOutput": true,
      "createdTime": 1700000000000,
      "modifiedTime": 1700000000000
    }
  ],
  "timestamp": 1700000000000
}
```

---

### 获取所有分类

**请求**
```
GET /api/logsystem/categories/all
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": [
    {
      "categoryId": "player.login",
      "majorCategory": "player",
      "minorCategory": "login",
      "description": "玩家登录日志",
      "level": "HIGH",
      "enabled": true,
      "consoleOutput": false,
      "fileOutput": true,
      "createdTime": 1700000000000,
      "modifiedTime": 1700000000000
    }
  ],
  "timestamp": 1700000000000
}
```

---

### 获取指定分类

**请求**
```
GET /api/logsystem/categories/{majorCategory}/{minorCategory}
```

**参数**
- `majorCategory` (path) - 大类名称
- `minorCategory` (path) - 小类名称

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": {
    "categoryId": "player.login",
    "majorCategory": "player",
    "minorCategory": "login",
    "description": "玩家登录日志",
    "level": "HIGH",
    "enabled": true,
    "consoleOutput": false,
    "fileOutput": true,
    "createdTime": 1700000000000,
    "modifiedTime": 1700000000000
  },
  "timestamp": 1700000000000
}
```

---

### 更新分类

**请求**
```
POST /api/logsystem/categories/update
Content-Type: application/json

{
  "majorCategory": "player",
  "minorCategory": "login",
  "description": "玩家登录日志",
  "level": "HIGH",
  "enabled": true,
  "consoleOutput": true,
  "fileOutput": true
}
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": true,
  "timestamp": 1700000000000
}
```

---

### 启用/禁用分类

**请求**
```
POST /api/logsystem/categories/enable/{majorCategory}/{minorCategory}?enabled=true
```

**参数**
- `majorCategory` (path) - 大类名称
- `minorCategory` (path) - 小类名称
- `enabled` (query) - true 启用，false 禁用

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": true,
  "timestamp": 1700000000000
}
```

---

### 设置分类输出选项

**请求**
```
POST /api/logsystem/categories/output/{majorCategory}/{minorCategory}?console=true&file=true
```

**参数**
- `majorCategory` (path) - 大类名称
- `minorCategory` (path) - 小类名称
- `console` (query) - 是否输出到控制台
- `file` (query) - 是否输出到文件

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": true,
  "timestamp": 1700000000000
}
```

---

## 上下文管理 API

### 创建日志上下文

**请求**
```
POST /api/logsystem/context/create
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": {
    "contextId": "550e8400-e29b-41d4-a716-446655440000",
    "accountId": 0,
    "accountName": null,
    "characterId": 0,
    "characterName": null,
    "ipAddress": null,
    "macAddress": null,
    "hardwareId": null,
    "mapId": 0,
    "mapName": null,
    "posX": 0,
    "posY": 0,
    "customData": null,
    "createdTime": 1700000000000,
    "lastAccessTime": 1700000000000
  },
  "timestamp": 1700000000000
}
```

---

### 设置日志上下文

**请求**
```
POST /api/logsystem/context/set
Content-Type: application/json

{
  "contextId": "550e8400-e29b-41d4-a716-446655440000",
  "accountId": 2,
  "accountName": "magical",
  "characterId": 2,
  "characterName": "Magical",
  "ipAddress": "127.0.0.1",
  "macAddress": "00-15-5D-C3-AE-64",
  "hardwareId": "B6770000",
  "mapId": 980010020,
  "mapName": "竞技场出口",
  "posX": 100,
  "posY": 200
}
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": true,
  "timestamp": 1700000000000
}
```

---

### 获取当前上下文

**请求**
```
GET /api/logsystem/context/current
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": {
    "contextId": "550e8400-e29b-41d4-a716-446655440000",
    "accountId": 2,
    "accountName": "magical",
    "characterId": 2,
    "characterName": "Magical",
    "ipAddress": "127.0.0.1",
    "macAddress": "00-15-5D-C3-AE-64",
    "hardwareId": "B6770000",
    "mapId": 980010020,
    "mapName": "竞技场出口",
    "posX": 100,
    "posY": 200,
    "customData": null,
    "createdTime": 1700000000000,
    "lastAccessTime": 1700000000000
  },
  "timestamp": 1700000000000
}
```

---

## 日志记录 API

### 记录日志

**请求**
```
POST /api/logsystem/log/record?majorCategory=player&minorCategory=login&message=玩家登录&customData={}
```

**参数**
- `majorCategory` (query) - 大类名称
- `minorCategory` (query) - 小类名称
- `message` (query) - 日志消息
- `customData` (query) - 自定义数据（可选，JSON格式）

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": true,
  "timestamp": 1700000000000
}
```

---

## 监控 API

### 获取监控汇总

**请求**
```
GET /api/logsystem/monitor/summary
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": "系统监控统计 - 总计: 1000, 成功: 990, 失败: 10, QPS: 100.50, 平均延迟: 2.50ms, 成功率: 99.00%",
  "timestamp": 1700000000000
}
```

---

### 获取系统级监控统计

**请求**
```
GET /api/logsystem/monitor/system
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": {
    "categoryId": "SYSTEM",
    "totalCount": 1000,
    "successCount": 990,
    "failureCount": 10,
    "totalTime": 2500,
    "lastUpdateTime": 1700000000000
  },
  "timestamp": 1700000000000
}
```

---

### 获取分类级监控统计

**请求**
```
GET /api/logsystem/monitor/categories
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": [
    {
      "categoryId": "player.login",
      "totalCount": 100,
      "successCount": 99,
      "failureCount": 1,
      "totalTime": 250,
      "lastUpdateTime": 1700000000000
    },
    {
      "categoryId": "player.logout",
      "totalCount": 80,
      "successCount": 80,
      "failureCount": 0,
      "totalTime": 200,
      "lastUpdateTime": 1700000000000
    }
  ],
  "timestamp": 1700000000000
}
```

---

### 获取队列统计

**请求**
```
GET /api/logsystem/monitor/queue
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": "高频队列: 10, 中频队列: 5, 低频队列: 2",
  "timestamp": 1700000000000
}
```

---

### 获取上下文统计

**请求**
```
GET /api/logsystem/monitor/context
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": "活跃上下文: 15",
  "timestamp": 1700000000000
}
```

---

### 清除监控数据

**请求**
```
POST /api/logsystem/monitor/clear
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": true,
  "timestamp": 1700000000000
}
```

---

## 健康检查 API

### 系统健康检查

**请求**
```
GET /api/logsystem/health
```

**响应示例**
```json
{
  "code": 200,
  "message": "成功",
  "data": {
    "status": "UP",
    "timestamp": 1700000000000,
    "categories": 45,
    "queueStats": "高频队列: 10, 中频队列: 5, 低频队列: 2",
    "contextStats": "活跃上下文: 15"
  },
  "timestamp": 1700000000000
}
```

---

## cURL 示例

### 获取所有大类
```bash
curl -X GET "http://localhost:8080/api/logsystem/categories/major"
```

### 获取player大类的所有小类
```bash
curl -X GET "http://localhost:8080/api/logsystem/categories/minor/player"
```

### 记录一条日志
```bash
curl -X POST "http://localhost:8080/api/logsystem/log/record?majorCategory=player&minorCategory=login&message=玩家登录&customData={}"
```

### 获取监控汇总
```bash
curl -X GET "http://localhost:8080/api/logsystem/monitor/summary"
```

---

## 错误处理

### 常见错误响应

**分类不存在**
```json
{
  "code": 400,
  "message": "分类不存在: player.xxx",
  "timestamp": 1700000000000
}
```

**服务器错误**
```json
{
  "code": 500,
  "message": "服务器内部错误",
  "timestamp": 1700000000000
}
```

---

## 速率限制

目前没有速率限制，建议：
- 避免在高频操作中调用同步日志API
- 使用异步API处理大量日志
- 合理设置监控数据查询频率

## 最后更新

文档更新时间：2025-11-21
