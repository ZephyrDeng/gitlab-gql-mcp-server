# GitLab MCP 工具使用指南

本 MCP 服务提供了与 GitLab 实例的强大集成能力，支持 GitLab RESTful API 访问，可通过多种操作与 GitLab 进行交互。

## 配置要求

在使用本工具前，您需要配置以下环境变量：

- `GITLAB_TOKEN`：GitLab 个人访问令牌（PAT），具有适当的权限
- `GITLAB_API_URL`：您的 GitLab 实例 URL (例如: gitlab.com)

## 主要工具: GitlabRestfulApiTool

该工具允许通过 GitLab RESTful API 查询和操作 GitLab 数据。

### 支持的操作

1. `getCurrentUserTasks` - 获取当前用户的任务（合并请求、问题等）
2. `searchUserWithProjects` - 搜索用户及其活跃项目
3. `searchProjectWithDetails` - 搜索项目并获取详情
4. `createMRComment` - 在合并请求上添加评论
5. `acceptMR` - 接受并合并指定的合并请求
6. `raw` - 直接访问 GitLab API 端点

### 字段过滤功能

所有操作都支持 `fields` 参数，用于指定需要返回的字段，减少数据量。字段可以使用简单名称（如 "id", "name"）或嵌套路径（如 "user.avatar_url", "projects[0].name"）。

## 使用示例

### 获取当前用户任务

```json
{
  "operation": "getCurrentUserTasks",
  "includeAssignedMRs": "true",
  "includeReviewMRs": "true",
  "fields": ["id", "name", "username", "assigned_mrs"]
}
```

### 搜索用户及其项目

```json
{
  "operation": "searchUserWithProjects",
  "username": "张三",
  "fields": ["id", "name", "username", "project_names"]
}
```

### 搜索项目并获取详情

```json
{
  "operation": "searchProjectWithDetails",
  "projectName": "前端项目",
  "fields": ["id", "name", "description", "branch_names", "member_names"]
}
```

### 创建合并请求评论

```json
{
  "operation": "createMRComment",
  "projectId": "group/project-name",
  "mergeRequestId": 123,
  "comment": "代码看起来不错，已批准！",
  "fields": ["id", "body", "created_at"]
}
```

### 接受合并请求

```json
{
  "operation": "acceptMR",
  "projectId": "group/project-name",
  "mergeRequestId": 789,
  "mergeOptions": {
    "shouldRemoveSourceBranch": true
  },
  "fields": ["id", "state", "title"]
}
```

### 使用原始 API 调用

```json
{
  "operation": "raw",
  "endpoint": "/projects",
  "method": "GET",
  "params": {
    "search": "backend"
  },
  "fields": ["id", "name", "description"]
}
```

## 字段映射系统

工具支持智能字段映射，允许使用简化字段名而不需要知道精确的嵌套路径：

- `id` → 自动映射到合适的对象 ID (如 `user.id`)
- `name` → 自动映射到名称字段
- `project_names` → 映射到 `active_projects[*].name`

## 注意事项

- 所有请求都需要指定至少一个字段 (`fields` 参数)
- 如果指定的字段不存在，系统会返回可用字段列表和建议
- 字符串形式的布尔值 ("true"/"false") 在处理时会自动转换为实际布尔值 