import { MCPTool, logger } from "mcp-framework";
import { z } from "zod";
import axios, { AxiosInstance, AxiosRequestConfig, AxiosError } from "axios";
import dotenv from "dotenv";
import _ from "lodash";

const { get, set } = _;
dotenv.config();

// 操作类型枚举
const OperationType = z.enum([
  'raw',
  'getCurrentUserTasks',
  'searchUserWithProjects', 
  'searchProjectWithDetails',
  'createMRComment',
  'acceptMR'
]);

// GitLab API 输入接口
interface GitlabRestfulApiInput {
  operation: z.infer<typeof OperationType>;
  endpoint?: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  params?: Record<string, any>;
  data?: Record<string, any>;
  username?: string;
  projectName?: string;
  projectId?: string;
  mergeRequestId?: number;
  comment?: string;
  mergeOptions?: {
    mergeCommitMessage?: string;
    squash?: boolean;
    shouldRemoveSourceBranch?: boolean;
  };
  includeAssignedMRs?: boolean | "true" | "false";
  includeReviewMRs?: boolean | "true" | "false";
  includePipelines?: boolean | "true" | "false";
  includeIssues?: boolean | "true" | "false";
  fields: string[]; // 必填项：指定需要返回的字段列表
}

// GitLab API 配置接口
interface GitlabApiConfig {
  baseUrl: string; // GitLab 实例 URL
  privateToken: string; // 私人访问令牌
  timeout?: number; // 请求超时时间
}

// 添加 GitLab API 响应接口
interface GitlabApiResponse {
  status?: number;
  message?: string;
  error?: boolean;
  details?: any;
  fieldsInfo?: {
    requestedFields: string[];
    availableFields: string[];
    missingFields: string[];
    suggestedPaths?: string[];
    processedFields?: string[]; // 处理后的字段路径，用于调试
    message: string;
  };
  // 错误情况下可能返回的额外字段
  availableOperations?: string[];
  examples?: any[];
  // 响应数据会直接在顶层，而不是嵌套在 data 字段中
  [key: string]: any;
}

const examples = [
  {
    title: "搜索用户及其项目",
    input: {
      operation: "searchUserWithProjects",
      username: "张三"
    },
    description: "根据用户名搜索用户并获取其活跃项目信息"
  },
  {
    title: "获取当前用户任务",
    input: {
      operation: "getCurrentUserTasks"
    },
    description: "获取当前用户 (基于 Token) 的待办任务，包括合并请求、问题等"
  },
  {
    title: "搜索项目并获取详情",
    input: {
      operation: "searchProjectWithDetails",
      projectName: "前端项目"
    },
    description: "根据项目名称搜索项目并获取其详细信息"
  },
  {
    title: "创建合并请求评论",
    input: {
      operation: "createMRComment",
      projectId: "group/project-name",
      mergeRequestId: 123,
      comment: "代码看起来不错，已批准！"
    },
    description: "在指定合并请求上添加评论"
  },
  {
    title: "接受合并请求",
    input: {
      operation: "acceptMR",
      projectId: 456,
      mergeRequestId: 789,
      mergeOptions: {
        shouldRemoveSourceBranch: true
      }
    },
    description: "接受并合并指定的合并请求"
  },
  {
    title: "使用原始 API 调用",
    input: {
      operation: "raw",
      endpoint: "/projects",
      method: "GET",
      params: {
        search: "backend"
      }
    },
    description: "使用原始 API 直接调用 GitLab API，提供灵活性"
  },
  {
    title: "使用字段过滤获取用户信息",
    input: {
      operation: "searchUserWithProjects",
      username: "张三",
      fields: ["user.id", "user.name", "user.avatar_url"]
    },
    description: "指定只返回用户的 ID、名称和头像，减少响应数据量"
  },
  {
    title: "获取项目的特定信息",
    input: {
      operation: "searchProjectWithDetails",
      projectName: "前端项目",
      fields: ["details.project.name", "details.project.description", "details.members"]
    },
    description: "只返回项目的名称、描述和成员列表，忽略其他信息"
  }
]
export class GitlabRestfulApiTool extends MCPTool<GitlabRestfulApiInput> {
  name = "Gitlab API MCP-Tool";
  description = "GitLab API v4 工具，用于访问 GitLab 服务。支持 5 种主要操作：1) 查询用户任务，2) 搜索用户及项目，3) 搜索项目详情，4) 创建 MR 评论，5) 接受 MR，以及灵活的原始 API 调用。支持字段过滤功能，减少数据量。" + `以下是例子参考：\n${JSON.stringify(examples)}`;
  
  // 工具使用示例
  examples = examples;

  private client: AxiosInstance;
  private config: GitlabApiConfig;
  
  constructor(config: GitlabApiConfig = {
    baseUrl: process.env.GITLAB_API_URL || "",
    privateToken: process.env.GITLAB_TOKEN || "",
    timeout: 10000
  }) {
    super();

    if (!config.privateToken) {
      throw new Error("GITLAB_TOKEN 未配置");
    }

    if (!config.baseUrl) {
      throw new Error("GITLAB_API_URL 未配置");
    }

    this.config = config;
    this.client = this.createApiClient();
  }

  schema = {
    operation: {
      type: OperationType,
      description: "操作类型，可选值：'raw'(原始 API 调用), 'getCurrentUserTasks'(获取当前用户任务), 'searchUserWithProjects'(搜索用户及项目), 'searchProjectWithDetails'(搜索项目详情), 'createMRComment'(创建 MR 评论), 'acceptMR'(接受 MR)",
    },
    endpoint: {
      type: z.string().optional(),
      description: "API 端点路径，仅在 operation='raw' 时使用，例如：'/projects', '/user'",
    },
    method: {
      type: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).optional().default('GET'),
      description: "HTTP 请求方法，仅在 operation='raw' 时使用",
    },
    params: {
      type: z.record(z.any()).optional(),
      description: "查询参数对象，仅在 operation='raw' 时使用，例如：{search: '关键词'}",
    },
    data: {
      type: z.record(z.any()).optional(),
      description: "请求体数据对象，仅在 operation='raw' 时使用",
    },
    username: {
      type: z.string().optional(),
      description: "用户名关键词，仅在 operation='searchUserWithProjects' 时使用",
    },
    projectName: {
      type: z.string().optional(),
      description: "项目名称关键词，仅在 operation='searchProjectWithDetails' 时使用",
    },
    projectId: {
      type: z.string().optional(),
      description: "GitLab 项目 ID 或路径，在 operation='createMRComment' 或 'acceptMR' 时使用",
    },
    mergeRequestId: {
      type: z.number().optional(),
      description: "合并请求 ID，在 operation='createMRComment' 或 'acceptMR' 时使用",
    },
    comment: {
      type: z.string().optional(),
      description: "评论内容，仅在 operation='createMRComment' 时使用",
    },
    mergeOptions: {
      type: z.object({
        mergeCommitMessage: z.string().optional(),
        squash: z.boolean().optional(),
        shouldRemoveSourceBranch: z.boolean().optional()
      }).optional(),
      description: "合并选项，仅在 operation='acceptMR' 时使用",
    },
    includeAssignedMRs: {
      type: z.union([z.boolean(), z.literal("true"), z.literal("false")]).optional(),
      description: "boolean 值，是否包含分配给当前用户的合并请求，仅在 operation='getCurrentUserTasks' 时使用。也接受字符串 'true'/'false'",
    },
    includeReviewMRs: {
      type: z.union([z.boolean(), z.literal("true"), z.literal("false")]).optional(),
      description: "boolean 值，是否包含需要当前用户评审的合并请求，仅在 operation='getCurrentUserTasks' 时使用。也接受字符串 'true'/'false'",
    },
    includePipelines: {
      type: z.union([z.boolean(), z.literal("true"), z.literal("false")]).optional(),
      description: "boolean 值，是否包含与当前用户相关的管道，仅在 operation='getCurrentUserTasks' 时使用。也接受字符串 'true'/'false'",
    },
    includeIssues: {
      type: z.union([z.boolean(), z.literal("true"), z.literal("false")]).optional(),
      description: "boolean 值，是否包含分配给当前用户的问题，仅在 operation='getCurrentUserTasks' 时使用。也接受字符串 'true'/'false'",
    },
    fields: {
      type: z.array(z.string()).min(1),
      description: "【必填参数】指定需要返回的字段列表，用于过滤响应数据。支持嵌套路径，例如：['id', 'name', 'user.profile.avatar_url', 'projects[0].name']。如果指定的字段不存在，系统会返回可用字段列表和建议。必须至少提供一个字段。",
    },
  };

  // 创建 API 客户端
  private createApiClient(): AxiosInstance {
    const normalizedBaseUrl = this.normalizeBaseUrl(this.config.baseUrl);
    
    const axiosConfig: AxiosRequestConfig = {
      baseURL: normalizedBaseUrl,
      timeout: this.config.timeout || 10000,
      headers: {
        'Content-Type': 'application/json',
        'PRIVATE-TOKEN': this.config.privateToken
      },
    };
    
    logger.info(`创建 GitLab API 客户端，基础 URL: ${normalizedBaseUrl}`);
    return axios.create(axiosConfig);
  }

  /**
   * 标准化 GitLab 基础 URL
   * 支持多种格式：https://gitlab.com、gitlab.com、gitlab.com/api/v4 等
   */
  private normalizeBaseUrl(url: string): string {
    // 以确保 URL 为 string 的方式开始处理
    let normalizedUrl = String(url).trim();
    
    // 处理空 URL
    if (!normalizedUrl) {
      logger.warn('空的 GitLab URL，使用默认值');
      return 'https://gitlab.com/api/v4';
    }
    
    // 如果不包含协议，添加 https://
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = `https://${normalizedUrl}`;
    }
    
    // 删除末尾的斜杠
    normalizedUrl = normalizedUrl.replace(/\/+$/, '');
    
    // 检测 URL 是否包含 /api/v4 路径并进行处理
    if (!/\/api\/v4(?:\/|$)/.test(normalizedUrl)) {
      // 没有包含 API 路径，添加它
      return `${normalizedUrl}/api/v4`;
    } else {
      // 提取到/api/v4 为止的部分（移除其后的路径）
      const apiPathIndex = normalizedUrl.indexOf('/api/v4');
      return normalizedUrl.substring(0, apiPathIndex + '/api/v4'.length);
    }
  }

  /**
   * 执行 GitLab API 请求
   * 统一处理请求、响应和错误
   */
  private async apiRequest(endpoint: string, method: string = 'GET', params?: Record<string, any>, data?: Record<string, any>): Promise<GitlabApiResponse> {
    try {
      // 确保 endpoint 以/开头
      if (endpoint && !endpoint.startsWith('/')) {
        endpoint = `/${endpoint}`;
      }
      
      logger.info(`执行 GitLab API 请求：${method} ${endpoint}`);
      
      const response = await this.client.request({
        url: endpoint,
        method,
        params,
        data,
      });
      
      // 直接返回数据，不包含元数据
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;
        const statusCode = axiosError.response?.status || 0;
        let errorMessage = `GitLab API 请求失败：${axiosError.message}`;
        
        // 增强错误消息
        if (statusCode === 401) {
          errorMessage = 'GitLab API 认证失败：请检查您的访问令牌是否有效';
        } else if (statusCode === 403) {
          errorMessage = 'GitLab API 权限不足：您没有足够的权限执行此操作';
        } else if (statusCode === 404) {
          errorMessage = `GitLab API 资源未找到：${endpoint} 不存在或无法访问`;
        } else if (statusCode === 429) {
          errorMessage = 'GitLab API 请求过于频繁：已达到速率限制，请稍后重试';
        } else if (statusCode >= 500) {
          errorMessage = 'GitLab API 服务器错误：服务器暂时不可用或存在内部错误';
        }
        
        return {
          error: true,
          status: statusCode,
          message: errorMessage,
          details: axiosError.response?.data || {},
        };
      }
      
      return {
        error: true,
        message: `GitLab API 请求失败：${(error as Error).message}`,
      };
    }
  }

  /**
   * 检查 API 响应是否有效
   */
  private isValidResponse(response: any): boolean {
    // 现在直接检查响应是否有错误标志
    return !(response && response.error === true);
  }

  // ========== 内部辅助方法 ==========
  
  /**
   * 获取当前用户信息
   */
  private async getCurrentUser() {
    return this.apiRequest('/user');
  }

  /**
   * 根据用户名模糊搜索用户
   */
  private async searchUsers(username: string) {
    return this.apiRequest('/users', 'GET', { search: username });
  }

  /**
   * 获取用户活跃项目
   */
  private async getUserProjects(userId: string | number, params?: Record<string, any>) {
    return this.apiRequest(`/users/${userId}/projects`, 'GET', params);
  }
  
  /**
   * 获取项目详情
   */
  private async getProject(projectId: string, params?: Record<string, any>) {
    return this.apiRequest(`/projects/${encodeURIComponent(String(projectId))}`, 'GET', params);
  }
  
  /**
   * 获取项目合并请求列表
   */
  private async getProjectMergeRequests(projectId: string, params?: Record<string, any>) {
    return this.apiRequest(`/projects/${encodeURIComponent(String(projectId))}/merge_requests`, 'GET', params);
  }

  // ========== 公开聚合方法 ==========

  /**
   * 获取当前用户的待办事项聚合信息
   * 包括待处理的合并请求、需要评审的合并请求、分配的问题、运行中的管道等
   */
  private async getCurrentUserTasksImpl(options?: {
    includeAssignedMRs?: boolean | "true" | "false",
    includeReviewMRs?: boolean | "true" | "false",
    includePipelines?: boolean | "true" | "false",
    includeIssues?: boolean | "true" | "false"
  }): Promise<GitlabApiResponse> {
    const tasks: Record<string, any> = {};
    const opts = {
      includeAssignedMRs: true,
      includeReviewMRs: true, 
      includePipelines: true,
      includeIssues: true,
      ...options
    };
    
    // 并行获取数据以提高性能
    const promises = [];
    
    if (opts.includeAssignedMRs) {
      promises.push(
        this.apiRequest('/merge_requests', 'GET', { scope: 'assigned_to_me', state: 'opened' }).then(result => {
          if (!this.isValidResponse(result)) return;
          tasks.assignedMergeRequests = result;
        })
      );
    }
    
    if (opts.includeReviewMRs) {
      promises.push(
        this.apiRequest('/merge_requests', 'GET', { scope: 'to_review' }).then(result => {
          if (!this.isValidResponse(result)) return;
          tasks.reviewMergeRequests = result;
        })
      );
    }
    
    if (opts.includeIssues) {
      promises.push(
        this.apiRequest('/issues', 'GET', { scope: 'assigned_to_me', state: 'opened' }).then(result => {
          if (!this.isValidResponse(result)) return;
          tasks.assignedIssues = result;
        })
      );
    }
    
    // 获取当前用户信息
    const userResult = await this.getCurrentUser();
    if (!this.isValidResponse(userResult)) {
      return {
        error: true,
        message: '获取用户信息失败'
      };
    }

    const userId = userResult.id;
    
    // 获取进行中的管道
    if (opts.includePipelines) {
      promises.push(
        this.apiRequest('/pipelines', 'GET', { scope: 'running', username: userId }).then(result => {
          if (!this.isValidResponse(result)) return;
          tasks.runningPipelines = result;
        })
      );
    }
    
    await Promise.all(promises);
    
    // 只返回数据
    return {
      user: userResult,
      tasks: tasks
    };
  }

  /**
   * 根据用户名查询用户及其活跃项目（聚合方法）
   */
  private async searchUserWithProjectsImpl(username: string): Promise<GitlabApiResponse> {
    const usersResult = await this.searchUsers(username);
    
    if (!this.isValidResponse(usersResult) || !usersResult.length) {
      return {
        error: true,
        message: `未找到匹配用户名 "${username}" 的用户`
      };
    }
    
    // 使用第一个匹配的用户
    const user = usersResult[0];
    const projectsResult = await this.getUserProjects(user.id, {
      order_by: 'last_activity_at',
      sort: 'desc'
    });
    
    if (!this.isValidResponse(projectsResult)) {
      return {
        user: user,
        active_projects: [],
        message: `找到用户 "${username}"，但无法获取项目信息`
      };
    }
    
    // 限制返回最活跃的 10 个项目
    const activeProjects = projectsResult.slice(0, 10);
    
    // 增强项目数据 - 为每个项目添加 MR 和管道摘要信息
    const enhancedProjects = await Promise.all(
      activeProjects.map(async (project: any) => {
        const [mergeRequests, pipelines] = await Promise.all([
          this.getProjectMergeRequests(project.id, { state: 'opened', per_page: 5 }),
          this.apiRequest(`/projects/${project.id}/pipelines`, 'GET', { per_page: 3 })
        ]);
        
        return {
          ...project,
          recent_merge_requests: this.isValidResponse(mergeRequests) ? mergeRequests : [],
          recent_pipelines: this.isValidResponse(pipelines) ? pipelines : []
        };
      })
    );
    
    return {
      user: user,
      active_projects: enhancedProjects,
      message: `成功获取用户 ${username} 及其活跃项目信息`
    };
  }

  /**
   * 根据项目名称模糊搜索并获取详情（聚合方法）
   */
  private async searchProjectWithDetailsImpl(projectName: string): Promise<GitlabApiResponse> {
    const projectsResult = await this.apiRequest('/projects', 'GET', {
      search: projectName,
      order_by: 'last_activity_at',
      sort: 'desc',
      per_page: 5
    });
    
    if (!this.isValidResponse(projectsResult) || !projectsResult.length) {
      return {
        error: true,
        message: `未找到匹配名称 "${projectName}" 的项目`
      };
    }
    
    // 获取第一个匹配项目的详情
    const project = projectsResult[0];
    
    // 并行获取项目的各种信息
    const [
      projectDetails,
      mergeRequests,
      pipelines,
      branches,
      members
    ] = await Promise.all([
      // 项目基本信息
      this.getProject(project.id),
      // 最近的合并请求
      this.getProjectMergeRequests(project.id, { per_page: 5 }),
      // 最近的管道
      this.apiRequest(`/projects/${encodeURIComponent(String(project.id))}/pipelines`, 'GET', { per_page: 5 }),
      // 分支信息
      this.apiRequest(`/projects/${encodeURIComponent(String(project.id))}/repository/branches`, 'GET', { per_page: 10 }),
      // 项目成员
      this.apiRequest(`/projects/${encodeURIComponent(String(project.id))}/members`, 'GET', { per_page: 10 })
    ]);
    
    return {
      search_results: projectsResult,
      details: {
        project: this.isValidResponse(projectDetails) ? projectDetails : project,
        merge_requests: this.isValidResponse(mergeRequests) ? mergeRequests : [],
        pipelines: this.isValidResponse(pipelines) ? pipelines : [],
        branches: this.isValidResponse(branches) ? branches : [],
        members: this.isValidResponse(members) ? members : []
      },
      message: `成功搜索并获取项目 "${projectName}" 的详情信息`
    };
  }

  /**
   * 创建合并请求评论
   */
  private async createMergeRequestComment(projectId: string | number, mergeRequestId: number, comment: string): Promise<GitlabApiResponse> {
    return this.apiRequest(
      `/projects/${encodeURIComponent(String(projectId))}/merge_requests/${mergeRequestId}/notes`,
      'POST',
      undefined,
      { body: comment }
    );
  }

  /**
   * 接受合并请求
   */
  private async acceptMergeRequest(
    projectId: string | number, 
    mergeRequestId: number, 
    options?: {
      mergeCommitMessage?: string,
      squash?: boolean,
      shouldRemoveSourceBranch?: boolean
    }
  ): Promise<GitlabApiResponse> {
    return this.apiRequest(
      `/projects/${encodeURIComponent(String(projectId))}/merge_requests/${mergeRequestId}/merge`,
      'PUT',
      undefined,
      {
        merge_commit_message: options?.mergeCommitMessage,
        squash: options?.squash,
        should_remove_source_branch: options?.shouldRemoveSourceBranch
      }
    );
  }

  /**
   * 验证操作参数
   * @param params 需要验证的参数
   * @param requiredParams 必须存在的参数名及其对应错误消息
   * @returns 如果验证失败返回错误响应，否则返回 null
   */
  private validateParams(params: Record<string, any>, requiredParams: Record<string, string>): GitlabApiResponse | null {
    for (const [param, errorMsg] of Object.entries(requiredParams)) {
      if (!params[param]) {
        return {
          error: true,
          message: errorMsg
        };
      }
    }
    return null;
  }

  /**
   * 过滤 API 响应数据，只返回请求的字段
   * @param data 原始 API 响应数据
   * @param fields 请求的字段路径列表
   * @returns 过滤后的数据或错误信息
   */
  private filterResponseFields(data: any, fields: string[]): any {
    if (!data || !fields || fields.length === 0) {
      return data;
    }
    
    // 记录有效字段和无效字段
    const validFields: string[] = [];
    const invalidFields: string[] = [];
    
    // 尝试从响应中提取字段
    const result = this.pickFieldsWithPaths(data, fields);
    
    // 验证哪些字段存在，哪些不存在
    for (const field of fields) {
      if (get(result, field) !== undefined) {
        validFields.push(field);
      } else {
        invalidFields.push(field);
      }
    }
    
    // 记录结果，便于调试
    logger.debug(`有效字段：${validFields.join(', ')}`);
    if (invalidFields.length > 0) {
      logger.debug(`无效字段：${invalidFields.join(', ')}`);
    }
    
    // 如果有任何字段找不到，生成友好的错误信息
    if (invalidFields.length > 0 && validFields.length === 0) {
      // 收集路径信息，用于建议
      const { allPaths, suggestedPaths } = this.collectPathInfo(data);
      
      const availableTopLevelFields = typeof data === 'object' && data !== null
        ? Object.keys(data)
        : [];
      
      // 增强的错误信息
      return {
        filtered: true,
        error: `请求的字段路径不存在：${invalidFields.join(', ')}`,
        valid_fields: validFields,
        invalid_fields: invalidFields,
        available_top_level_fields: availableTopLevelFields,
        suggested_paths: suggestedPaths.length > 0 
          ? suggestedPaths 
          : allPaths.slice(0, 20) // 如果没有建议路径，展示前 20 个所有路径
      };
    }
    
    // 如果只找到了部分字段，但不是所有字段
    if (invalidFields.length > 0 && validFields.length > 0) {
      // 我们找到了部分字段，可以继续使用这些有效字段
      logger.warn(`部分字段未找到：${invalidFields.join(', ')}`);
      
      // 如果找到的字段很少，可以提供建议
      if (validFields.length < fields.length / 2) {
        const { suggestedPaths } = this.collectPathInfo(data);
        logger.debug(`建议尝试字段: ${suggestedPaths.slice(0, 10).join(', ')}`);
      }
    }
    
    // 优化结果结构：如果结果只有一个顶层键且这个键不是原始字段
    // 则将其内容提升到顶层，使返回更扁平
    if (typeof result === 'object' && result !== null) {
      const resultKeys = Object.keys(result);
      if (resultKeys.length === 1 && !fields.includes(resultKeys[0])) {
        const singleKey = resultKeys[0];
        // 检查是否具有多级嵌套而不是简单对象
        const value = result[singleKey];
        
        // 只有当值是复杂对象时才扁平化
        if (typeof value === 'object' && value !== null && Object.keys(value).length > 0) {
          return value;
        }
      }
    }
    
    return result;
  }

  /**
   * 收集对象中的路径信息，优化版
   * @param obj 要分析的对象
   * @returns 所有路径和建议路径
   */
  private collectPathInfo(obj: any): { allPaths: string[], suggestedPaths: string[] } {
    const allPaths: string[] = [];
    const suggestedPaths: string[] = [];
    
    // 用于缓存已访问路径，避免循环引用问题
    const visited = new WeakSet();
    
    /**
     * 递归分析对象路径
     */
    const analyze = (value: any, path: string, depth: number) => {
      // 避免过深递归或循环引用
      if (depth > 3 || !value || typeof value !== 'object' || visited.has(value)) {
        return;
      }
      
      visited.add(value);
      
      const isArray = Array.isArray(value);
      
      // 对于数组，限制只分析前几个元素
      const keys = isArray 
        ? value.length > 5 ? [...Array(3).keys()] : [...Array(value.length).keys()]
        : Object.keys(value);
        
      for (const key of keys) {
        const currentPath = path 
          ? (isArray ? `${path}[${key}]` : `${path}.${key}`)
          : String(key);
        
        allPaths.push(currentPath);
        
        // 只将较浅层的路径添加为建议
        if (depth <= 1) {
          suggestedPaths.push(currentPath);
        }
        
        // 递归处理嵌套结构
        const childValue = value[key];
        if (childValue && typeof childValue === 'object') {
          analyze(childValue, currentPath, depth + 1);
        }
      }
    };
    
    // 从根对象开始分析
    analyze(obj, '', 0);
    
    return { allPaths, suggestedPaths };
  }

  /**
   * 从对象中提取指定路径的字段（简化版）
   */
  private pickFieldsWithPaths(obj: Record<string, any>, paths: string[]): Record<string, any> {
    const result: Record<string, any> = {};
    
    for (const path of paths) {
      try {
        // 使用 lodash 的 get 和 set 保持原始路径结构
        const value = get(obj, path);
        if (value !== undefined) {
          set(result, path, value);
        }
      } catch (e) {
        // 忽略无效路径
        continue;
      }
    }
    
    return result;
  }

  /**
   * 压缩和格式化 Zod 验证错误
   * @param error Zod 验证错误
   * @returns 压缩后的错误消息
   */
  private formatZodError(error: z.ZodError): string {
    // 将错误扁平化并格式化为一个简洁的消息
    const errorMap = error.flatten().fieldErrors;
    const messages: string[] = [];
    
    // 处理各个字段的错误
    for (const [field, fieldErrors] of Object.entries(errorMap)) {
      if (fieldErrors && fieldErrors.length > 0) {
        messages.push(`${field}: ${fieldErrors[0]}`);
      }
    }
    
    return messages.length > 0 
      ? `参数验证失败：${messages.join('; ')}` 
      : '参数验证失败';
  }

  /**
   * 将字符串 "true"/"false" 转换为布尔值
   */
  private toBooleanValue(value: any): boolean | undefined {
    if (value === undefined) return undefined;
    if (typeof value === 'boolean') return value;
    if (value === 'true') return true;
    if (value === 'false') return false;
    return Boolean(value); // 兜底转换
  }

  /**
   * 根据操作类型获取字段映射关系
   * 用于将用户提供的简单字段名映射到实际的嵌套路径
   */
  private getFieldMappings(operation: string): Record<string, string> {
    // 基本字段映射 - 适用于所有操作类型
    const baseMapping: Record<string, string> = {
      // 通用属性
      'id': 'id',
      'name': 'name',
      'description': 'description',
      'created_at': 'created_at',
      'updated_at': 'updated_at'
    };
    
    // 根据操作类型返回特定映射
    switch (operation) {
      case 'searchUserWithProjects':
        return {
          ...baseMapping,
          // 用户相关
          'id': 'user.id', // 优先映射到用户 ID
          'name': 'user.name', // 优先映射到用户名称
          'username': 'user.username',
          'email': 'user.email',
          'avatar_url': 'user.avatar_url',
          'bio': 'user.bio',
          'state': 'user.state',
          'web_url': 'user.web_url',
          // 项目相关
          'projects': 'active_projects',
          'project_count': 'active_projects.length',
          'project_names': 'active_projects[*].name', // 特殊语法用于表示数组中所有元素的同一属性
          'project_urls': 'active_projects[*].web_url',
          // 某些常用组合
          'user_info': 'user',
        };
      
      case 'searchProjectWithDetails':
        return {
          ...baseMapping,
          // 项目基本信息
          'id': 'details.project.id', // 优先映射到项目 ID
          'name': 'details.project.name', // 优先映射到项目名称
          'description': 'details.project.description', // 优先映射到项目描述
          'project_id': 'details.project.id',
          'project_name': 'details.project.name', 
          'project_description': 'details.project.description',
          'project_url': 'details.project.web_url',
          'path': 'details.project.path',
          'path_with_namespace': 'details.project.path_with_namespace',
          'visibility': 'details.project.visibility',
          // 分支信息
          'branches': 'details.branches',
          'branch_names': 'details.branches[*].name',
          'default_branch': 'details.project.default_branch',
          // 成员信息
          'members': 'details.members',
          'member_names': 'details.members[*].name',
          'member_usernames': 'details.members[*].username',
          // 合并请求
          'merge_requests': 'details.merge_requests',
          'open_merge_requests': 'details.merge_requests',
          'mr_titles': 'details.merge_requests[*].title',
          // 管道
          'pipelines': 'details.pipelines',
          'pipeline_statuses': 'details.pipelines[*].status',
          // 搜索结果
          'search_results': 'search_results',
          // 组合信息
          'project_info': 'details.project',
        };
      
      case 'getCurrentUserTasks':
        return {
          ...baseMapping,
          // 用户信息 - 添加对顶层字段的映射
          'id': 'user.id', // 映射简单 id 到 user.id
          'name': 'user.name', // 映射简单 name 到 user.name
          'username': 'user.username',
          'email': 'user.email',
          'avatar_url': 'user.avatar_url',
          'user_url': 'user.web_url',
          // 任务汇总
          'assigned_mrs': 'tasks.assignedMergeRequests',
          'review_mrs': 'tasks.reviewMergeRequests',
          'issues': 'tasks.assignedIssues',
          'pipelines': 'tasks.runningPipelines',
          // 详细信息
          'mr_titles': 'tasks.assignedMergeRequests[*].title',
          'mr_urls': 'tasks.assignedMergeRequests[*].web_url',
          'issue_titles': 'tasks.assignedIssues[*].title',
          'issue_urls': 'tasks.assignedIssues[*].web_url',
          // 组合信息
          'user_info': 'user',
          'tasks_summary': 'tasks',
        };
      
      // 其他操作类型根据需要添加
      case 'createMRComment':
      case 'acceptMR':
      case 'raw':
      default:
        return baseMapping;
    }
  }

  /**
   * 预处理字段路径，将简单字段名替换为实际嵌套路径
   * @param operation 操作类型
   * @param fields 用户提供的字段列表
   * @returns 处理后的字段路径列表
   */
  private preprocessFieldPaths(operation: string, fields: string[]): string[] {
    // 获取当前操作的字段映射
    const fieldMappings = this.getFieldMappings(operation);
    const processedFields: string[] = [];
    
    // 处理每个字段
    for (const field of fields) {
      // 如果是完整路径 (包含 . 或 [)，假设用户提供了完整路径，保持不变
      if (field.includes('.') || field.includes('[')) {
        processedFields.push(field);
        continue;
      }
      
      // 如果存在映射，使用映射的路径
      if (fieldMappings[field]) {
        const mappedPath = fieldMappings[field];
        
        // 处理特殊的数组映射语法 [*]
        if (mappedPath.includes('[*]')) {
          // 将 [*] 替换为 [0], [1] 等具体索引，这里我们取前 5 个元素
          for (let i = 0; i < 5; i++) {
            const specificPath = mappedPath.replace(/\[\*\]/g, `[${i}]`);
            processedFields.push(specificPath);
          }
        } else {
          processedFields.push(mappedPath);
        }
      } else {
        // 如果找不到映射，尝试基于操作类型添加多个可能的路径
        const guessedPaths = this.guessFieldPaths(operation, field);
        processedFields.push(...guessedPaths);
      }
    }
    
    // 记录调试信息
    logger.debug(`原始字段 ${JSON.stringify(fields)} 预处理后: ${JSON.stringify([...new Set(processedFields)])}`);
    
    // 返回去重后的字段列表
    return [...new Set(processedFields)];
  }

  /**
   * 猜测可能的字段路径，用于处理未在映射表中的字段
   */
  private guessFieldPaths(operation: string, field: string): string[] {
    const guessedPaths: string[] = [field]; // 始终包含原始字段名
    
    switch (operation) {
      case 'searchUserWithProjects':
        guessedPaths.push(`user.${field}`);
        guessedPaths.push(`active_projects[0].${field}`);
        break;
      
      case 'searchProjectWithDetails':
        guessedPaths.push(`details.project.${field}`);
        guessedPaths.push(`search_results[0].${field}`);
        guessedPaths.push(`details.members[0].${field}`);
        break;
      
      case 'getCurrentUserTasks':
        // 始终尝试获取user对象下的字段
        guessedPaths.push(`user.${field}`);
        // 尝试获取任务数据中的字段
        guessedPaths.push(`tasks.${field}`);
        // 尝试具体任务类型的第一个元素中的字段
        guessedPaths.push(`tasks.assignedMergeRequests[0].${field}`);
        guessedPaths.push(`tasks.reviewMergeRequests[0].${field}`);
        guessedPaths.push(`tasks.assignedIssues[0].${field}`);
        guessedPaths.push(`tasks.runningPipelines[0].${field}`);
        break;
    }
    
    return guessedPaths;
  }

  // 执行方法 - 工具统一入口
  async execute(input: GitlabRestfulApiInput): Promise<GitlabApiResponse> {
    try {
      // 确保 fields 参数存在且有效
      if (!input.fields || input.fields.length === 0) {
        return {
          error: true,
          message: '缺少必填参数 fields。请指定至少一个要返回的字段，例如：fields: ["id", "name"]'
        };
      }

      // 预处理布尔值字段，处理可能的字符串形式
      if (typeof input.includeAssignedMRs === 'string') {
        (input as any).includeAssignedMRs = this.toBooleanValue(input.includeAssignedMRs);
      }
      if (typeof input.includeReviewMRs === 'string') {
        (input as any).includeReviewMRs = this.toBooleanValue(input.includeReviewMRs);
      }
      if (typeof input.includePipelines === 'string') {
        (input as any).includePipelines = this.toBooleanValue(input.includePipelines);
      }
      if (typeof input.includeIssues === 'string') {
        (input as any).includeIssues = this.toBooleanValue(input.includeIssues);
      }
      
      // 兼容性处理 - 对非标准操作名称进行转换
      const operation = this.normalizeOperation(input.operation);
      
      // 处理 API 调用和返回结果过滤
      let result;
      
      // 原始 API 调用 - 兜底方案
      if (operation === 'raw') {
        const validationError = this.validateParams(input, {
          endpoint: '使用原始 API 调用时必须提供 endpoint 参数，例如：{operation: "raw", endpoint: "/projects"}'
        });
        if (validationError) return validationError;
        
        result = await this.apiRequest(input.endpoint!, input.method, input.params, input.data);
      }
      
      // 用户待办任务查询
      else if (operation === 'getCurrentUserTasks') {
        result = await this.getCurrentUserTasksImpl({
          includeAssignedMRs: input.includeAssignedMRs,
          includeReviewMRs: input.includeReviewMRs,
          includePipelines: input.includePipelines,
          includeIssues: input.includeIssues
        });
      }
      
      // 用户查询及项目信息
      else if (operation === 'searchUserWithProjects') {
        const validationError = this.validateParams(input, {
          username: '搜索用户时必须提供 username 参数，例如：{operation: "searchUserWithProjects", username: "张三"}'
        });
        if (validationError) return validationError;
        
        result = await this.searchUserWithProjectsImpl(input.username!);
      }
      
      // 项目搜索及详情查询
      else if (operation === 'searchProjectWithDetails') {
        const validationError = this.validateParams(input, {
          projectName: '搜索项目时必须提供 projectName 参数，例如：{operation: "searchProjectWithDetails", projectName: "前端项目"}'
        });
        if (validationError) return validationError;
        
        result = await this.searchProjectWithDetailsImpl(input.projectName!);
      }
      
      // 创建合并请求评论
      else if (operation === 'createMRComment') {
        const validationError = this.validateParams(input, {
          projectId: '创建评论时必须提供 projectId 参数',
          mergeRequestId: '创建评论时必须提供 mergeRequestId 参数',
          comment: '创建评论时必须提供 comment 参数'
        });
        if (validationError) return validationError;
        
        result = await this.createMergeRequestComment(input.projectId!, input.mergeRequestId!, input.comment!);
      }
      
      // 接受合并请求
      else if (operation === 'acceptMR') {
        const validationError = this.validateParams(input, {
          projectId: '接受合并请求时必须提供 projectId 参数',
          mergeRequestId: '接受合并请求时必须提供 mergeRequestId 参数'
        });
        if (validationError) return validationError;
        
        result = await this.acceptMergeRequest(input.projectId!, input.mergeRequestId!, input.mergeOptions);
      }
      
      // 操作类型无法识别
      else {
        const availableOperations = [
          'raw', 
          'getCurrentUserTasks', 
          'searchUserWithProjects', 
          'searchProjectWithDetails', 
          'createMRComment', 
          'acceptMR'
        ];

        return {
          error: true,
          message: `无效的操作类型："${input.operation}"，可用的操作有：${availableOperations.join(', ')}`,
          availableOperations,
          examples: this.examples
        };
      }
      
      // 检查响应是否有错误
      if (result && result.error) {
        return result; // 有错误，直接返回错误信息
      }

      // 记录原始响应结构的顶层字段，方便调试
      const resultKeys = typeof result === 'object' && result !== null ? Object.keys(result) : [];
      logger.debug(`响应数据顶层字段：${JSON.stringify(resultKeys)}`);
      
      // 针对特定操作，智能添加必要但缺失的字段
      const smartFields = this.addSmartFields(operation, input.fields);
      if (smartFields.length > input.fields.length) {
        logger.debug(`智能添加字段：${JSON.stringify(smartFields.filter(f => !input.fields.includes(f)))}`);
      }
      
      // 对用户提供的字段进行预处理，添加适当的前缀路径
      const processedFields = this.preprocessFieldPaths(operation, smartFields);
      
      // 记录原始字段和处理后的字段，便于调试
      logger.debug(`原始字段：${JSON.stringify(input.fields)}`);
      logger.debug(`智能补充后字段：${JSON.stringify(smartFields)}`);
      logger.debug(`处理后字段：${JSON.stringify(processedFields)}`);
      
      // 应用字段过滤 - 使用处理后的字段路径
      const filteredData = this.filterResponseFields(result, processedFields);
      
      // 如果返回了过滤错误信息
      if (filteredData?.filtered) {
        return {
          error: true,
          message: `字段过滤失败：${filteredData.error}`,
          fieldsInfo: {
            requestedFields: input.fields, // 保留原始请求字段，便于用户理解
            processedFields: processedFields, // 添加处理后的字段，便于调试
            availableFields: filteredData.available_top_level_fields || [],
            suggestedPaths: filteredData.suggested_paths || [],
            missingFields: filteredData.error.split('：')[1]?.split(', ') || [],
            message: `部分请求的字段路径不存在。` +
                    `可用的顶层字段：${(filteredData.available_top_level_fields || []).join(', ')}。` +
                    `建议尝试：${(filteredData.suggested_paths || []).slice(0, 10).join(', ')}`
          }
        };
      } else {
        // 成功过滤，返回过滤后的数据
        return filteredData;
      }
    } catch (error) {
      // 处理 Zod 验证错误
      if (error instanceof z.ZodError) {
        return {
          error: true,
          message: this.formatZodError(error),
          details: error.flatten()
        };
      }
      
      // 处理其他类型的错误
      return {
        error: true,
        message: `执行失败：${(error as Error).message}`,
      };
    }
  }

  /**
   * 对操作类型进行标准化处理
   * 支持常见别名和拼写错误
   */
  private normalizeOperation(operation: string): string {
    if (!operation) return 'raw';
    
    const opMap: Record<string, string> = {
      // 用户搜索相关
      'searchuser': 'searchUserWithProjects',
      'finduser': 'searchUserWithProjects',
      'getuser': 'searchUserWithProjects',
      'user': 'searchUserWithProjects',
      
      // 任务相关
      'getusertasks': 'getCurrentUserTasks',
      'tasks': 'getCurrentUserTasks',
      'mytasks': 'getCurrentUserTasks',
      'gettasks': 'getCurrentUserTasks',
      
      // 项目相关
      'searchproject': 'searchProjectWithDetails',
      'findproject': 'searchProjectWithDetails',
      'getproject': 'searchProjectWithDetails',
      'project': 'searchProjectWithDetails',
      
      // 评论相关
      'comment': 'createMRComment',
      'addcomment': 'createMRComment',
      'commentmr': 'createMRComment',
      'createcomment': 'createMRComment',
      
      // 合并相关
      'merge': 'acceptMR',
      'mergemr': 'acceptMR',
      'acceptmerge': 'acceptMR',
      'approve': 'acceptMR'
    };
    
    // 尝试完全匹配
    const opLower = operation.toLowerCase();
    if (opMap[opLower]) {
      return opMap[opLower];
    }
    
    // 检查是否是标准操作类型
    const standardOps = [
      'raw', 
      'getCurrentUserTasks', 
      'searchUserWithProjects', 
      'searchProjectWithDetails', 
      'createMRComment', 
      'acceptMR'
    ];
    
    // 如果已经是标准操作类型，直接返回
    if (standardOps.includes(operation)) {
      return operation;
    }
    
    // 否则默认为 raw 操作
    logger.warn(`未识别的操作类型："${operation}"，将使用 raw 操作`);
    return 'raw';
  }

  /**
   * 智能添加必要的字段
   * 针对特定操作，会自动添加一些常用字段，提高用户体验
   */
  private addSmartFields(operation: string, fields: string[]): string[] {
    // 复制原始字段列表
    const smartFields = [...fields];
    
    // 检查是否已有明确的嵌套路径
    const hasNestedPath = fields.some(f => f.includes('.') || f.includes('['));
    
    // 如果已经有嵌套路径，说明用户知道路径结构，不需要智能补充
    if (hasNestedPath) {
      return smartFields;
    }
    
    // 根据操作类型添加默认重要字段
    switch (operation) {
      case 'getCurrentUserTasks':
        // 如果只有简单字段如 'id'，同时确保添加 'user.id' 等常见路径
        if (fields.includes('id') && !fields.includes('user.id')) {
          smartFields.push('user.id');
        }
        if (fields.includes('name') && !fields.includes('user.name')) {
          smartFields.push('user.name');
        }
        // 其他常见字段也可以类似处理
        break;
        
      case 'searchUserWithProjects':
        if (fields.includes('id') && !fields.includes('user.id')) {
          smartFields.push('user.id');
        }
        if (fields.includes('name') && !fields.includes('user.name')) {
          smartFields.push('user.name');
        }
        break;
        
      case 'searchProjectWithDetails':
        if (fields.includes('id') && !fields.includes('details.project.id')) {
          smartFields.push('details.project.id');
        }
        if (fields.includes('name') && !fields.includes('details.project.name')) {
          smartFields.push('details.project.name');
        }
        break;
    }
    
    return smartFields;
  }

  /**
   * 测试字段处理逻辑（仅限开发环境使用）
   * @param operation 操作类型
   * @param fields 需要处理的字段列表
   * @returns 处理结果
   */
  testFieldProcessing(operation: string, fields: string[]): Record<string, any> {
    try {
      // 1. 标准化操作类型
      const normalizedOperation = this.normalizeOperation(operation);
      
      // 2. 获取该操作的字段映射
      const mappings = this.getFieldMappings(normalizedOperation);
      
      // 3. 智能添加字段
      const smartFields = this.addSmartFields(normalizedOperation, fields);
      
      // 4. 预处理字段路径
      const processedFields = this.preprocessFieldPaths(normalizedOperation, smartFields);
      
      return {
        normalizedOperation,
        originalFields: fields,
        smartFields,
        processedFields,
        mappings
      };
    } catch (error) {
      return {
        error: true,
        message: (error as Error).message
      };
    }
  }
}

export default GitlabRestfulApiTool;