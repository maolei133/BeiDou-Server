import axios from 'axios';

const API_BASE = '/logsystem';

// 通用响应类型
export interface ApiResponse<T> {
  code: number;
  message: string;
  data: T;
  timestamp: number;
}

// 日志查询相关类型
export interface LogQueryRequest {
  keyword?: string;
  startDate?: string;
  endDate?: string;
  category?: string;
  level?: string;
  pageNum?: number;
  pageSize?: number;
  sortField?: string;
  sortOrder?: string;
}

export interface LogRecord {
  id: string;
  timestamp: string;
  category: string;
  level: string;
  message: string;
  details?: string;
}

export interface LogQueryResult {
  success: boolean;
  message?: string;
  records: LogRecord[];
  totalCount: number;
  pageNum: number;
  pageSize: number;
  totalPages: number;
}

export interface LogStatistics {
  totalCount: number;
  categoryStats: Record<string, number>;
  levelStats: Record<string, number>;
  timeRangeStats: Array<{ time: string; count: number }>;
}

// 仪表板相关类型
export interface DashboardMetrics {
  totalLogs: number;
  todayLogs: number;
  averageLogsPerSecond: number;
  alertsToday: number;
  unresolvedAlerts: number;
}

export interface DashboardOverview {
  metrics: DashboardMetrics;
  todayTrend: Record<string, any>;
  systemHealth: Record<string, any>;
  categoryStats: Record<string, number>;
  timestamp: string;
}

// 配置相关类型
export interface LogConfig {
  enabled: boolean;
  logDir: string;
  logRetentionDays: number;
  maxLogFileSize: number;
  compressionEnabled: boolean;
  compressionFormat: string;
  highFreqBufferSize: number;
  highFreqFlushInterval: number;
  mediumFreqBufferSize: number;
  mediumFreqFlushInterval: number;
  lowFreqBufferSize: number;
  asyncThreadPoolSize: number;
  asyncQueueSize: number;
}

export interface PacketLogConfig {
  enabled: boolean;
  logOutgoing: boolean;
  logIncoming: boolean;
  inBlockList: number[];
  outBlockList: number[];
  inBlockListSize: number;
  outBlockListSize: number;
}

// 备份相关类型
export interface BackupMetadata {
  backupId: string;
  backupType: string;
  status: string;
  startTime: string;
  endTime?: string;
  fileCount: number;
  totalSize: number;
  compressedSize: number;
  compressionRatio: number;
  reason: string;
}

export interface BackupStrategy {
  fullBackupEnabled: boolean;
  fullBackupSchedule: string;
  incrementalBackupEnabled: boolean;
  incrementalBackupSchedule: string;
  retentionDays: number;
  compressionEnabled: boolean;
  autoCleanupEnabled: boolean;
}

// 监控相关类型
export interface PerformanceRank {
  category: string;
  value: number;
  percentage: number;
}

export interface PerformanceTrend {
  category: string;
  metricType: string;
  dataPoints: Array<{ timestamp: string; value: number }>;
}

// ========== API 方法 ==========

// 日志查询 API
export const logQueryApi = {
  // 查询日志
  query: (request: LogQueryRequest) =>
    axios.post<ApiResponse<LogQueryResult>>(`${API_BASE}/logs/query`, request, {
      transformRequest: [(data) => JSON.stringify(data)],
    }),

  // 导出CSV
  exportCsv: (request: LogQueryRequest) =>
    axios.post<ApiResponse<string>>(`${API_BASE}/logs/export/csv`, request, {
      transformRequest: [(data) => JSON.stringify(data)],
    }),

  // 获取统计信息
  getStatistics: (request: LogQueryRequest) =>
    axios.post<ApiResponse<LogStatistics>>(
      `${API_BASE}/logs/statistics`,
      request,
      {
        transformRequest: [(data) => JSON.stringify(data)],
      }
    ),

  // 快速搜索
  search: (keyword: string, pageNum = 1, pageSize = 20) =>
    axios.get<ApiResponse<LogQueryResult>>(`${API_BASE}/logs/search`, {
      params: { keyword, pageNum, pageSize },
    }),
};

// 仪表板 API
export const dashboardApi = {
  // 获取仪表板总览
  getOverview: () =>
    axios.get<ApiResponse<DashboardOverview>>(`${API_BASE}/dashboard/overview`),

  // 获取小部件数据
  getWidgets: (widgetType = 'all') =>
    axios.get<ApiResponse<any>>(`${API_BASE}/dashboard/widgets`, {
      params: { widgetType },
    }),

  // 获取报告列表
  getReports: () =>
    axios.get<ApiResponse<any>>(`${API_BASE}/dashboard/reports`),

  // 生成报告
  generateReport: (reportData: any) =>
    axios.post<ApiResponse<any>>(`${API_BASE}/dashboard/reports`, reportData, {
      transformRequest: [(data) => JSON.stringify(data)],
    }),

  // 获取报告详情
  getReportDetail: (reportId: string) =>
    axios.get<ApiResponse<any>>(`${API_BASE}/dashboard/reports/${reportId}`),

  // 删除报告
  deleteReport: (reportId: string) =>
    axios.delete<ApiResponse<boolean>>(
      `${API_BASE}/dashboard/reports/${reportId}`
    ),
};

// 配置 API
export const configApi = {
  // 获取日志配置
  getLogConfig: () =>
    axios.get<ApiResponse<LogConfig>>(`${API_BASE}/config/log`),

  // 更新日志配置
  updateLogConfig: (config: Partial<LogConfig>) =>
    axios.put<ApiResponse<boolean>>(`${API_BASE}/config/log`, config, {
      transformRequest: [(data) => JSON.stringify(data)],
    }),

  // 获取网络包配置
  getPacketConfig: () =>
    axios.get<ApiResponse<PacketLogConfig>>(`${API_BASE}/config/packet`),

  // 添加入站网络包屏蔽
  addInBlockPacket: (opcode: number) =>
    axios.post<ApiResponse<boolean>>(
      `${API_BASE}/config/packet/in-block/${opcode}`
    ),

  // 删除入站网络包屏蔽
  deleteInBlockPacket: (opcode: number) =>
    axios.delete<ApiResponse<boolean>>(
      `${API_BASE}/config/packet/in-block/${opcode}`
    ),

  // 添加出站网络包屏蔽
  addOutBlockPacket: (opcode: number) =>
    axios.post<ApiResponse<boolean>>(
      `${API_BASE}/config/packet/out-block/${opcode}`
    ),

  // 删除出站网络包屏蔽
  deleteOutBlockPacket: (opcode: number) =>
    axios.delete<ApiResponse<boolean>>(
      `${API_BASE}/config/packet/out-block/${opcode}`
    ),

  // 清空所有网络包屏蔽
  clearPacketBlocks: () =>
    axios.delete<ApiResponse<boolean>>(
      `${API_BASE}/config/packet/clear-blocks`
    ),

  // 获取配置总览
  getConfigOverview: () =>
    axios.get<ApiResponse<any>>(`${API_BASE}/config/overview`),
};

// 备份 API
export const backupApi = {
  // 获取备份列表
  getAllBackups: () =>
    axios.get<ApiResponse<BackupMetadata[]>>(`${API_BASE}/backup/list`),

  // 创建备份
  createBackup: (request: any) =>
    axios.post<ApiResponse<any>>(`${API_BASE}/backup/create`, request, {
      transformRequest: [(data) => JSON.stringify(data)],
    }),

  // 恢复备份
  restoreBackup: (request: any) =>
    axios.post<ApiResponse<boolean>>(`${API_BASE}/backup/restore`, request, {
      transformRequest: [(data) => JSON.stringify(data)],
    }),

  // 删除备份
  deleteBackup: (backupPath: string) =>
    axios.delete<ApiResponse<boolean>>(`${API_BASE}/backup`, {
      params: { backupPath },
    }),

  // 获取备份状态
  getBackupStatus: () =>
    axios.get<ApiResponse<any>>(`${API_BASE}/backup/status`),
};

// 监控 API
export const monitorApi = {
  // 获取性能概览
  getPerformanceOverview: () =>
    axios.get<ApiResponse<any>>(`${API_BASE}/monitor/performance`),

  // 获取QPS排行
  getQpsRanking: (limit = 10) =>
    axios.get<ApiResponse<PerformanceRank[]>>(
      `${API_BASE}/monitor/ranking/qps`,
      { params: { limit } }
    ),

  // 获取延迟排行
  getLatencyRanking: (limit = 10) =>
    axios.get<ApiResponse<PerformanceRank[]>>(
      `${API_BASE}/monitor/ranking/latency`,
      { params: { limit } }
    ),

  // 获取成功率排行
  getSuccessRateRanking: (limit = 10) =>
    axios.get<ApiResponse<PerformanceRank[]>>(
      `${API_BASE}/monitor/ranking/success-rate`,
      { params: { limit } }
    ),

  // 获取性能趋势
  getPerformanceTrend: (category?: string, metricType = 'QPS', hours = 24) =>
    axios.get<ApiResponse<PerformanceTrend>>(
      `${API_BASE}/monitor/performance/trend`,
      { params: { category, metricType, hours } }
    ),

  // 获取队列监控数据
  getQueueMonitorData: () =>
    axios.get<ApiResponse<any>>(`${API_BASE}/monitor/queue`),

  // 获取上下文监控数据
  getContextMonitorData: () =>
    axios.get<ApiResponse<any>>(`${API_BASE}/monitor/context`),

  // 获取异常检测数据
  getAnomalyDetectionData: () =>
    axios.get<ApiResponse<any>>(`${API_BASE}/monitor/anomalies`),

  // 获取告警规则列表
  getAlertRules: () =>
    axios.get<ApiResponse<any[]>>(`${API_BASE}/monitor/alert-rules`),

  // 添加告警规则
  addAlertRule: (rule: any) =>
    axios.post<ApiResponse<boolean>>(`${API_BASE}/monitor/alert-rules`, rule),

  // 删除告警规则
  deleteAlertRule: (ruleId: string) =>
    axios.delete<ApiResponse<boolean>>(
      `${API_BASE}/monitor/alert-rules/${ruleId}`
    ),

  // 获取系统健康状况
  getSystemHealth: () =>
    axios.get<ApiResponse<any>>(`${API_BASE}/monitor/health`),
};

// 用户数据缓存 API
export const userDataApi = {
  // 获取所有缓存数据
  getAllData: () => axios.get<ApiResponse<any>>(`${API_BASE}/userdata`),

  // 获取账号列表
  getAccounts: () =>
    axios.get<ApiResponse<any[]>>(`${API_BASE}/userdata/accounts`),

  // 获取角色列表
  getCharacters: () =>
    axios.get<ApiResponse<any[]>>(`${API_BASE}/userdata/characters`),

  // 获取职业列表
  getJobs: () => axios.get<ApiResponse<any[]>>(`${API_BASE}/userdata/jobs`),

  // 获取地图列表
  getMaps: () => axios.get<ApiResponse<any[]>>(`${API_BASE}/userdata/maps`),

  // 刷新缓存
  refresh: () =>
    axios.post<ApiResponse<boolean>>(`${API_BASE}/userdata/refresh`),
};
