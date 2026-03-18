import axios from 'axios';

// =============================
// V1 - 日志查询相关
// =============================

/**
 * @zh-CN 物品流转日志查询参数
 * @en-US Parameters for querying item trace logs
 */
export interface TraceabilityQuery {
  pageNumber?: number;
  pageSize?: number;
  uid?: string; // [FIXED] Changed from number to string to support 64-bit Long values
  itemId?: number;
  characterId?: number;
  actionType?: string;
  actionSource?: string;
  startTime?: number;
  endTime?: number;
}

/**
 * @zh-CN 物品流转日志记录
 * @en-US Item trace log record
 */
export interface TraceLog {
  uid: string; // [FIXED] Changed from number to string to match backend serialization
  itemId: number;
  itemName: string;
  characterId: number;
  characterName: string;
  mapId: number;
  mapName: string;
  actionType: string;
  actionSource: string;
  quantityChange: number;
  itemSnapshot: string; // JSON string
  timestamp: number;
  targetInfo?: string;
  memo?: string;
}

/**
 * @zh-CN 分页响应体
 * @en-US Paginated response body
 */
export interface PagedResponse<T> {
  records: T[];
  totalRow: number;
  totalPage: number;
  pageNumber: number;
  pageSize: number;
}

/**
 * @zh-CN 行为类型DTO
 * @en-US Action Type DTO
 */
export interface ActionTypeDTO {
  value: string;
  label: string;
}

/**
 * (V1) 根据条件查询物品流转日志
 * @param params 查询参数
 */
export function queryTraceLogs(params: TraceabilityQuery) {
  return axios.get<PagedResponse<TraceLog>>('/v1/traceability/logs', {
    params,
  });
}

// =============================
// V2 - 新增API
// =============================

export interface TraceabilityRules {
  // 这里可以根据后端的 POJO 定义详细的类型
  // 为了快速修复，暂时使用 any
  [key: string]: any;
}

/**
 * (V2) 获取溯源配置
 */
export function getTraceabilityConfig(params?: { useDefault: boolean }) {
  return axios.get<TraceabilityRules>('/v1/traceability/config', { params });
}

/**
 * (V2) 更新溯源配置
 * @param config 完整的配置JSON对象
 */
export function updateTraceabilityConfig(config: any) {
  return axios.put('/v1/traceability/config', config);
}

/**
 * (V2) 获取状态看板的统计数据
 */
export function getTraceabilityStats() {
  return axios.get('/v1/traceability/stats');
}
