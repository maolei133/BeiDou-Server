import axios from 'axios';
import type { HttpResponse } from './interceptor';

export interface LogQueryParams {
  majorCategory?: string;
  minorCategory?: string;
  startDate?: string;
  endDate?: string;
  keyword?: string;
}

export interface LogCategory {
  id: string;
  name: string;
}

/**
 * 查询日志
 * @param params 查询参数
 */
export function queryLogs(params: LogQueryParams) {
  return axios.get<HttpResponse<string[]>>('/api/logs/query', { params });
}

/**
 * 获取所有大类
 */
export function getAllMajorCategories() {
  return axios.get<HttpResponse<string[]>>('/api/logs/categories/major');
}

/**
 * 获取指定大类下的所有小类
 * @param majorCategory 大类
 */
export function getMinorCategoriesByMajor(majorCategory: string) {
  return axios.get<HttpResponse<string[]>>('/api/logs/categories/minor', {
    params: { majorCategory },
  });
}
