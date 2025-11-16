import axios from 'axios';
import type { HttpResponse } from './interceptor';

export interface LogQueryParams {
  majorCategory?: string;
  minorCategory?: string;
  startDate?: string;
  endDate?: string;
  keyword?: string;
  ip?: string;
  mac?: string;
  hwid?: string;
  account?: string;
  character?: string;
}

export interface LogCategory {
  id: string;
  name: string;
}

export interface UniqueValuesResponse {
  data: string[];
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

/**
 * 获取唯一IP列表
 * @param majorCategory 大类
 * @param minorCategory 小类
 */
export function getUniqueIPs(majorCategory: string, minorCategory: string) {
  return axios.get<HttpResponse<UniqueValuesResponse>>('/api/logs/unique/ips', {
    params: { majorCategory, minorCategory },
  });
}

/**
 * 获取唯一MAC列表
 * @param majorCategory 大类
 * @param minorCategory 小类
 */
export function getUniqueMACs(majorCategory: string, minorCategory: string) {
  return axios.get<HttpResponse<UniqueValuesResponse>>(
    '/api/logs/unique/macs',
    {
      params: { majorCategory, minorCategory },
    }
  );
}

/**
 * 获取唯一HWID列表
 * @param majorCategory 大类
 * @param minorCategory 小类
 */
export function getUniqueHWIDs(majorCategory: string, minorCategory: string) {
  return axios.get<HttpResponse<UniqueValuesResponse>>(
    '/api/logs/unique/hwids',
    {
      params: { majorCategory, minorCategory },
    }
  );
}

/**
 * 获取唯一账号列表
 * @param majorCategory 大类
 * @param minorCategory 小类
 */
export function getUniqueAccounts(
  majorCategory: string,
  minorCategory: string
) {
  return axios.get<HttpResponse<UniqueValuesResponse>>(
    '/api/logs/unique/accounts',
    {
      params: { majorCategory, minorCategory },
    }
  );
}

/**
 * 获取唯一角色ID列表
 * @param majorCategory 大类
 * @param minorCategory 小类
 */
export function getUniqueCharacterIds(
  majorCategory: string,
  minorCategory: string
) {
  return axios.get<HttpResponse<UniqueValuesResponse>>(
    '/api/logs/unique/characterIds',
    {
      params: { majorCategory, minorCategory },
    }
  );
}
