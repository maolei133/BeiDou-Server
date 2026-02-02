import axios from 'axios';

export interface ProcessStatus {
  loki: number | null;
  promtail: number | null;
  grafana?: number | null;
}

export interface LogQuery {
  query: string;
  start?: number;
  end?: number;
  limit?: number;
  direction?: string;
  range?: string; // 新增 range 参数
}

export interface LogStats {
  query: string;
  raw: string;
}

export function getProcessStatus() {
  return axios.get<ProcessStatus>('/log/process/status');
}

export function startProcess() {
  return axios.post<string>('/log/process/start');
}

export function stopProcess() {
  return axios.post<string>('/log/process/stop');
}

export function restartProcess() {
  return axios.post<string>('/log/process/restart');
}

export function resetProcess() {
  return axios.post<string>('/log/process/reset');
}

export function getModuleConfig() {
  return axios.get<Record<string, boolean>>('/log/config/modules');
}

export function setModuleConfig(module: string, enabled: boolean) {
  return axios.post<string>(
    `/log/config/modules?module=${module}&enabled=${enabled}`
  );
}

export function getLoggerLevels() {
  return axios.get<Record<string, string>>('/log/config/levels');
}

export function setLoggerLevel(loggerName: string, level: string) {
  return axios.post<string>(
    `/log/config/levels?loggerName=${loggerName}&level=${level}`
  );
}

export function getConfigFiles() {
  return axios.get<string[]>('/log/files');
}

export function readConfigFile(fileName: string) {
  return axios.get<string>(`/log/files/${fileName}`);
}

export function saveConfigFile(fileName: string, content: string) {
  return axios.post<string>(`/log/files/${fileName}`, content, {
    headers: { 'Content-Type': 'text/plain' },
  });
}

export function getConfigYaml(fileName: string) {
  return axios.get<any>(`/log/config/yaml/${fileName}`);
}

export function saveConfigYaml(fileName: string, config: any) {
  return axios.post<any>(`/log/config/yaml/${fileName}`, config);
}

export function queryLogs(params: LogQuery) {
  return axios.get<string>('/log/query/range', { params });
}

export function getLogStats(range: string) {
  return axios.get<LogStats>('/log/query/stats', { params: { range } });
}

export function searchAccount(keyword: string) {
  return axios.get<any[]>('/log/search/account', { params: { keyword } });
}

export function searchCharacter(keyword: string) {
  return axios.get<any[]>('/log/search/character', { params: { keyword } });
}

export function searchIp(keyword: string) {
  return axios.get<string[]>('/log/search/ip', { params: { keyword } });
}

export function searchMac(keyword: string) {
  return axios.get<string[]>('/log/search/mac', { params: { keyword } });
}

export function searchHwid(keyword: string) {
  return axios.get<string[]>('/log/search/hwid', { params: { keyword } });
}

// 新增通用搜索接口，适配 index.vue 中的调用
export function searchLogs(type: string, keyword: string) {
  return axios.get<string[]>(`/log/search/${type}`, { params: { keyword } });
}
