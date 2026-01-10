import axios from 'axios';

export interface InformationSearch {
  types: string[];
  filter: string;
  filterType?: number;
  fullMatch?: boolean;
  page?: number;
  pageSize?: number;
  gender?: number;
  color?: number | null;
}

export interface InformationResult {
  type: string;
  id: number;
  name: string;
  desc: string;
}

export interface PageResult<T> {
  records: T[];
  totalRow: number;
  totalPage: number;
  pageNumber: number;
  pageSize: number;
}

export interface GetStylesParams {
  type: 'hair' | 'face';
  keyword?: string;
  page?: number;
  pageSize?: number;
  gender?: number;
  color?: number | null;
}

export function informationSearch(condition: InformationSearch) {
  return axios.post<PageResult<InformationResult>>(
    '/common/v1/informationSearch',
    condition
  );
}

export function getStyles(params: GetStylesParams) {
  // 如果关键字为空，使用 % 通配符绕过后端非空校验
  const filter =
    params.keyword && params.keyword.trim() !== '' ? params.keyword : '%';

  return informationSearch({
    types: [params.type],
    filter,
    page: params.page,
    pageSize: params.pageSize,
    gender: params.gender,
    color: params.color,
  });
}

export function getAllMaps() {
  return axios.get<InformationResult[]>('/common/v1/getAllMaps');
}

export function getStreetNames() {
  return axios.get<string[]>('/common/v1/getStreetNames');
}

export function getMapsByStreetName(streetName: string) {
  return axios.get<InformationResult[]>('/common/v1/getMapsByStreetName', {
    params: { streetName },
  });
}

export function getJobs() {
  return axios.get<InformationResult[]>('/common/v1/getJobs');
}

export function getSkinColors() {
  return axios.get<InformationResult[]>('/common/v1/getSkinColors');
}

export function getGuilds() {
  return axios.get<InformationResult[]>('/common/v1/getGuilds');
}
