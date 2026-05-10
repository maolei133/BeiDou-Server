import axios from 'axios';
import type { RouteRecordNormalized } from 'vue-router';
import { UserState } from '@/store/modules/user/types';

export interface LoginData {
  username: string;
  password: string;
}

export interface SubmitBody {
  requestId: string;
  data: any;
}

export interface LoginRes {
  token: string;
}
export function login(data: LoginData) {
  return axios.post<LoginRes, LoginRes>('/auth/v1/login', data);
}

export function logout() {
  return axios.delete<LoginRes, LoginRes>('/auth/v1/logout');
}

export function getUserInfo() {
  return axios.get<UserState, UserState>('/account/v1/info');
}

export function getMenuList() {
  return axios.get<RouteRecordNormalized[], RouteRecordNormalized[]>(
    '/account/v1/menu'
  );
}

export function refreshToken() {
  return axios.get<LoginRes, LoginRes>('/auth/v1/refreshToken');
}
