import axios from 'axios';
import type { AxiosRequestConfig, AxiosResponse } from 'axios';
import { Message, Modal } from '@arco-design/web-vue';
import { useUserStore } from '@/store';
import { getToken } from '@/utils/auth';

const SUCCESS_CODE = 20000;
const AUTH_EXPIRED_CODE = 20002;
const ACCESS_DENIED_CODE = 30001;
const VALIDATION_ERROR_CODE = 10001;
const SYSTEM_ERROR_CODE = 50000;

let authExpiredHandled = false;

/* eslint-disable no-bitwise */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export interface ApiResponse<T = unknown> {
  code: number;
  message: string;
  data: T;
  timestamp: number;
  path: string;
}

export type HttpResponse<T = unknown> = ApiResponse<T>;

if (import.meta.env.VITE_API_BASE_URL) {
  axios.defaults.baseURL = import.meta.env.VITE_API_BASE_URL;
}

function isApiResponse(data: unknown): data is ApiResponse {
  return (
    !!data &&
    typeof data === 'object' &&
    'code' in data &&
    'message' in data &&
    'data' in data
  );
}

function getResponseMessage(res: ApiResponse) {
  switch (res.code) {
    case AUTH_EXPIRED_CODE:
      return res.message || '登录状态已失效，请重新登录';
    case ACCESS_DENIED_CODE:
      return res.message || '权限不足，无法访问该资源';
    case VALIDATION_ERROR_CODE:
      return res.message || '请求参数不正确，请检查后重试';
    case SYSTEM_ERROR_CODE:
      return res.message || '系统异常，请稍后重试或联系管理员';
    default:
      return res.message || '操作失败，请稍后重试';
  }
}

function redirectToLogin() {
  const userStore = useUserStore();

  userStore.logoutCallBack();
  window.location.href = '/';
}

function handleAuthExpired(res?: ApiResponse) {
  if (authExpiredHandled) return;
  authExpiredHandled = true;

  Modal.warning({
    title: '登录已失效',
    content: res?.message || '登录状态已失效，请重新登录',
    okText: '重新登录',
    maskClosable: false,
    onOk: redirectToLogin,
    onCancel: redirectToLogin,
  });
}

function handleBusinessError(res: ApiResponse) {
  const content = getResponseMessage(res);

  if (res.code === AUTH_EXPIRED_CODE) {
    handleAuthExpired(res);
  } else if (res.code === ACCESS_DENIED_CODE) {
    Message.warning({
      content,
      duration: 5 * 1000,
    });
  } else if (res.code === SYSTEM_ERROR_CODE) {
    Message.error({
      content,
      duration: 5 * 1000,
    });
  } else {
    Message.warning({
      content,
      duration: 5 * 1000,
    });
  }

  return Promise.reject(new Error(content));
}

function getHttpErrorMessage(error: any) {
  const status = error?.response?.status;

  if (status === 401) return '登录状态已失效，请重新登录';
  if (status === 403) return '权限不足，无法访问该资源';
  if (status >= 500) return '系统异常，请稍后重试或联系管理员';
  if (error.message === 'Network Error')
    return '无法连接到服务器，请检查网络或服务状态';

  return error.message || '请求失败，请稍后重试';
}

axios.interceptors.request.use(
  (config: AxiosRequestConfig) => {
    // 每个请求自动携带 JWT Token。
    // Authorization 是自定义请求头，如后端约定变更需同步调整。
    const token = getToken();
    if (token) {
      if (!config.headers) {
        config.headers = {};
      }
      config.headers.Authorization = `Bearer ${token}`;
    }
    const isUpload = config.headers?.['Content-type'] === 'multipart/form-data';
    if (config.data && !isUpload) {
      config.data = {
        requestId: generateUUID(),
        data: config.data,
      };
    }
    return config;
  },
  (error) => Promise.reject(error)
);

axios.interceptors.response.use(
  (response: AxiosResponse<ApiResponse | Blob>) => {
    if (response.config.responseType === 'blob') {
      const res = response.data as Blob;
      if (response.status !== 200) {
        Message.error({
          content: response.statusText || '文件下载失败',
          duration: 5 * 1000,
        });
        return Promise.reject(new Error(response.statusText || '文件下载失败'));
      }
      const url = window.URL.createObjectURL(new Blob([res]));
      const link = document.createElement('a');
      link.href = url;
      // 从 Content-Disposition 中获取文件名。
      link.setAttribute(
        'download',
        response.headers['content-disposition']
          .split('filename=')[1]
          .replace(/"/g, '')
      );
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      // 释放 URL 对象。
      window.URL.revokeObjectURL(url);
      return null;
    }

    const res = response.data;
    if (!isApiResponse(res)) {
      return response;
    }

    if (res.code !== SUCCESS_CODE) {
      return handleBusinessError(res);
    }

    return res.data;
  },
  (error) => {
    const errorMessage = getHttpErrorMessage(error);
    const status = error?.response?.status;

    if (status === 401) {
      handleAuthExpired();
      return Promise.reject(new Error(errorMessage));
    }

    if (status === 403) {
      Message.warning({
        content: errorMessage,
        duration: 5 * 1000,
      });
      return Promise.reject(new Error(errorMessage));
    }

    Message.error({
      content: errorMessage,
      duration: 5 * 1000,
    });
    return Promise.reject(error);
  }
);
