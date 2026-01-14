import axios from 'axios';
import { PageState } from '@/store/page';
import { ResultBody } from '@/types/global';

export interface DueyItem {
  itemId: number;
  quantity: number;
  owner: string;
  expiration: number;
}

export interface DueyPackage {
  packageId: number;
  receiverId: number;
  receiverName: string;
  senderName: string;
  mesos: number;
  timestamp: string;
  message: string;
  checked: number;
  type: number;
  items: DueyItem[];
}

export interface DueyListParams {
  pageNo: number;
  pageSize: number;
  receiverName?: string;
  senderName?: string;
  startTime?: number;
  endTime?: number;
  itemId?: number;
  itemName?: string;
  itemType?: number;
  checked?: number;
}

export interface SendDueyReq {
  receiverName?: string;
  receiverId?: number;
  isAll?: boolean;
  mesos?: number;
  message?: string;
  itemId?: number;
  quantity?: number;
  quick?: boolean;
  senderName?: string;
  expireTime?: number;
  expireDays?: number;
}

export function getDueyList(params: DueyListParams) {
  return axios.get<PageState<DueyPackage>>('/duey/v1/list', {
    params,
  });
}

export function deleteDueyPackage(id: number) {
  return axios.delete<ResultBody<void>>(`/duey/v1/${id}`);
}

export function sendDueyPackage(data: SendDueyReq) {
  return axios.post<ResultBody<void>>('/duey/v1/send', data);
}
