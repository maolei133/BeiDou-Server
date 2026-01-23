import axios from 'axios';
import { PageState } from '@/store/page';
import { ResultBody } from '@/types/global';

export interface DueyItem {
  itemId: number;
  quantity: number;
  owner: string;
  expiration: number;
  name?: string;
  // 装备属性
  str?: number;
  dex?: number;
  inte?: number; // 统一为 inte
  luk?: number;
  hp?: number;
  mp?: number;
  watk?: number;
  matk?: number;
  wdef?: number;
  mdef?: number;
  acc?: number;
  avoid?: number;
  hands?: number;
  speed?: number;
  jump?: number;
  upgradeSlots?: number;
  level?: number;
  itemLevel?: number;
  flag?: number;
  vicious?: number;
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
  expireTime: string;
  deliveryTime: string;
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
  receiverIds?: number[];
  isAll?: boolean;
  mesos?: number;
  message?: string;
  itemId?: number;
  quantity?: number;
  quick?: boolean;
  senderName?: string;
  expireTime?: number;
  expireDays?: number;
  deliveryTime?: number;
  // 物品属性
  owner?: string;
  itemExpiration?: number;

  // 装备属性
  str?: number;
  dex?: number;
  inte?: number; // 统一为 inte
  luk?: number;
  hp?: number;
  mp?: number;
  watk?: number;
  matk?: number;
  wdef?: number;
  mdef?: number;
  acc?: number;
  avoid?: number;
  hands?: number;
  speed?: number;
  jump?: number;
  upgradeSlots?: number;
  level?: number;
  itemLevel?: number;
  flag?: number;
  vicious?: number;
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
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { inte, ...rest } = data;
  return axios.post<ResultBody<void>>('/duey/v1/send', {
    ...rest,
    int: inte, // 映射回后端期望的 'int'
  });
}
