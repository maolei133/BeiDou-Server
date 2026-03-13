import axios from 'axios';
import { PageState } from '@/store/page';
import { ResultBody } from '@/types/global';

// 定义物品的数据结构，这个接口保持不变
export interface DueyItem {
  itemId: number;
  quantity: number;
  owner?: string;
  expiration?: number;
  name?: string;
  // 装备属性
  str?: number;
  dex?: number;
  int?: number;
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

// 快递包裹的数据结构
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
  // --- 核心修改 ---
  // 后端返回的是单个物品对象，而不是数组
  // 将 'items: DueyItem[]' 修改为 'item?: DueyItem'
  item?: DueyItem;
  expireTime: string;
  deliveryTime: string;
  statusTime: string;
}

// 列表查询参数接口，保持不变
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

// 发送快递的请求体结构
export interface SendDueyReq {
  packageId?: number; // 用于更新
  receiverIds?: number[];
  isAll?: boolean;
  mesos?: number;
  message?: string;
  quick?: boolean;
  senderName?: string;
  expireTime?: number;
  expireDays?: number;
  deliveryTime?: number;

  // 批量物品列表
  // 虽然发送时可以批量，但后端会拆分成多个包裹
  items?: DueyItem[];

  // 兼容旧字段（单个物品），保持不变
  itemId?: number;
  quantity?: number;
  owner?: string;
  itemExpiration?: number;
  str?: number;
  dex?: number;
  int?: number;
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
  return axios.post<ResultBody<void>>('/duey/v1/send', data);
}
