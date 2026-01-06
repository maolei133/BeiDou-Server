import axios from 'axios';
import { PageState } from '@/store/page';

export interface GiveForm {
  worldId?: number;
  playerId?: number;
  player?: string;
  type: number;
  id?: number;
  quantity?: number;
  rate?: number;
  str?: number;
  dex?: number;
  int?: number;
  luk?: number;
  hp?: number;
  mp?: number;
  pAtk?: number;
  mAtk?: number;
  pDef?: number;
  mDef?: number;
  acc?: number;
  avoid?: number;
  hands?: number;
  speed?: number;
  jump?: number;
  upgradeSlot?: number;
  expire?: number;
}

export interface OnlinePlayer {
  world: number;
  accountId: number;
  accountName?: string;
  id: number;
  name: string;
  map: number;
  mapName: string;
  job: number;
  jobName: string;
  level: number;
  gm: number;
  maxHp: number;
  maxMp: number;
  guildName?: string;
  guildId: number;
  gender: number;
  partyId: number;
  channel: number;
  fame: number;
  loginTime?: string;
  lastLogoutTime?: string;
}

export function getPlayerList(
  pageNo: number,
  pageSize: number,
  id?: number,
  name?: string,
  map?: number,
  status?: number
) {
  return axios.post<PageState<OnlinePlayer>>('/character/v1/online/list', {
    pageNo,
    pageSize,
    id,
    name,
    map,
    status,
  });
}

export function givePlayerSrc(data: GiveForm) {
  return axios.post(`/give/v1/resource`, data);
}

export function getEquInitialInfo(id: number) {
  return axios.post(`/common/v1/getEquipmentInfoByItemId`, { id });
}
