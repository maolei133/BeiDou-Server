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
  // Add missing fields for edit
  str?: number;
  dex?: number;
  int?: number;
  luk?: number;
  hp?: number;
  mp?: number;
  ap?: number;
  sp?: string;
  face?: number;
  hair?: number;
  skinColor?: number;
}

export interface UpdatePlayerForm {
  id: number;
  name?: string;
  level?: number;
  job?: number;
  str?: number;
  dex?: number;
  intAttr?: number;
  luk?: number;
  hp?: number;
  maxHp?: number;
  mp?: number;
  maxMp?: number;
  ap?: number;
  sp?: string;
  fame?: number;
  face?: number;
  hair?: number;
  skinColor?: number;
  gender?: number;
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

export function updatePlayer(data: UpdatePlayerForm) {
  return axios.post(`/character/v1/update`, data);
}

export function getPlayerDetail(id: number) {
  return axios.post<OnlinePlayer>(`/character/v1/detail`, { id });
}
