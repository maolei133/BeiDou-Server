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
  level?: number;
  itemLevel?: number;
  expire?: number;
  expireDate?: string;
  expireType?: number;
  owner?: string;
  flag?: number;
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
  // New fields
  equipSlots?: number;
  useSlots?: number;
  setupSlots?: number;
  etcSlots?: number;
  buddyCapacity?: number;
  merchantMesos?: number;
  gachaExp?: number;
  spawnPoint?: number;
  mountLevel?: number;
  mountExp?: number;
  mountTiredness?: number;
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
  // New fields
  equipSlots?: number;
  useSlots?: number;
  setupSlots?: number;
  etcSlots?: number;
  buddyCapacity?: number;
  merchantMesos?: number;
  gachaExp?: number;
  map?: number;
  spawnPoint?: number;
  mountLevel?: number;
  mountExp?: number;
  mountTiredness?: number;
}

export interface PlayerListParams {
  pageNo: number;
  pageSize: number;
  id?: number;
  name?: string;
  map?: number;
  status?: number;
  accountId?: number;
  channel?: number;
  job?: number;
  partyId?: number;
  guildId?: number;
  minLevel?: number;
  maxLevel?: number;
  minOnlineTime?: number;
  maxOnlineTime?: number;
}

export interface DisconnectReq {
  ids: number[];
  all: boolean;
}

export interface BanPlayerReq {
  ids: number[];
  all: boolean;
  reason: string;
  duration?: number;
  banIp: boolean;
  banMac: boolean;
  banHwid: boolean;
  notify: boolean;
  notifyContent?: string;
  ips?: string[];
  macs?: string[];
}

export interface BanInfoRtn {
  ips: string[];
  macs: string[];
  hwid: string;
}

export function getPlayerList(params: PlayerListParams) {
  return axios.post<PageState<OnlinePlayer>>(
    '/character/v1/online/list',
    params
  );
}

export function givePlayerSrc(data: GiveForm) {
  return axios.post(`/give/v1/resource`, data);
}

export function getEquInitialInfo(id: number) {
  return axios.post(`/common/v1/getEquipmentInfoByItemId`, { id });
}

export function getItemInitialInfo(id: number) {
  return axios.post(`/common/v1/getItemInfoByItemId`, { id });
}

export function updatePlayer(data: UpdatePlayerForm) {
  return axios.post(`/character/v1/update`, data);
}

export function getPlayerDetail(id: number) {
  return axios.post<OnlinePlayer>(`/character/v1/detail`, { id });
}

export function disconnectPlayer(data: DisconnectReq) {
  return axios.post(`/character/v1/disconnect`, data);
}

export function banPlayer(data: BanPlayerReq) {
  return axios.post(`/character/v1/ban`, data);
}

export function getBanInfo(id: number) {
  return axios.post<BanInfoRtn>(`/character/v1/banInfo`, { id });
}
