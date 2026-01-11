import axios from 'axios';
import { PageResult, SubmitBody, ResultBody } from '@/types/global';

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

export interface OnlinePlayer {
  world: number;
  accountId: number;
  accountName: string;
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
  guildName: string;
  guildId: number;
  gender: number;
  partyId: number;
  channel: number;
  fame: number;
  loginTime: string;
  lastLogoutTime: string;
  str: number;
  dex: number;
  intAttr: number;
  luk: number;
  hp: number;
  mp: number;
  ap: number;
  sp: string;
  face: number;
  hair: number;
  skinColor: number;
  banned: boolean;
}

export interface GiveForm {
  worldId?: number;
  playerId?: number;
  player?: string;
  type: number;
  quantity?: number;
  id?: number;
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
  expireType?: number;
  expire?: number;
  expireDate?: string;
  owner?: string;
  flag?: number | number[];
}

export interface UpdatePlayerForm {
  id: number;
  name?: string;
  level?: number;
  exp?: number;
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
  meso?: number;
  gm?: number;
  face?: number;
  hair?: number;
  skinColor?: number;
  gender?: number;
  nxCredit?: number;
  maplePoint?: number;
  nxPrepaid?: number;
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

export interface ChrDetailRtn {
  id: number;
  name: string;
  level: number;
  exp: number;
  job: number;
  jobName: string;
  str: number;
  dex: number;
  intAttr: number;
  luk: number;
  hp: number;
  maxHp: number;
  mp: number;
  maxMp: number;
  ap: number;
  sp: string;
  fame: number;
  meso: number;
  gm: number;
  face: number;
  hair: number;
  skinColor: number;
  gender: number;
  nxCredit: number;
  maplePoint: number;
  nxPrepaid: number;
  equipSlots: number;
  useSlots: number;
  setupSlots: number;
  etcSlots: number;
  buddyCapacity: number;
  merchantMesos: number;
  gachaExp: number;
  map: number;
  spawnPoint: number;
  mountLevel: number;
  mountExp: number;
  mountTiredness: number;
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
  banUntil?: number;
  banIp: boolean;
  banMac: boolean;
  banHwid: boolean;
  notify: boolean;
  notifyContent: string;
}

export interface BanInfoRtn {
  ips: string[];
  macs: string[];
  hwid: string;
}

export function getPlayerList(params: PlayerListParams) {
  return axios.post<ResultBody<PageResult<OnlinePlayer>>>(
    '/character/v1/online/list',
    params
  );
}

export function givePlayerSrc(data: GiveForm) {
  return axios.post<ResultBody<any>>('/give/v1/resource', data);
}

export function getEquInitialInfo(itemId: number) {
  return axios.get<ResultBody<any>>('/common/v1/getEquInitialInfo', {
    params: { itemId },
  });
}

export function getItemInitialInfo(itemId: number) {
  return axios.get<ResultBody<any>>('/common/v1/getItemInitialInfo', {
    params: { itemId },
  });
}

export function updatePlayer(data: UpdatePlayerForm) {
  return axios.post<ResultBody<any>>('/character/v1/update', data);
}

export function getPlayerDetail(id: number) {
  return axios.post<ResultBody<ChrDetailRtn>>('/character/v1/detail', { id });
}

export function disconnectPlayer(data: DisconnectReq) {
  return axios.post<ResultBody<any>>('/character/v1/disconnect', data);
}

export function banPlayer(data: BanPlayerReq) {
  return axios.post<ResultBody<any>>('/character/v1/ban', data);
}

export function getBanInfo(id: number) {
  return axios.post<ResultBody<BanInfoRtn>>('/character/v1/banInfo', { id });
}

export function unbanPlayer(id: number) {
  return axios.post<ResultBody<any>>('/character/v1/unban', { id });
}
