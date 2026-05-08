import axios from 'axios';

export interface CommandReq {
  id?: number;
  level?: number;
  levelList?: number[];
  syntax?: string;
  defaultLevel?: number;
  defaultLevelList?: number[];
  clazz?: string;
  description?: string;
  enabled?: boolean;
}

export function getCommandList(data: any) {
  return axios.post('/command/v1/getCommandListFromDB', data);
}

export function updateCommand(data: CommandReq) {
  return axios.post('/command/v1/updateCommand', data);
}

export function reloadEventsByGMCommand() {
  return axios.get('/command/v1/reloadEventsByGMCommand');
}

export function reloadPortalsByGMCommand() {
  return axios.get('/command/v1/reloadPortalsByGMCommand');
}

export function reloadMapsByGMCommand() {
  return axios.get('/command/v1/reloadMapsByGMCommand');
}

export function reloadDropsByGMCommand() {
  return axios.get('/command/v1/reloadDropsByGMCommand');
}

export function reloadShopsByGMCommand() {
  return axios.get('/command/v1/reloadShopsByGMCommand');
}

export function reloadQuestsByGMCommand() {
  return axios.get('/command/v1/reloadQuestsByGMCommand');
}

export function reloadSkillsByGMCommand() {
  return axios.get('/command/v1/reloadSkillsByGMCommand');
}

export function reloadMonstersByGMCommand() {
  return axios.get('/command/v1/reloadMonstersByGMCommand');
}

export function reloadReactorsByGMCommand() {
  return axios.get('/command/v1/reloadReactorsByGMCommand');
}

export function reloadOpcodesByGMCommand() {
  return axios.get('/command/v1/reloadOpcodesByGMCommand');
}

export function reloadPacketsByGMCommand() {
  return axios.get('/command/v1/reloadPacketsByGMCommand');
}

/**
 * 请求后端动态重载 PacketCreator.js 脚本。
 */
export function reloadPacketCreatorScript() {
  return axios.get('/command/v1/reload-packet-creator');
}
