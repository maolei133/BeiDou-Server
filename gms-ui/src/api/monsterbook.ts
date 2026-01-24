import axios from 'axios';
import { PageResult, ResultBody } from '@/types/global';

export interface MonsterBookItem {
  charid: number;
  cardid: number;
  level: number;
  cardName?: string;
}

export interface MonsterBookSearchParams {
  pageNo: number;
  pageSize: number;
  charIds?: number[];
}

export interface MonsterBookUpdateItem {
  oldCharId: number;
  oldCardId: number;
  newCardId: number;
  newLevel: number;
}

export interface MonsterBookTransferParams {
  items: MonsterBookItem[];
  newCharId: number;
}

export function getMonsterBookList(params: MonsterBookSearchParams) {
  return axios.post<ResultBody<PageResult<MonsterBookItem>>>(
    '/monsterbook/v1/list',
    params
  );
}

export function batchDeleteMonsterBook(items: MonsterBookItem[]) {
  return axios.post<ResultBody<any>>('/monsterbook/v1/batchDelete', {
    items,
  });
}

export function batchAddMonsterBook(items: MonsterBookItem[]) {
  return axios.post<ResultBody<any>>('/monsterbook/v1/batchAdd', {
    items,
  });
}

export function batchUpdateMonsterBook(items: MonsterBookUpdateItem[]) {
  return axios.post<ResultBody<any>>('/monsterbook/v1/batchUpdate', {
    items,
  });
}

export function transferMonsterBook(params: MonsterBookTransferParams) {
  return axios.post<ResultBody<any>>('/monsterbook/v1/transfer', params);
}

export function getMonsterCardNames(cardIds: number[]) {
  return axios.post<ResultBody<Record<number, string>>>(
    '/monsterbook/v1/getCardNames',
    {
      cardIds,
    }
  );
}
