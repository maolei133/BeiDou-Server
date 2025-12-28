import axios from 'axios';

export interface InformationSearch {
  types: string[];
  filter: string;
  filterType?: number;
  fullMatch?: boolean;
}

export interface InformationResult {
  type: string;
  id: number;
  name: string;
  desc: string;
}

export function informationSearch(condition: InformationSearch) {
  return axios.post('/common/v1/informationSearch', condition);
}

export function getAllMaps() {
  return axios.get<InformationResult[]>('/common/v1/getAllMaps');
}

export function getStreetNames() {
  return axios.get<string[]>('/common/v1/getStreetNames');
}

export function getMapsByStreetName(streetName: string) {
  return axios.get<InformationResult[]>('/common/v1/getMapsByStreetName', {
    params: { streetName },
  });
}
