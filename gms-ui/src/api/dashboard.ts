import axios from 'axios';

export interface MonitorMemoryInfo {
  init?: number | null;
  used?: number | null;
  committed?: number | null;
  max?: number | null;
  usage?: number | null;
}

export interface MonitorSampleInfo {
  sampledAt?: number | null;
  sampledAtIso?: string | null;
  partial?: boolean | null;
  warnings?: string[] | null;
}

export interface MonitorServerInfo {
  online?: boolean | null;
  version?: string | null;
}

export interface MonitorRuntimeInfo {
  pid?: number | null;
  uptimeMs?: number | null;
  startedAt?: number | null;
  startedAtIso?: string | null;
  userDir?: string | null;
  environment?: string | null;
  activeProfiles?: string[] | null;
}

export interface MonitorCpuInfo {
  /** 宿主环境 CPU 占用率，取值范围 0..1。 */
  hostCpuLoad?: number | null;
  /** 游戏服务端 Java 进程 CPU 占用率，取值范围 0..1。 */
  gameServerCpuLoad?: number | null;
  osName?: string | null;
  osVersion?: string | null;
  osArch?: string | null;
  processorModel?: string | null;
  availableProcessors?: number | null;
  systemLoadAverage?: number | null;
  processCpuLoad?: number | null;
  systemCpuLoad?: number | null;
  systemMemory?: MonitorMemoryInfo | null;
}

export interface MonitorJvmInfo {
  javaVersion?: string | null;
  javaVendor?: string | null;
  vmName?: string | null;
  vmVersion?: string | null;
  heap?: MonitorMemoryInfo | null;
  nonHeap?: MonitorMemoryInfo | null;
  threadCount?: number | null;
  daemonThreadCount?: number | null;
  peakThreadCount?: number | null;
  totalStartedThreadCount?: number | null;
  gcCount?: number | null;
  gcTimeMs?: number | null;
}

export interface MonitorDiskInfo {
  path?: string | null;
  total?: number | null;
  free?: number | null;
  usable?: number | null;
  used?: number | null;
  usage?: number | null;
}

export interface MonitorDiskIoInfo {
  /** 宿主环境磁盘读取速率。 */
  hostReadBytesPerSecond?: number | null;
  /** 宿主环境磁盘写入速率。 */
  hostWriteBytesPerSecond?: number | null;
  /** 游戏服务端 Java 进程磁盘读取速率。 */
  gameServerReadBytesPerSecond?: number | null;
  /** 游戏服务端 Java 进程磁盘写入速率。 */
  gameServerWriteBytesPerSecond?: number | null;
  available?: boolean | null;
  note?: string | null;
  readBytesPerSecond?: number | null;
  writeBytesPerSecond?: number | null;
  readOpsPerSecond?: number | null;
  writeOpsPerSecond?: number | null;
  processReadBytesPerSecond?: number | null;
  processWriteBytesPerSecond?: number | null;
}

export interface MonitorNetworkInterfaceInfo {
  name?: string | null;
  displayName?: string | null;
  up?: boolean | null;
  loopback?: boolean | null;
  virtual?: boolean | null;
  mtu?: number | null;
  addresses?: string[] | null;
  internetReachable?: boolean | null;
  defaultInterface?: boolean | null;
  primaryAddress?: string | null;
}

export interface MonitorNetworkInfo {
  /** 宿主环境所选网卡下载速率；当前不等同于游戏服务端进程网络 IO。 */
  hostRxBytesPerSecond?: number | null;
  /** 宿主环境所选网卡上传速率；当前不等同于游戏服务端进程网络 IO。 */
  hostTxBytesPerSecond?: number | null;
  hostName?: string | null;
  selectedInterfaceName?: string | null;
  defaultInterfaceName?: string | null;
  interfaces?: MonitorNetworkInterfaceInfo[] | null;
  rxBytesPerSecond?: number | null;
  txBytesPerSecond?: number | null;
}

export interface MonitorContainerInfo {
  detected?: boolean | null;
  runtime?: string | null;
  dockerEnv?: boolean | null;
  cgroupPath?: string | null;
  memory?: MonitorMemoryInfo | null;
}

export interface ServerMonitorSnapshot {
  sample?: MonitorSampleInfo | null;
  server?: MonitorServerInfo | null;
  runtime?: MonitorRuntimeInfo | null;
  cpu?: MonitorCpuInfo | null;
  jvm?: MonitorJvmInfo | null;
  disks?: MonitorDiskInfo[] | null;
  diskIo?: MonitorDiskIoInfo | null;
  network?: MonitorNetworkInfo | null;
  container?: MonitorContainerInfo | null;
}

export interface ServerMonitorHistoryPoint {
  sampledAt?: number | null;
  sampledAtIso?: string | null;
  systemCpuLoad?: number | null;
  processCpuLoad?: number | null;
  systemLoadAverage?: number | null;
  systemMemoryUsage?: number | null;
  jvmHeapUsage?: number | null;
  jvmNonHeapUsage?: number | null;
  networkRxBytesPerSecond?: number | null;
  networkTxBytesPerSecond?: number | null;
  diskReadBytesPerSecond?: number | null;
  diskWriteBytesPerSecond?: number | null;
  cpuAnomaly?: boolean | null;
  cpuAnomalyLevel?: string | null;
  cpuAnomalyReason?: string | null;
  cpuAnomalyBaseline?: number | null;
  partial?: boolean | null;
  warnings?: string[] | null;
}

export interface ServerMonitorEvent {
  occurredAt?: number | null;
  occurredAtIso?: string | null;
  type?: string | null;
  level?: string | null;
  message?: string | null;
  value?: number | null;
  baseline?: number | null;
}

export interface ServerMonitorHistory {
  from?: number | null;
  to?: number | null;
  minutes?: number | null;
  intervalSeconds?: number | null;
  points?: ServerMonitorHistoryPoint[] | null;
  events?: ServerMonitorEvent[] | null;
}

export interface CpuMonitorRule {
  p?: number | null;
  lv?: 'WARN' | 'ERROR' | string | null;
}

export interface CpuMonitorConfig {
  rules?: CpuMonitorRule[] | null;
}

export function getServerStatus() {
  return axios.get<boolean>('/server/v1/online');
}

export function startServer() {
  return axios.get('/server/v1/startServer');
}

interface StopServerParams {
  minutes: number;
  shutdownMsg: string;
  showServerMsg: boolean;
  showCenterMsg: boolean;
  showChatMsg: boolean;
}

export function stopServer(params: StopServerParams) {
  return axios.post('/server/v1/stopServerWithMsgAndInternal', params);
}

export function restartServer() {
  return axios.get('/server/v1/restartServer');
}

export function shutdown(params?: StopServerParams) {
  return axios.post('/server/v1/shutdown', params);
}

export function getServerMonitorSnapshot(params?: { interfaceName?: string }) {
  return axios.get<ServerMonitorSnapshot>('/server/v1/monitor/snapshot', {
    params,
  });
}

export interface ServerMonitorHistoryParams {
  minutes?: number;
  range?: string;
  start?: number;
  end?: number;
}

export function getServerMonitorHistory(
  params: number | ServerMonitorHistoryParams
) {
  const requestParams =
    typeof params === 'number' ? { minutes: params } : params;
  return axios.get<ServerMonitorHistory>('/server/v1/monitor/history', {
    params: requestParams,
  });
}

export function getCpuMonitorConfig() {
  return axios.get<CpuMonitorConfig>('/server/v1/monitor/cpu-config');
}

export function updateCpuMonitorConfig(data: CpuMonitorConfig) {
  return axios.post<CpuMonitorConfig>('/server/v1/monitor/cpu-config', data);
}

export interface ServerWorldInfo {
  id: number;
  expRate?: number | null;
  dropRate?: number | null;
  mesoRate?: number | null;
  bossDropRate?: number | null;
  questRate?: number | null;
  travelRate?: number | null;
  fishingRate?: number | null;
}

export interface ServerChannelInfo {
  id: number;
  worldId: number;
  playerCount?: number | null;
  mapCount?: number | null;
  estimatedMapMemoryBytes?: number | null;
  disposedMapCount?: number | null;
}

export function getServerWorldList() {
  return axios.get<ServerWorldInfo[]>('/server/v1/world/list');
}

export function getServerChannelList(worldId: number) {
  return axios.get<ServerChannelInfo[]>('/server/v1/channel/list', {
    params: { worldId },
  });
}

export function getAllWorldsOnlinePlayersCount(worldIdList: number[]) {
  return axios.post<number>('/common/v1/getAllWorldsOnlinePlayersCount', {
    worldIdList,
  });
}

export function getVersion() {
  return axios.get('/server/v1/version');
}
