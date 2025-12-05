import axios from 'axios';

/**
 * 日志系统REST API调用模块
 * 提供与后端日志系统交互的所有接口
 */

const baseURL = '/logsystem';

export default {
  // 获取所有大类
  getMajorCategories() {
    return axios.get(`${baseURL}/categories/major`);
  },

  // 获取小类
  getMinorCategories(majorCategory: string) {
    return axios.get(
      `${baseURL}/categories/minor?majorCategory=${majorCategory}`
    );
  },

  // 获取所有分类
  getAllCategories() {
    return axios.get(`${baseURL}/categories/all`);
  },

  // 系统级监控统计
  getSystemStats() {
    return axios.get(`${baseURL}/system/monitor`);
  },

  // 分类级监控统计
  getCategoryStats() {
    return axios.get(`${baseURL}/system/categories-monitor`);
  },

  // 队列统计
  getQueueStats() {
    return axios.get(`${baseURL}/monitor/queue`);
  },

  // 上下文统计
  getContextStats() {
    return axios.get(`${baseURL}/monitor/context`);
  },

  // 清除监控数据
  clearMonitorData() {
    return axios.post(`${baseURL}/system/monitor/clear`);
  },

  // 性能趋势
  getPerformanceTrend() {
    return axios.get(`${baseURL}/monitor/trend`);
  },

  // 异常检测
  detectAnomalies() {
    return axios.get(`${baseURL}/monitor/anomalies`);
  },

  // QPS排行
  getQPSRanking(limit = 10) {
    return axios.get(`${baseURL}/monitor/ranking/qps?limit=${limit}`);
  },

  // 延迟排行
  getLatencyRanking(limit = 10) {
    return axios.get(`${baseURL}/monitor/ranking/latency?limit=${limit}`);
  },

  // 成功率排行
  getSuccessRateRanking(limit = 10) {
    return axios.get(`${baseURL}/monitor/ranking/success-rate?limit=${limit}`);
  },

  // 系统信息
  getSystemInfo() {
    return axios.get(`${baseURL}/monitor/system-info`);
  },

  // 内存信息
  getMemoryInfo() {
    return axios.get(`${baseURL}/monitor/memory-info`);
  },

  // 性能概览
  getPerformanceOverview() {
    return axios.get(`${baseURL}/monitor/performance-overview`);
  },

  // 健康检查
  health() {
    return axios.get(`${baseURL}/health`);
  },

  // 系统配置
  getSystemConfig() {
    return axios.get(`${baseURL}/config/system`);
  },

  // 更新系统配置
  updateSystemConfig(config: any) {
    return axios.post(`${baseURL}/config/system`, config);
  },

  // 性能配置
  getPerformanceConfig() {
    return axios.get(`${baseURL}/config/performance`);
  },

  // 更新性能配置
  updatePerformanceConfig(
    level: string,
    bufferSize: number,
    flushInterval: number
  ) {
    return axios.post(`${baseURL}/config/performance`, {
      level,
      bufferSize,
      flushInterval,
    });
  },

  // 获取所有分类配置
  getAllCategoryConfig() {
    return axios.get(`${baseURL}/config/categories`);
  },

  // 更新分类配置
  updateCategoryConfig(
    majorCategory: string,
    minorCategory: string,
    enabled: boolean,
    consoleOutput: boolean,
    fileOutput: boolean
  ) {
    return axios.post(`${baseURL}/config/category`, {
      majorCategory,
      minorCategory,
      enabled,
      consoleOutput,
      fileOutput,
    });
  },

  // 获取网络包配置
  getPacketConfig() {
    return axios.get(`${baseURL}/config/packet`);
  },

  // 更新网络包配置
  updatePacketConfig(config: any) {
    return axios.post(`${baseURL}/config/packet`, config);
  },

  // 添加入站包屏蔽
  addInPacketBlock(opcode: number) {
    return axios.post(`${baseURL}/config/packet/in-block`, { opcode });
  },

  // 删除入站包屏蔽
  removeInPacketBlock(opcode: number) {
    return axios.delete(`${baseURL}/config/packet/in-block/${opcode}`);
  },

  // 添加出站包屏蔽
  addOutPacketBlock(opcode: number) {
    return axios.post(`${baseURL}/config/packet/out-block`, { opcode });
  },

  // 删除出站包屏蔽
  removeOutPacketBlock(opcode: number) {
    return axios.delete(`${baseURL}/config/packet/out-block/${opcode}`);
  },

  // 获取告警历史
  getAlertHistory(ruleId: number) {
    return axios.get(`${baseURL}/alert/history?ruleId=${ruleId}&limit=50`);
  },

  // ============ 备份管理接口 ============
  // 获取备份列表
  getBackupList() {
    return axios.get(`${baseURL}/backup/list`);
  },

  // 获取备份统计信息
  getBackupStatistics() {
    return axios.get(`${baseURL}/backup/statistics`);
  },

  // 获取备份策略
  getBackupStrategy() {
    return axios.get(`${baseURL}/backup/strategy`);
  },

  // 更新备份策略
  updateBackupStrategy(strategy: any) {
    return axios.put(`${baseURL}/backup/strategy`, strategy);
  },

  // 执行完整备份
  performFullBackup() {
    return axios.post(`${baseURL}/backup/full`);
  },

  // 执行增量备份
  performIncrementalBackup() {
    return axios.post(`${baseURL}/backup/incremental`);
  },

  // 恢复备份
  restoreBackup(backupId: string) {
    return axios.post(`${baseURL}/backup/restore/${backupId}`);
  },

  // 删除备份
  deleteBackup(backupId: string) {
    return axios.delete(`${baseURL}/backup/${backupId}`);
  },

  // ============ 告警规则接口 ============
  // 获取所有告警规则
  getAlertRules() {
    return axios.get(`${baseURL}/alert/rules`);
  },

  // 获取告警统计信息
  getAlertStatistics() {
    return axios.get(`${baseURL}/alert/statistics`);
  },

  // 创建告警规则
  createAlertRule(rule: any) {
    return axios.post(`${baseURL}/alert/rule`, rule);
  },

  // 更新告警规则
  updateAlertRule(id: string, rule: any) {
    return axios.put(`${baseURL}/alert/rule/${id}`, rule);
  },

  // 删除告警规则
  deleteAlertRule(id: string) {
    return axios.delete(`${baseURL}/alert/rule/${id}`);
  },

  // 启用告警规则
  enableAlertRule(id: string) {
    return axios.post(`${baseURL}/alert/rule/${id}/enable`);
  },

  // 禁用告警规则
  disableAlertRule(id: string) {
    return axios.post(`${baseURL}/alert/rule/${id}/disable`);
  },

  // ============ 测试日志生成接口 ============
  // 生成所有分类的测试日志
  generateTestLogs(count = 100) {
    return axios.post(`${baseURL}/test/generate-all`, { count });
  },

  // 生成特定分类的测试日志
  generateTestLogsByCategory(
    majorCategory: string,
    minorCategory: string,
    count = 50
  ) {
    return axios.post(`${baseURL}/test/generate-category`, {
      majorCategory,
      minorCategory,
      count,
    });
  },

  // 生成特定日志级别的测试日志
  generateTestLogsByLevel(level: string, count = 50) {
    return axios.post(`${baseURL}/test/generate-level`, { level, count });
  },

  // 批量生成多个分类的测试日志
  generateBatchTestLogs(
    categories: Array<{
      majorCategory: string;
      minorCategory: string;
      count: number;
    }>
  ) {
    return axios.post(`${baseURL}/test/generate-batch`, { categories });
  },
};
