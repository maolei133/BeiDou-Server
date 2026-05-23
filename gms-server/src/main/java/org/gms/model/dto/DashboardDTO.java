package org.gms.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.gms.model.dto.monitor.ServerMonitorSnapshotDTO;

import java.util.List;
import java.util.Map;

/**
 * 工作台首页面数据聚合DTO。
 * <p>
 * 合并了监控快照 + 大区列表 + 频道列表 + 在线人数，
 * 前端工作台页面只请求此一个接口，避免多个定时请求。
 * <p>
 * 如需新增工作台相关的字段，在此 DTO 中添加即可，
 * 不要新增独立的 API 请求，保持"一次请求全量数据"原则。
 *
 * @see org.gms.controller.ServerMonitorController#getDashboard
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DashboardDTO {
    /**
     * 服务器运行监控快照（CPU / 内存 / 网络 / 磁盘 / 运行时）
     */
    private ServerMonitorSnapshotDTO monitor;
    /**
     * 大区列表（含各倍率配置）
     */
    private List<WorldListRtnDTO> worldList;
    /**
     * 频道列表，按大区ID分组
     */
    private Map<Integer, List<ChannelListRtnDTO>> channelList;
    /**
     * 所有大区在线玩家总数
     */
    private Integer onlinePlayerCount;
}
