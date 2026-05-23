package org.gms.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import org.gms.constants.api.ApiConstant;
import org.gms.model.dto.ChannelListRtnDTO;
import org.gms.model.dto.DashboardDTO;
import org.gms.model.dto.ResultBody;
import org.gms.model.dto.SubmitBody;
import org.gms.model.dto.WorldListRtnDTO;
import org.gms.model.dto.monitor.CpuMonitorConfigDTO;
import org.gms.model.dto.monitor.ServerMonitorSnapshotDTO;
import org.gms.service.CommonService;
import org.gms.service.ServerMonitorService;
import org.gms.service.ServerService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/server")
@AllArgsConstructor
public class ServerMonitorController {
    private final ServerMonitorService serverMonitorService;
    private final ServerService serverService;
    private final CommonService commonService;

    /**
     * 工作台首页聚合数据接口。
     * <p>
     * 合并了监控快照、大区列表、频道列表、在线人数，
     * 前端每5秒仅请求此一个接口即可获取所有仪表盘数据。
     * <p>
     * ⚠️ 后续如需在工作台页面增加新数据，请在此 DTO 和本方法中添加，
     *    不要再新增独立的定时 API 请求。
     *
     * @see DashboardDTO
     */
    @Tag(name = "/server/" + ApiConstant.LATEST + "/monitor")
    @Operation(summary = "工作台首页聚合数据（监控+大区+频道+在线人数，合并为1个请求）")
    @GetMapping("/" + ApiConstant.LATEST + "/dashboard")
    public ResultBody<DashboardDTO> getDashboard(
            @RequestParam(value = "interfaceName", required = false) String interfaceName) {
        // 监控快照（强制实时采集：传一个非空值使 getSnapshot 不走 latestSnapshot 缓存分支）
        String refreshKey = interfaceName != null ? interfaceName : "__REFRESH__";
        ServerMonitorSnapshotDTO monitor = serverMonitorService.getSnapshot(refreshKey);

        // 大区列表 + 频道列表 + 在线人数
        List<WorldListRtnDTO> worldList = serverService.worldList();
        Map<Integer, List<ChannelListRtnDTO>> channelList = new HashMap<>();
        List<Integer> worldIds = worldList.stream().map(WorldListRtnDTO::getId).toList();
        for (Integer wid : worldIds) {
            channelList.put(wid, serverService.channelList(wid));
        }
        Integer onlinePlayerCount = commonService.getAllWorldsOnlinePlayersCount(worldIds);

        return ResultBody.success(DashboardDTO.builder()
                .monitor(monitor)
                .worldList(worldList)
                .channelList(channelList)
                .onlinePlayerCount(onlinePlayerCount)
                .build());
    }

    @Tag(name = "/server/" + ApiConstant.LATEST + "/monitor")
    @Operation(summary = "获取服务器监控快照")
    @GetMapping("/" + ApiConstant.LATEST + "/monitor/snapshot")
    public ResultBody<ServerMonitorSnapshotDTO> getSnapshot(
            @RequestParam(value = "interfaceName", required = false) String interfaceName) {
        return ResultBody.success(serverMonitorService.getSnapshot(interfaceName));
    }

    @Tag(name = "/server/" + ApiConstant.LATEST + "/monitor")
    @Operation(summary = "获取服务器监控历史快照与 CPU 异常事件")
    @GetMapping("/" + ApiConstant.LATEST + "/monitor/history")
    public ResultBody<org.gms.model.dto.monitor.ServerMonitorHistoryDTO> getHistory(
            @RequestParam(value = "minutes", required = false) Integer minutes,
            @RequestParam(value = "range", required = false) String range,
            @RequestParam(value = "start", required = false) Long start,
            @RequestParam(value = "end", required = false) Long end) {
        return ResultBody.success(serverMonitorService.getHistory(minutes, range, start, end));
    }

    @Tag(name = "/server/" + ApiConstant.LATEST + "/monitor")
    @Operation(summary = "获取 CPU 监控阈值配置")
    @GetMapping("/" + ApiConstant.LATEST + "/monitor/cpu-config")
    public ResultBody<CpuMonitorConfigDTO> getCpuConfig() {
        return ResultBody.success(serverMonitorService.getCpuMonitorConfig());
    }

    @Tag(name = "/server/" + ApiConstant.LATEST + "/monitor")
    @Operation(summary = "更新 CPU 监控阈值配置")
    @PostMapping("/" + ApiConstant.LATEST + "/monitor/cpu-config")
    public ResultBody<CpuMonitorConfigDTO> updateCpuConfig(@RequestBody SubmitBody<CpuMonitorConfigDTO> request) {
        return ResultBody.success(request, serverMonitorService.updateCpuMonitorConfig(request.getData()));
    }
}
