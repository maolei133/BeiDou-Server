package org.gms.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import org.gms.constants.api.ApiConstant;
import org.gms.model.dto.ResultBody;
import org.gms.model.dto.SubmitBody;
import org.gms.model.dto.monitor.CpuMonitorConfigDTO;
import org.gms.model.dto.monitor.ServerMonitorSnapshotDTO;
import org.gms.service.ServerMonitorService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/server")
@AllArgsConstructor
public class ServerMonitorController {
    private final ServerMonitorService serverMonitorService;

    @Tag(name = "/server/" + ApiConstant.LATEST + "/monitor")
    @Operation(summary = "获取服务器监控快照")
    @GetMapping("/" + ApiConstant.LATEST + "/monitor/snapshot")
    public ResultBody<ServerMonitorSnapshotDTO> getSnapshot() {
        return ResultBody.success(serverMonitorService.getSnapshot());
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
