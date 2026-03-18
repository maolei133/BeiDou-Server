package org.gms.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mybatisflex.core.paginate.Page;
import lombok.AllArgsConstructor;
import org.gms.dao.entity.ItemTraceLogsDO;
import org.gms.model.dto.ResultBody;
import org.gms.model.dto.TraceabilityQueryDTO;
import org.gms.model.pojo.TraceabilityRules;
import org.gms.service.TraceabilityConfigService;
import org.gms.service.TraceabilityService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 物品溯源系统API控制器 (V2.6 - 增加日志查询接口).
 */
@RestController
@RequestMapping("/v1/traceability")
@AllArgsConstructor
public class TraceabilityController {

    private final TraceabilityConfigService configService;
    private final TraceabilityService traceabilityService;
    private final ObjectMapper objectMapper;

    /**
     * 根据条件分页查询物品溯源日志。
     *
     * @param queryDTO 查询条件和分页参数
     * @return 分页后的日志数据
     */
    @GetMapping("/logs")
    public ResultBody<Page<ItemTraceLogsDO>> queryTraceLogs(TraceabilityQueryDTO queryDTO) {
        Page<ItemTraceLogsDO> page = traceabilityService.queryLogs(queryDTO);
        return ResultBody.success(page);
    }

    /**
     * 获取当前应用的溯源配置。
     *
     * @param useDefault 是否强制获取内置的默认配置
     * @return 溯源配置POJO
     */
    @GetMapping("/config")
    public ResultBody<TraceabilityRules> getTraceabilityConfig(@RequestParam(required = false) boolean useDefault) {
        if (useDefault) {
            return ResultBody.success(configService.getDefaultConfig());
        }
        return ResultBody.success(configService.getTraceabilityConfig());
    }

    /**
     * 更新溯源配置。
     *
     * @param config 新的配置JSON对象
     * @return 操作结果
     */
    @PutMapping("/config")
    public ResultBody<String> updateTraceabilityConfig(@RequestBody JsonNode config) {
        // 调用溯源系统专属的配置更新方法
        if (configService.saveTraceabilityConfig(config)) {
            return ResultBody.success("配置更新成功，已触发热重载。");
        }
        return ResultBody.error("未能找到溯源系统配置项，请检查游戏配置表。");
    }

    /**
     * 获取状态看板的统计数据。
     *
     * @return 包含多维度统计数据的JSON对象
     */
    @GetMapping("/stats")
    public ResultBody<JsonNode> getTraceabilityStats() {
        // 调用服务层获取真实的统计数据
        Map<String, Object> statsMap = traceabilityService.getTraceabilityStats();
        // 将Map转换为JsonNode以便统一返回格式
        JsonNode statsNode = objectMapper.convertValue(statsMap, JsonNode.class);
        return ResultBody.success(statsNode);
    }
}
