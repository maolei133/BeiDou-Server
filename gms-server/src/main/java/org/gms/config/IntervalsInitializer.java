package org.gms.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.gms.net.server.channel.handlers.ItemRewardHandler;
import org.gms.property.ServiceProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class IntervalsInitializer {

    private final ServiceProperty serviceProperty;

    @EventListener(ApplicationReadyEvent.class)
    public void init() {
        // 注入执行间隔配置
        ItemRewardHandler.setIntervals(
                serviceProperty.getMobVacInterval(),
                serviceProperty.getItemVacInterval(),
                serviceProperty.getBagOrganizeInterval()
        );
        // 启动热加载任务（如果尚未启动）
        ItemRewardHandler.init();
        log.info("已初始化脚本执行间隔：吸怪={}ms，吸物={}ms，背包整理={}ms",
                serviceProperty.getMobVacInterval(),
                serviceProperty.getItemVacInterval(),
                serviceProperty.getBagOrganizeInterval());
    }
}