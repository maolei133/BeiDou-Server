package org.gms.property;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "gms.service")
@Component
@Data
public class ServiceProperty {
    private String language;
    private RateLimitProperty rateLimit;
    private StartupProperty startup;
    private String wanHost;
    private String lanHost;
    private String localhost;
    private int loginPort;

    /**
     * 启动参数
     */
    @Data
    public static class StartupProperty {
        /** 是否在启动时全量预加载所有WZ数据（如Skill, Quest, CashShop等） */
        private boolean allWz;
    }
    /** 速率限制 */
    @Data
    public static class RateLimitProperty {
        /** 是否启用 */
        private boolean enabled;
        /** 速率限制阈值 */
        private int limit;
        /** 速率限制时间窗口（秒） */
        private long duration;
        /** 是否自动封禁 */
        private boolean autoBan;
    }
}
