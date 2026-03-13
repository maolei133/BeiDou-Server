package org.gms.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Jackson 全局配置
 *
 * @author sleep
 * @since 2024-07-26
 */
@Configuration
public class JacksonConfig {

    /**
     * 配置全局 ObjectMapper, 用于统一项目的 JSON 序列化行为。
     * <p>
     * 核心配置:
     * 1.  {@code JsonInclude.Include.NON_DEFAULT}:
     *     这是实现"稀疏存储"的关键。它告诉 Jackson 在序列化时：
     *     <ul>
     *         <li>如果字段值为 {@code null}，则不包含该字段。</li>
     *         <li>如果字段是原始类型（如 {@code int}, {@code boolean}），且其值为该类型的默认值（{@code 0}, {@code false}），则不包含该字段。</li>
     *         <li>对于包装类型（如 {@code Integer}, {@code Boolean}），此配置等同于 {@code NON_NULL}，即只过滤 {@code null} 值。</li>
     *     </ul>
     *     为了确保包装类型中的 {@code 0} 或 {@code false} 也能被过滤，业务逻辑中（如 {@code toInfoRtnDTO} 方法）必须避免为这些默认值字段赋值，从而使其保持为 {@code null}。
     * <p>
     * 2.  {@code @Primary}:
     *     确保 Spring 在进行依赖注入时，会优先使用我们自定义的这个 {@code ObjectMapper} 实例，而不是默认的实例。
     *
     * @return 配置好的 ObjectMapper 实例
     */
    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        // 设置全局序列化规则：不包含值为默认值的字段 (null, 0, false 等)
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);
        return objectMapper;
    }
}
