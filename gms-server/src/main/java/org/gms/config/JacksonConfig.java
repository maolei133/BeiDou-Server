package org.gms.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
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
     * 提供一个标准的、全局的 ObjectMapper 实例。
     * <p>
     * 这个 Bean 被标记为 {@code @Primary}，意味着它将是 Spring 依赖注入时的首选。
     * 它不包含任何特殊的序列化规则，以确保项目大部分功能的 JSON 行为保持默认和可预测。
     *
     * @return 一个标准的 ObjectMapper 实例
     */
    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    /**
     * 提供一个专用于“稀疏存储”场景的 ObjectMapper 实例。
     * <p>
     * 核心配置: {@code JsonInclude.Include.NON_DEFAULT}
     * <ul>
     *     <li>如果字段值为 {@code null}，则不包含该字段。</li>
     *     <li>如果字段是原始类型（如 {@code int}, {@code boolean}），且其值为该类型的默认值（{@code 0}, {@code false}），则不包含该字段。</li>
     * </ul>
     * 这个 Bean 有一个特定的名称 "sparseItemObjectMapper"，只能通过 {@code @Qualifier("sparseItemObjectMapper")} 进行注入。
     * 它专门用于文档规定的五个系统（快递、仓库、雇佣商店、物品溯源、物品找回）中的物品序列化。
     *
     * @return 一个配置了 NON_DEFAULT 序列化规则的 ObjectMapper 实例
     */
    @Bean
    @Qualifier("sparseItemObjectMapper")
    public ObjectMapper sparseItemObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        // 设置序列化规则：不包含值为默认值的字段 (null, 0, false 等)
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);
        return objectMapper;
    }
}
