package org.gms.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Jackson 全局配置 (V1.1 - 增强容错).
 * <p>
 * 新增配置：所有通过Spring注入的ObjectMapper实例都将忽略JSON字段的大小写，
 * 以提高对不规范JSON数据的容错能力。
 * </p>
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
     * <p>
     * <b>新增配置:</b> 启用 {@code ACCEPT_CASE_INSENSITIVE_PROPERTIES}，
     * 使其在反序列化时能够匹配大小写不一致的JSON字段。
     *
     * @return 一个配置了大小写不敏感的、标准的 ObjectMapper 实例
     */
    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        // 启用不区分大小写的属性反序列化
        objectMapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
        return objectMapper;
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
     * <p>
     * <b>新增配置:</b> 同样启用大小写不敏感属性匹配，保持行为一致性。
     *
     * @return 一个配置了 NON_DEFAULT 序列化规则和大小写不敏感的 ObjectMapper 实例
     */
    @Bean
    @Qualifier("sparseItemObjectMapper")
    public ObjectMapper sparseItemObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        // 设置序列化规则：不包含值为默认值的字段 (null, 0, false 等)
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_DEFAULT);
        // 启用不区分大小写的属性反序列化
        objectMapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
        return objectMapper;
    }
}
