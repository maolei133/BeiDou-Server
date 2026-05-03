package org.gms.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

/**
 * Jackson 全局配置 (V1.2 - 修复HTTP消息转换器).
 * <p>
 * 修复了因自定义 ObjectMapper 导致 Spring MVC 默认的 HttpMessageConverter 失效的问题。
 * 通过继承和定制 Jackson2ObjectMapperBuilder，确保所有 ObjectMapper 实例都包含 Spring Boot 的默认配置（如 JavaTimeModule），
 * 同时明确指定用于 HTTP 消息转换的 ObjectMapper。
 * </p>
 *
 * @author sleep
 * @since 2024-07-27
 */
@Configuration
public class JacksonConfig {

    /**
     * 提供一个标准的、全局的 ObjectMapper 实例。
     * <p>
     * 这个 Bean 被标记为 {@code @Primary}，是 Spring 依赖注入和 **HTTP消息转换** 的首选。
     * 它继承了 Spring Boot 的所有默认配置（例如，对 {@code java.time.LocalDateTime} 的支持）。
     *
     * @param builder Spring Boot 自动配置的 Jackson2ObjectMapperBuilder
     * @return 一个标准的、功能完备的 ObjectMapper 实例
     */
    @Bean
    @Primary
    public ObjectMapper objectMapper(Jackson2ObjectMapperBuilder builder) {
        // 通过 builder.build() 创建的 ObjectMapper 会自动包含 Spring Boot 的所有默认配置
        // 例如：JavaTimeModule, Jdk8Module 等
        return builder.build();
    }

    /**
     * 提供一个专用于“稀疏存储”场景的 ObjectMapper 实例。
     * <p>
     * 核心配置: {@code JsonInclude.Include.NON_DEFAULT}
     * <p>
     * 这个 Bean 有一个特定的名称 "sparseItemObjectMapper"，只能通过 {@code @Qualifier("sparseItemObjectMapper")} 进行注入。
     * 它同样基于 Spring Boot 的默认配置构建，然后应用了额外的序列化规则。
     *
     * @param builder Spring Boot 自动配置的 Jackson2ObjectMapperBuilder
     * @return 一个配置了 NON_DEFAULT 序列化规则的 ObjectMapper 实例
     */
    @Bean
    @Qualifier("sparseItemObjectMapper")
    public ObjectMapper sparseItemObjectMapper(Jackson2ObjectMapperBuilder builder) {
        // 从 builder 克隆一个独立的配置实例，避免污染全局 builder
        return builder.createXmlMapper(false) // createXmlMapper(false) 是一个克隆 builder 的标准方法
                .serializationInclusion(JsonInclude.Include.NON_DEFAULT)
                .build();
    }
}
