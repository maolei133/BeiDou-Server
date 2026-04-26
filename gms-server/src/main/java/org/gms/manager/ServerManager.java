package org.gms.manager;

import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.gms.ServerApplication;
import org.gms.constants.net.ServerConstants;
import org.gms.net.server.Server;
import org.gms.provider.CachingDataProvider;
import org.gms.provider.DataProviderFactory;
import org.gms.server.ItemInformationProvider;
import org.gms.util.I18nUtil;
import org.springdoc.core.properties.SpringDocConfigProperties;
import org.springdoc.core.properties.SwaggerUiConfigProperties;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.net.InetAddress;
import java.util.Map;

@Component
@Slf4j
public class ServerManager implements ApplicationContextAware, ApplicationRunner, DisposableBean {
    @Getter
    private static ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(@NonNull ApplicationContext applicationContext) throws BeansException {
        ServerManager.applicationContext = applicationContext;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // --- 两阶段缓存流程 ---
        CachingDataProvider.startRecording();
        ItemInformationProvider.initItemInformationService();
        Server.getInstance().init();
        CachingDataProvider.stopRecording();

        DataProviderFactory.getProviders().values().stream()
                .filter(p -> p instanceof CachingDataProvider)
                .map(p -> (CachingDataProvider) p)
                .forEach(CachingDataProvider::transferStartupToLongTerm);

        // --- 新增：启动后缓存状态分析 ---
        log.info("========== 启动后长期缓存状态分析 ==========");
        long totalCachedItems = 0;
        for (Map.Entry<String, CachingDataProvider> entry : DataProviderFactory.getProviders().entrySet()) {
            String wzName = entry.getKey();
            CachingDataProvider provider = entry.getValue();
            long cacheSize = provider.getLongTermCache().estimatedSize();
            if (cacheSize > 0) {
                log.info("WZ文件: {} -> 持有的DOM对象数量: {}", wzName, cacheSize);
                totalCachedItems += cacheSize;
            }
        }
        log.info("总计持有的DOM对象数量: {}", totalCachedItems);
        log.info("==========================================");


        // --- 原始的服务器启动后日志打印代码 ---
        SpringDocConfigProperties springDocConfigProperties = applicationContext.getBean(SpringDocConfigProperties.class);
        SwaggerUiConfigProperties swaggerUiConfigProperties = applicationContext.getBean(SwaggerUiConfigProperties.class);
        Environment environment = applicationContext.getBean(Environment.class);
        log.info(I18nUtil.getLogMessage("ServerManager.run.info3"), ServerConstants.BEI_DOU_VERSION, ServerConstants.BEI_DOU_BUILD_TIME);
        if (springDocConfigProperties.getApiDocs().isEnabled() && swaggerUiConfigProperties.isEnabled()) {
            log.info(I18nUtil.getLogMessage("ServerManager.run.info1"), InetAddress.getLocalHost().getHostAddress(), environment.getProperty("server.port"));
        }
        // 判断是否集成前端，集成则提示前端地址
        try(InputStream resource = ServerApplication.class.getClassLoader().getResourceAsStream("static/index.html")) {
            if (resource != null) {
                log.info(I18nUtil.getLogMessage("ServerManager.run.info2"), InetAddress.getLocalHost().getHostAddress(), environment.getProperty("server.port"));
            }
        }
    }

    @Override
    public void destroy() throws Exception {
        Server.getInstance().shutdownInternal(false);
    }
}
