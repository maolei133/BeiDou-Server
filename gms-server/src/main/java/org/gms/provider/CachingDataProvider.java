package org.gms.provider;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * 注解：
 * 这是一个数据提供者的缓存装饰器 (Caching Decorator)。
 *
 * 核心设计（V5 - 增加用完即弃功能）：
 * 1. 维持V4版本的两阶段缓存策略，以确保启动稳定性。
 * 2. 新增一个核心方法 `getDataAndRelease(String path)`。此方法用于“提取-转换”模式的加载场景。
 *    它会加载数据，但不会将其存入任何缓存，确保DOM对象在使用完毕后能被立即回收。
 *    这适用于那些将数据完全提取到POJO中，不再需要原始DOM树的模块（如SkillFactory, CashItemFactory）。
 */
@Slf4j
public class CachingDataProvider implements DataProvider {

    private static boolean isRecording = false;
    private final Map<String, Data> startupCache = new ConcurrentHashMap<>();
    @Getter
    private final Cache<String, Data> longTermCache;
    private final DataProvider source;

    public CachingDataProvider(DataProvider source) {
        this.source = source;
        this.longTermCache = Caffeine.newBuilder()
                .softValues()
                .expireAfterAccess(60, TimeUnit.SECONDS)
                .evictionListener(this::logEviction)
                .build();
//        log.info("CachingDataProvider 已初始化，为 {} 启用V5缓存策略。", source.getRoot().getName());
    }

    /**
     * 标准的获取数据方法，会应用缓存策略。
     */
    @Override
    public Data getData(String path) {
//        log.info("获取数据: {}", path);
        if (isRecording) {
            return startupCache.computeIfAbsent(path, source::getData);
        } else {
            Data data = startupCache.get(path);
            if (data != null) return data;
            return longTermCache.get(path, source::getData);
        }
    }

    /**
     * 注解：新增的“用完即弃”方法。
     * 它直接从源加载数据，完全绕过缓存机制。
     * 返回的Data对象不会被缓存持有，因此在其引用被释放后，GC可以立即回收其占用的内存。
     * @param path 要加载的数据路径
     * @return 加载到的数据对象
     */
    public Data getDataAndRelease(String path) {
//         log.info("用完即弃模式加载: {}", path);
        return source.getData(path);
    }

    public void transferStartupToLongTerm() {
        if (!startupCache.isEmpty()) {
//            log.warn("正在将 {} 个启动缓存项转移到长期软引用缓存中...", startupCache.size());
            longTermCache.putAll(startupCache);
            startupCache.clear();
//            log.warn("转移完成。");
        }
    }

    @Override
    public DataDirectoryEntry getRoot() {
        return source.getRoot();
    }

    private void logEviction(String key, Data value, RemovalCause cause) {
        if (cause.wasEvicted()) {
//            log.info("长期缓存项被驱逐: [{}], 原因: [{}].", key, cause);
        }
    }

    public static void startRecording() {
        isRecording = true;
//        log.warn("启动缓存录制模式已开启 (使用强引用)...");
    }

    public static void stopRecording() {
        isRecording = false;
//        log.warn("启动缓存录制模式已关闭。");
    }
}
