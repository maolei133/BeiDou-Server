package org.gms.net.netty;

import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import lombok.extern.slf4j.Slf4j;

/**
 * Netty 全局线程组管理器。
 * 用于实现全局共享的 bossGroup 和 workerGroup，避免每个 Channel 创建独立的线程组导致 Direct Memory 和线程数爆炸。
 */
@Slf4j
public class NettyServerManager {

    private static volatile NettyServerManager instance;

    // 负责接收连接的线程组，通常 1 个线程就足够了，如果端口极多可以适当增加
    private final EventLoopGroup bossGroup;
    // 负责处理 IO 读写和业务逻辑的线程组，默认是 CPU 核心数 * 2
    private final EventLoopGroup workerGroup;

    private NettyServerManager() {
        // 创建全局共享的 EventLoopGroup
        this.bossGroup = new NioEventLoopGroup(1); // 接收连接的线程
        this.workerGroup = new NioEventLoopGroup(); // 默认 CPU核心数 * 2 的工作线程
        log.info("全局 Netty EventLoopGroup 初始化完成。");
    }

    public static NettyServerManager getInstance() {
        if (instance == null) {
            synchronized (NettyServerManager.class) {
                if (instance == null) {
                    instance = new NettyServerManager();
                }
            }
        }
        return instance;
    }

    public EventLoopGroup getBossGroup() {
        return bossGroup;
    }

    public EventLoopGroup getWorkerGroup() {
        return workerGroup;
    }

    /**
     * 优雅地关闭所有 Netty 线程组
     */
    public void shutdown() {
        log.info("正在关闭全局 Netty EventLoopGroup...");
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        log.info("全局 Netty EventLoopGroup 关闭完成。");
    }
}
