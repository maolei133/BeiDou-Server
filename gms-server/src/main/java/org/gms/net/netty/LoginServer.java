package org.gms.net.netty;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.socket.nio.NioServerSocketChannel;

public class LoginServer extends AbstractServer {
    public static final int WORLD_ID = -1;
    public static final int CHANNEL_ID = -1;
    private Channel channel;

    public LoginServer(int port) {
        super(port);
    }

    @Override
    public void start() {
        // 使用全局共享的 EventLoopGroup 代替每次都创建一个新的 NioEventLoopGroup()
        // 以此修复数百兆直接内存（Direct Memory）和冗余线程暴增的问题。
        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(NettyServerManager.getInstance().getBossGroup(), NettyServerManager.getInstance().getWorkerGroup())
                .channel(NioServerSocketChannel.class)
                .childHandler(new LoginServerInitializer());

        this.channel = bootstrap.bind(port).syncUninterruptibly().channel();
    }

    @Override
    public void stop() {
        if (channel == null) {
            throw new IllegalStateException("必须在停止之前启动 LoginServer");
        }

        channel.close().syncUninterruptibly();
    }
}
