package org.gms.net.netty;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.socket.nio.NioServerSocketChannel;

public class ChannelServer extends AbstractServer {
    private final int world;
    private final int channel;
    private Channel nettyChannel;

    public ChannelServer(int port, int world, int channel) {
        super(port);
        this.world = world;
        this.channel = channel;
    }

    @Override
    public void start() {
        // 使用全局共享的 EventLoopGroup 代替每个 Channel 创建一个新的 NioEventLoopGroup()
        // 以此修复数百兆直接内存（Direct Memory）和冗余线程暴增的问题。
        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(NettyServerManager.getInstance().getBossGroup(), NettyServerManager.getInstance().getWorkerGroup())
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelServerInitializer(world, channel));

        this.nettyChannel = bootstrap.bind(port).syncUninterruptibly().channel();
    }

    @Override
    public void stop() {
        if (nettyChannel == null) {
            throw new IllegalStateException("必须在停止之前启动 ChannelServer");
        }

        nettyChannel.close().syncUninterruptibly();
    }
}
