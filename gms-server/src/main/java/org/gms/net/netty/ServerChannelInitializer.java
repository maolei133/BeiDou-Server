package org.gms.net.netty;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.gms.client.Client;
import org.gms.constants.net.ServerConstants;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.timeout.IdleStateHandler;
import org.gms.net.encryption.ClientCyphers;
import org.gms.net.encryption.InitializationVector;
import org.gms.net.encryption.PacketCodec;
import org.gms.net.packet.logging.InPacketLogger;
import org.gms.net.packet.logging.OutPacketLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.util.PacketCreator;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicLong;

public abstract class ServerChannelInitializer extends ChannelInitializer<SocketChannel> {
    private static final Logger log = LoggerFactory.getLogger(ServerChannelInitializer.class);
    private static final int IDLE_TIME_SECONDS = 30;
    private static final ChannelHandler sendPacketLogger = new OutPacketLogger();
    private static final ChannelHandler receivePacketLogger = new InPacketLogger();

    static final AtomicLong sessionId = new AtomicLong(7777);

    String getRemoteAddress(Channel channel) {
        String remoteAddress = "null";
        try {
            remoteAddress = ((InetSocketAddress) channel.remoteAddress()).getAddress().getHostAddress();
        } catch (NullPointerException npe) {
            log.warn("Unable to get remote address from netty Channel: {}", channel, npe);
        }

        return remoteAddress;
    }

    void initPipeline(SocketChannel socketChannel, Client client) {
        final String physicalIp = getRemoteAddress(socketChannel);
        // [链路调试] log.info("[链路] 新连接 physicalIp={}", physicalIp);

        final InitializationVector sendIv = InitializationVector.generateSend();
        final InitializationVector recvIv = InitializationVector.generateReceive();

        // ① Proxy Protocol 解码器（最前端，直连时自动透传）
        addProxyProtocolHandler(socketChannel.pipeline(), client);

        // ② MapleStory hello 握手
        writeInitialUnencryptedHelloPacket(socketChannel, sendIv, recvIv);

        // ③ 加密/解码/Idle/Client
        setUpHandlers(socketChannel.pipeline(), sendIv, recvIv, client);
    }

    /**
     * 自定义 Proxy Protocol 检测 handler。
     *
     * <p>替代 HAProxyMessageDecoder —— 后者在直连时把 MapleStory 二进制封包
     * 当作非法 HAProxy 头并触发 failFast 断连。</p>
     *
     * <p>此 handler 检查首包首 12 字节是否为 HAProxy v2 签名。匹配则解析
     * 真实源 IP 并覆盖 Client.remoteAddress；不匹配则原样透传。处理完成后
     * 自移除，零 pipeline 残留。</p>
     */
    private void addProxyProtocolHandler(ChannelPipeline pipeline, Client client) {
        // HAProxy v2 signature
        final byte[] SIG = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

        pipeline.addLast(new ChannelInboundHandlerAdapter() {
            private boolean checked;

            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                if (checked) {
                    super.channelRead(ctx, msg);
                    return;
                }
                checked = true;

                if (msg instanceof ByteBuf buf && buf.readableBytes() >= 16) {
                    buf.markReaderIndex();
                    boolean match = true;
                    for (byte b : SIG) {
                        if (buf.readByte() != b) { match = false; break; }
                    }
                    if (match) {
                        buf.readByte();               // version + command
                        int family = buf.readUnsignedByte();
                        buf.readUnsignedShort();      // address length
                        if (family == 0x11) {          // IPv4 over TCP
                            byte[] addr = new byte[12];
                            buf.readBytes(addr);
                            String realIp = (addr[0] & 0xFF) + "." + (addr[1] & 0xFF)
                                    + "." + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
                            // [链路调试] log.info("[链路] Proxy: physical={} → remote={}", client.getEffectiveAddress(), realIp);
                            client.setRemoteAddress(realIp);
                        }
                    } else {
                        // [链路调试] log.info("[链路] 直连（非Proxy头）: physical={}", client.getEffectiveAddress());
                        buf.resetReaderIndex();
                    }
                } else if (msg instanceof ByteBuf) {
                    // [链路调试] log.info("[链路] 直连（首包不足16字节）: physical={}", client.getEffectiveAddress());
                }

                if (msg instanceof ByteBuf b && b.isReadable()) {
                    super.channelRead(ctx, b);
                }
                ctx.pipeline().remove(this);
            }
        });
    }

    private void writeInitialUnencryptedHelloPacket(SocketChannel socketChannel, InitializationVector sendIv, InitializationVector recvIv) {
        socketChannel.writeAndFlush(Unpooled.wrappedBuffer(PacketCreator.getHello(ServerConstants.VERSION, sendIv, recvIv).getBytes()));
    }

    private void setUpHandlers(ChannelPipeline pipeline, InitializationVector sendIv, InitializationVector recvIv,
                               Client client) {
        pipeline.addLast("IdleStateHandler", new IdleStateHandler(0, 0, IDLE_TIME_SECONDS));
        pipeline.addLast("PacketCodec", new PacketCodec(ClientCyphers.of(sendIv, recvIv)));
        pipeline.addLast("Client", client);

        pipeline.addBefore("Client", "SendPacketLogger", sendPacketLogger);
        pipeline.addBefore("Client", "ReceivePacketLogger", receivePacketLogger);
    }
}
