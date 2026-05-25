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
import org.gms.net.server.coordinator.session.IpAddresses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.gms.util.PacketCreator;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public abstract class ServerChannelInitializer extends ChannelInitializer<SocketChannel> {
    private static final Logger log = LoggerFactory.getLogger(ServerChannelInitializer.class);
    private static final int IDLE_TIME_SECONDS = 30;
    private static final ChannelHandler sendPacketLogger = new OutPacketLogger();
    private static final ChannelHandler receivePacketLogger = new InPacketLogger();

    static final AtomicLong sessionId = new AtomicLong(7777);

    // ─── 可信 Proxy Protocol 来源 ───

    /**
     * 受信任的代理来源 IP 集合（启动时静态填充）。
     *
     * <p>可信来源：127.0.0.1 + 本机所有网卡 IPv4 + RFC 1918 内网段。
     * 后续可通过 GameConfig 扩展：{@code proxy.trusted.sources}。</p>
     */
    private static final Set<String> TRUSTED_PROXY_IPS = new HashSet<>();

    static {
        TRUSTED_PROXY_IPS.add("127.0.0.1");
        TRUSTED_PROXY_IPS.add("0:0:0:0:0:0:0:1");
        collectLocalNicIps();
        // 后续接入: GameConfig.getServerString("proxy.trusted.sources").split(",")
    }

    /** 枚举本机所有 UP 状态的网卡 IPv4 地址加入可信列表。 */
    private static void collectLocalNicIps() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface ni = ifaces.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr.isLoopbackAddress()) continue;
                    String ip = addr.getHostAddress();
                    if (ip.contains(":")) continue; // 仅 IPv4
                    TRUSTED_PROXY_IPS.add(ip);
                }
            }
        } catch (SocketException e) {
            log.warn("枚举本机网卡失败，Proxy Protocol 可信来源仅包含 127.0.0.1 + RFC 1918", e);
        }
    }

    /**
     * 判断物理 IP 是否为可信代理来源。
     *
     * <p>两级匹配：
     * <ol>
     * <li>精确匹配：{@link #TRUSTED_PROXY_IPS}（127.0.0.1 + 本机网卡 IP）</li>
     * <li>RFC 1918 内网段：复用 {@link IpAddresses#isLanAddress(String)}</li>
     * </ol>
     */
    private static boolean isTrustedProxySource(String physicalIp) {
        if (physicalIp == null) return false;
        if (TRUSTED_PROXY_IPS.contains(physicalIp)) return true;
        return IpAddresses.isLanAddress(physicalIp);
    }

    // ─── Pipeline 初始化 ───

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

        addProxyProtocolHandler(socketChannel.pipeline(), client);

        writeInitialUnencryptedHelloPacket(socketChannel, sendIv, recvIv);

        setUpHandlers(socketChannel.pipeline(), sendIv, recvIv, client);
    }

    // ─── Proxy Protocol v2 检测 ───

    /**
     * HAProxy Protocol v2 自定义解码 handler。
     *
     * <p>检测首包是否为 HAProxy v2 签名，匹配时校验版本/命令/地址长度/
     * 可信来源，通过后覆盖 Client.remoteAddress 为真实源 IP。不匹配时
     * 原样透传。处理完成后自移除。</p>
     */
    private void addProxyProtocolHandler(ChannelPipeline pipeline, Client client) {
        final byte[] SIG = {
                0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A,
                0x51, 0x55, 0x49, 0x54, 0x0A
        };

        pipeline.addLast(new ChannelInboundHandlerAdapter() {
            private boolean done;

            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                if (done) {
                    super.channelRead(ctx, msg);
                    return;
                }
                done = true;

                if (!(msg instanceof ByteBuf buf) || buf.readableBytes() < 16) {
                    forward(ctx, msg);
                    return;
                }

                // 检测 v2 签名
                buf.markReaderIndex();
                for (byte b : SIG) {
                    if (buf.readByte() != b) {
                        buf.resetReaderIndex();
                        forward(ctx, msg);
                        return;
                    }
                }

                // 解析 v2 头部
                int verCmd = buf.readByte();
                int family = buf.readUnsignedByte();
                int addrLen = buf.readUnsignedShort();

                int version = (verCmd >> 4) & 0x0F;
                int command = verCmd & 0x0F;
                if (version != 2 || command != 1) {
                    log.warn("Proxy Protocol: 不支持的版本/命令 version={} command={}", version, command);
                    buf.resetReaderIndex();
                    forward(ctx, msg);
                    return;
                }
                if (addrLen > buf.readableBytes()) {
                    log.warn("Proxy Protocol: 地址长度超实际数据 addrLen={} readable={}", addrLen, buf.readableBytes());
                    buf.resetReaderIndex();
                    forward(ctx, msg);
                    return;
                }

                // 可信来源检查
                String physicalIp = client.getEffectiveAddress();
                if (!isTrustedProxySource(physicalIp)) {
                    log.warn("Proxy Protocol: 非可信来源 {} 携带 Proxy 头，已忽略", physicalIp);
                    buf.resetReaderIndex();
                    forward(ctx, msg);
                    return;
                }

                // 提取源 IP
                if (family == 0x11) {  // IPv4 over TCP
                    byte[] addr = new byte[12];
                    buf.readBytes(addr);
                    String realIp = (addr[0] & 0xFF) + "." + (addr[1] & 0xFF)
                            + "." + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
                    // [链路调试] log.info("[链路] Proxy: physical={} → remote={}", physicalIp, realIp);
                    client.setRemoteAddress(realIp);
                } else if (family == 0x21) {  // IPv6 over TCP
                    log.warn("Proxy Protocol: IPv6 暂不支持，已跳过");
                }

                forward(ctx, msg);
            }

            private void forward(ChannelHandlerContext ctx, Object msg) throws Exception {
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
