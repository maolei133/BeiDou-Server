package org.gms.net;

import lombok.extern.slf4j.Slf4j;
import org.gms.client.Client;
import org.gms.net.packet.InPacket;
import org.gms.scripting.AbstractScriptManager;

import java.util.HashMap;
import java.util.Map;

/**
 * 一个通用的数据包处理器，它将处理逻辑委托给一个外部的 GraalVM JS 脚本。
 * 每个实例都关联一个特定的脚本文件。
 * 这种设计实现了“一个操作码一个脚本”的模式，提供了高度的解耦和错误隔离。
 */
@Slf4j
public class ScriptedPacketHandler implements PacketHandler {

    private final String scriptPath;

    /**
     * 构造一个新的脚本化数据包处理器。
     *
     * @param scriptPath 脚本的相对路径，例如 "packet/login/LOGIN_PASSWORD.js"
     */
    public ScriptedPacketHandler(String scriptPath) {
        this.scriptPath = scriptPath;
    }

    /**
     * 处理数据包。
     * 此方法会执行关联的脚本文件，并将 client 和 packet 对象注入到脚本的作用域中。
     *
     * @param packet 接收到的数据包，类型为项目自定义的 InPacket。
     * @param client 发送数据包的客户端实例。
     */
    @Override
    public void handlePacket(InPacket packet, Client client) {
        // 为脚本执行准备绑定的变量
        Map<String, Object> bindings = new HashMap<>();
        bindings.put("client", client);
        bindings.put("packet", packet);
        // 注意：'log' 对象会由 AbstractScriptManager.executeScript 方法自动注入

        try {
            // 使用统一的脚本管理器执行脚本
            AbstractScriptManager.executeScript(scriptPath, bindings);
        } catch (Exception e) {
            // 捕获在脚本执行期间可能发生的任何未预料到的异常
            log.error("执行数据包处理脚本 [{}] 时发生严重错误。", scriptPath, e);
            // 可以在这里决定是否断开客户端连接，以防止潜在的未知状态
            // client.disconnect(true, false);
        }
    }

    @Override
    public boolean validateState(Client c) {
        // 默认情况下，我们假设脚本内部会处理所有状态验证。
        // 如果需要，可以在脚本执行前或执行后添加更复杂的逻辑。
        return true;
    }
}
