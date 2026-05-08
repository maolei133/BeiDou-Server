/**
 * 数据包处理器脚本注册中心
 *
 * 这个脚本的唯一职责是定义哪些数据包操作码（Opcode）由哪个外部脚本文件处理。
 * 它会在 PacketProcessor 初始化时以及执行热更新时被调用。
 *
 * @global log       由 Java 注入的 SLF4J Logger 实例。
 * @global processor 由 Java 注入的 PacketProcessor 实例。
 */

// log.info("开始注册脚本化的数据包处理器...");

// 导入 RecvOpcode 以便在脚本中使用
var RecvOpcode = Java.type('org.gms.net.opcodes.RecvOpcode');
// 导入 OpcodeManager 以获取所有（包括新增的）操作码
var OpcodeManager = Java.type('org.gms.net.OpcodeManager');

// 检查 'processor' 对象是否存在
if (typeof processor === 'undefined') {
    log.error("致命错误：'processor' 对象未从 Java 注入，无法注册任何脚本处理器。");
} else {
    // ---------------------------------------------------------------------------------
    // 在这里注册你的所有脚本化处理器
    // 格式: processor.registerScriptedHandler(操作码, "脚本相对路径");
    // ---------------------------------------------------------------------------------

    // // --- 示例 1: 注册一个由 Java 枚举定义的操作码 ---
    // processor.registerScriptedHandler(RecvOpcode.LOGIN_PASSWORD, "packet/login/LOGIN_PASSWORD.js");
    // log.info("已将 LOGIN_PASSWORD 路由到 'packet/login/LOGIN_PASSWORD.js'");

    // // --- 示例 2: 注册一个在 OpcodeManager.js 中新增的自定义操作码 ---
    // // 这个操作码必须提前注册，比如在 OpcodeManager.js 中使用 manager.putRecv("MY_CUSTOM_PACKET", 0x7FFF);
    // var myCustomPacketOpcode = OpcodeManager.getInstance().getRecvOpcode("MY_CUSTOM_PACKET");
    // if (myCustomPacketOpcode !== null) {
    //     processor.registerScriptedHandler(myCustomPacketOpcode, "packet/custom/MY_CUSTOM_PACKET.js");
    //     log.info("已将新的自定义操作码 MY_CUSTOM_PACKET (值: {}) 路由到 'packet/custom/MY_CUSTOM_PACKET.js'", myCustomPacketOpcode);
    // } else {
    //     log.warn("无法注册 MY_CUSTOM_PACKET 的处理器，因为在 OpcodeManager 中找不到该操作码。");
    // }


    // ... 在这里添加更多路由规则
    log.info("JS脚本化的数据包处理器注册完毕。");
}
