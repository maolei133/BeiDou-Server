/**
 * =================================================================================
 * 操作码（Opcode）动态管理脚本
 * =================================================================================
 *
 * 本脚本是所有操作码的“唯一真实来源”。它负责定义、覆盖和新增操作码。
 *
 * @global log      由Java注入的SLF4J日志记录器。
 * @global manager  由Java注入的 `org.gms.net.OpcodeManager` 实例。
 *
 * =================================================================================
 * 开发指南
 * =================================================================================
 *
 * 1. **覆盖现有操作码**:
 *    - 导入 `RecvOpcode` 和 `SendOpcode` 枚举类以获得IDE自动补全。
 *    - 使用 `manager.putRecv(RecvOpcode.<操作码名称>.name(), <新值>);`
 *    - `manager.putRecv(RecvOpcode.LOGIN_PASSWORD.name(), 0x01);`
 *
 * 2. **新增全新操作码**:
 *    - 直接使用字符串作为操作码名称。
 *    - `manager.putRecv("MY_CUSTOM_PACKET", 0x7FFF);`
 *    - 这个操作码在Java代码中不存在，但服务器会通过本脚本动态识别它。
 *
 * 3. **在其他脚本中使用操作码**:
 *    - 在需要使用操作码的JS脚本（如 PacketProcessor.js）中，导入 OpcodeManager。
 *    - `var OpcodeManager = Java.type('org.gms.net.OpcodeManager');`
 *    - 通过 `OpcodeManager.getInstance().getRecvOpcode("MY_CUSTOM_PACKET")` 获取值。
 *
 * 4. **热重载**:
 *    - GM命令 `!reloadopcodes` 会调用本脚本的 `reload` 函数，触发所有操作码的重新加载。
 *
 * =================================================================================
 */

// --- 1. 导入Java枚举类 (用于覆盖) ---
var RecvOpcode = Java.type('org.gms.net.opcodes.RecvOpcode');
var SendOpcode = Java.type('org.gms.net.opcodes.SendOpcode');

// log.info("开始从 JS 脚本注册和更新操作码...");
//
// // =====================================================
// // 接收操作码 (Recv Opcodes)
// // =====================================================
//
// // --- 覆盖Java中已有的操作码 ---
// manager.putRecv(RecvOpcode.LOGIN_PASSWORD.name(), 0x01);
// manager.putRecv(RecvOpcode.CHARLIST_REQUEST.name(), 0x05);
// manager.putRecv(RecvOpcode.PLAYER_LOGGEDIN.name(), 0x14);
// manager.putRecv(RecvOpcode.CHANGE_MAP.name(), 0x26);
// manager.putRecv(RecvOpcode.MOVE_PLAYER.name(), 0x29);
// manager.putRecv(RecvOpcode.PONG.name(), 0x18);
//
// // --- 新增一个Java中不存在的全新操作码 ---
// // 假设这个操作码用于处理一个自定义的客户端功能
// manager.putRecv("MY_CUSTOM_PACKET", 0x169);
// log.info("已注册新的自定义接收操作码: MY_CUSTOM_PACKET (0x169)");
//
//
// // =====================================================
// // 发送操作码 (Send Opcodes)
// // =====================================================
//
// // --- 覆盖Java中已有的操作码 ---
// manager.putSend(SendOpcode.LOGIN_STATUS.name(), 0x00);
// manager.putSend(SendOpcode.SERVERLIST.name(), 0x0A);
// manager.putSend(SendOpcode.CHARLIST.name(), 0x0B);
// manager.putSend(SendOpcode.SERVER_IP.name(), 0x0C);
// manager.putSend(SendOpcode.SET_FIELD.name(), 0x7D);
// manager.putSend(SendOpcode.PING.name(), 0x11);
//
// // --- 新增一个Java中不存在的全新操作码 ---
// // 假设这个操作码用于向客户端发送一个自定义的响应
// manager.putSend("MY_CUSTOM_RESPONSE", 0x7F);
// log.info("已注册新的自定义发送操作码: MY_CUSTOM_RESPONSE (0x7FFE)");
//
//
// log.info("JS 脚本操作码注册/更新完毕。");

/**
 * 热重载所有操作码的接口函数。
 * 可由外部脚本或GM命令调用。
 */
function reload() {
    log.info("从 JS 脚本触发操作码热重载...");
    manager.reloadOpcodes();
    log.info("操作码热重载请求已发送。");
}
