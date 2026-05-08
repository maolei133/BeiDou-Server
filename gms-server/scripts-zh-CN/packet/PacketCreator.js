/**
 * =================================================================================
 * 脚本化封包创建器 - 主脚本
 * =================================================================================
 *
 * 这个脚本包含了所有被脚本化的封包创建函数的实现。
 * Java 的字节码增强机制 (ByteBuddy + 自定义ClassLoader) 会在调用 PacketCreator 的方法时，
 * 优先在这里寻找并执行同名的函数。
 *
 * @global log 由 Java 注入的 SLF4J 日志记录器。
 *
 * =================================================================================
 */

// --- 导入需要的 Java 类 ---
// GraalJS 环境允许我们直接使用 Java.type() 来引用 Java 类
var OutPacket = Java.type('org.gms.net.packet.OutPacket');
var SendOpcode = Java.type('org.gms.net.opcodes.SendOpcode');
/*

/!**
 * 获取登录失败的封包。
 * 这个JS函数会自动覆盖 Java 中的 PacketCreator.getLoginFailed(int reason) 方法。
 *
 * @param {number} reason - 登录失败的原因代码。
 * @returns {OutPacket} - 构建好的登录失败封包。
 *!/
function getLoginFailed(reason) {
    // log 是由 ScriptEngine 自动注入的，可以直接使用
    log.info("正在通过 JS 脚本创建 getLoginFailed 封包, 原因: {}", reason);

    // 错误修正：直接传递 SendOpcode 枚举对象，而不是它的整数值。
    var p = OutPacket.create(SendOpcode.LOGIN_STATUS);
    p.writeByte(reason);
    p.writeByte(0);
    p.writeInt(0);

    // 返回 OutPacket 对象，拦截器会自动处理它
    return p;
}
*/

/*

/!**
 * 一个在 Java 中不存在的、全新的封包创建函数。
 * 只能通过 PacketCreator.invoke("getLoginFailednew", ...) 的方式从JS中调用。
 * @param {number} reason - 登录失败的原因代码。
 * @returns {OutPacket} - 构建好的登录失败封包。
 *!/
function getLoginFailednew(reason) {
    log.info("正在执行一个Java中不存在的全新JS封包函数 getLoginFailednew, 原因: {}", reason);
    var p = OutPacket.create(SendOpcode.LOGIN_STATUS);
    p.writeByte(reason);
    p.writeByte(1); // 与原版不同的标识，用于测试
    p.writeInt(0);
    return p;
}

*/

// --- 在这里可以添加更多需要脚本化的封包函数 ---
// 例如，如果要覆盖 getPing() 方法：
/*
function getPing() {
    log.info("正在通过 JS 脚本创建 getPing 封包");
    // 注意：这里也应该直接传递枚举对象
    return OutPacket.create(SendOpcode.PING);
}
*/

// log.info("脚本化封包创建器 (packet/PacketCreator.js) 加载完毕。");
