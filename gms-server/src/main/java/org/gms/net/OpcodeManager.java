package org.gms.net;

import lombok.extern.slf4j.Slf4j;
import org.gms.net.opcodes.Opcode;
import org.gms.net.opcodes.RecvOpcode;
import org.gms.net.opcodes.SendOpcode;
import org.gms.scripting.AbstractScriptManager;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 操作码（Opcode）管理器。
 * <p>
 * 负责从 JavaScript 脚本中加载、注册和管理发送（Send）和接收（Recv）操作码。
 * 本管理器是所有操作码值的“唯一真实来源”，支持覆盖现有操作码和注册全新的操作码。
 * <p>
 * 工作流程：
 * 1. 首先，将 Java 枚举（{@link RecvOpcode}, {@link SendOpcode}）中定义的默认值加载到内存。
 * 2. 接着，执行 {@code scripts/packet/OpcodeManager.js} 脚本。
 * 3. JS 脚本通过调用 {@code putRecv} 和 {@code putSend} 方法来注册操作码。
 *    - 如果操作码已存在，则其值被覆盖。
 *    - 如果是新操作码，则被动态添加。
 * 4. 对于在 Java 枚举中存在的操作码，其值会被更新，以兼容旧代码。
 * 5. 提供 {@code getRecvOpcode} 和 {@code getSendOpcode} 方法，供其他脚本（如 PacketProcessor.js）查询任何操作码的值。
 * 6. 支持通过 {@link #reloadOpcodes()} 进行热重载。
 * 7. 采用线程安全的单次加载机制，确保初始化过程仅执行一次。
 */
@Slf4j
public class OpcodeManager {

    private static final OpcodeManager INSTANCE = new OpcodeManager();
    private static final String SCRIPT_PATH = "packet/OpcodeManager.js"; // 已更新为新路径

    private final Map<String, Integer> sendOpcodes = new ConcurrentHashMap<>();
    private final Map<String, Integer> recvOpcodes = new ConcurrentHashMap<>();

    // 单一加载状态标志
    private volatile boolean isLoaded = false;
    private final Object lock = new Object();

    private OpcodeManager() {
    }

    public static OpcodeManager getInstance() {
        return INSTANCE;
    }

    /**
     * 将一个接收操作码（Recv Opcode）及其值放入管理器。
     * 此方法主要由 JS 脚本调用。
     *
     * @param name  操作码的名称。
     * @param value 操作码的十六进制整数值。
     */
    public void putRecv(String name, int value) {
        recvOpcodes.put(name, value);
    }

    /**
     * 将一个发送操作码（Send Opcode）及其值放入管理器。
     * 此方法主要由 JS 脚本调用。
     *
     * @param name  操作码的名称。
     * @param value 操作码的十六进制整数值。
     */
    public void putSend(String name, int value) {
        sendOpcodes.put(name, value);
    }

    /**
     * 根据名称获取接收操作码（Recv Opcode）的值。
     *
     * @param name 操作码的名称。
     * @return 操作码的整数值，如果不存在则返回 null。
     */
    public Integer getRecvOpcode(String name) {
        ensureLoaded();
        return recvOpcodes.get(name);
    }

    /**
     * 根据值获取接收操作码（Recv Opcode）的名称。
     *
     * @param value 操作码的整数值。
     * @return 操作码的名称，如果不存在则返回 "UNKNOWN"。
     */
    public String getRecvOpcodeName(int value) {
        ensureLoaded();
        return recvOpcodes.entrySet().stream()
                .filter(entry -> entry.getValue() == value)
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse("UNKNOWN_RECV_OPCODE");
    }

    /**
     * 获取所有接收操作码的Map副本。
     * @return a map of recv opcodes
     */
    public Map<String, Integer> getRecvOpcodes() {
        ensureLoaded();
        return new HashMap<>(recvOpcodes);
    }

    /**
     * 根据名称获取发送操作码（Send Opcode）的值。
     *
     * @param name 操作码的名称。
     * @return 操作码的整数值，如果不存在则返回 null。
     */
    public Integer getSendOpcode(String name) {
        ensureLoaded();
        return sendOpcodes.get(name);
    }

    /**
     * 获取所有发送操作码的Map副本。
     * @return a map of send opcodes
     */
    public Map<String, Integer> getSendOpcodes() {
        ensureLoaded();
        return new HashMap<>(sendOpcodes);
    }

    /**
     * 确保操作码已加载。这是由外部（如Opcode枚举的静态块）调用的入口点。
     */
    public void ensureLoaded() {
        if (!isLoaded) {
            synchronized (lock) {
                // 双重检查锁定，防止多线程环境下的重复加载
                if (!isLoaded) {
                    loadAllOpcodes();
                }
            }
        }
    }

    /**
     * 核心的加载方法，包含所有初始化逻辑。
     * 此方法只应在同步块内被调用一次。
     */
    private void loadAllOpcodes() {
//        log.info("开始加载所有Recv操作码...");

        // 1. 从 Java 枚举加载 Recv 默认值
        for (RecvOpcode op : RecvOpcode.values()) {
            recvOpcodes.put(op.name(), op.getValue());
//            log.debug("已加载操作码: 0x{} = {}", Integer.toHexString(op.getValue()).toUpperCase(), op.name());
        }
//        log.info("已从 Java 枚举中加载 {} 个默认 Recv 操作码。", recvOpcodes.size());

//        log.info("开始加载所有Send操作码...");
        // 2. 从 Java 枚举加载 Send 默认值
        for (SendOpcode op : SendOpcode.values()) {
            sendOpcodes.put(op.name(), op.getValue());
//            log.debug("已加载操作码: 0x{} = {}", Integer.toHexString(op.getValue()).toUpperCase(), op.name());
        }
        int sendCount = sendOpcodes.size();
        int recvCount = recvOpcodes.size();
//        log.info("已从 Java 枚举中加载 {} 个默认Recv 操作码， {} 个默认 Send 操作码。", recvCount, sendCount);

        // 3. 执行脚本以进行覆盖和新增
//        log.info("正在执行操作码定义脚本: {}", SCRIPT_PATH);
        Map<String, Object> bindings = new HashMap<>();
        bindings.put("manager", this);
        AbstractScriptManager.executeScript(SCRIPT_PATH, bindings);

        // 4. 将脚本中的值更新回 Java 枚举（为了兼容性）
        updateOpcodes(RecvOpcode.values(), recvOpcodes, "Recv");
        updateOpcodes(SendOpcode.values(), sendOpcodes, "Send");

        log.info("所有操作码加载完成。当前共定义 Recv: {}, Send: {} 个操作码，Java定义 Recv: {}, Send: {} 个操作码， Js定义 Recv: {}, Send: {} 个操作码", recvOpcodes.size(), sendOpcodes.size(), recvCount, sendCount, recvOpcodes.size() - recvCount, sendOpcodes.size() - sendCount);
        
        // 修复：在所有加载和更新操作完成后，再设置加载完成标志，防止竞态条件
        isLoaded = true;
    }

    /**
     * 热重载所有操作码。
     */
    public void reloadOpcodes() {
//        log.info("开始热重载所有操作码...");
        synchronized (lock) {
            // 清空状态和缓存，强制重新加载
            isLoaded = false;
            recvOpcodes.clear();
            sendOpcodes.clear();
            ensureLoaded();
        }
//        log.info("所有操作码已成功热重载。");
    }

    private void updateOpcodes(Opcode[] opcodes, Map<String, Integer> scriptValues, String type) {
        int updatedCount = 0;
        for (Opcode opcode : opcodes) {
            Integer scriptValue = scriptValues.get(opcode.name());
            if (scriptValue != null) {
                int oldValue = opcode.getValue();
                if (oldValue != scriptValue) {
                    opcode.setValue(scriptValue);
                    log.info("[{} Opcode] [JS覆盖] {}({}) -> {}", type, opcode.name(), String.format("0x%04X", oldValue), String.format("0x%04X", scriptValue));
                    updatedCount++;
                }
            }
        }
        if (updatedCount > 0) {
            log.info("从脚本更新了 {} 个 {} 类型的 Java 枚举操作码。", updatedCount, type);
        }
    }
}
