package org.gms.util;

import lombok.extern.slf4j.Slf4j;
import org.gms.net.packet.Packet;
import org.gms.scripting.AbstractScriptManager;

import javax.script.Invocable;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * 脚本化封包创建器的调度中心。
 * <p>
 * 该管理器采用单例模式，负责加载和执行 JavaScript 中定义的封包创建函数。
 * 它提供了一个核心的 {@link #dispatch} 方法，用于实现 "JS优先，Java保底" 的调用策略。
 * </p>
 * <p>
 * <b>工作流程:</b>
 * <ol>
 *     <li>在服务启动时，通过 {@link #getInstance()} 初始化单例，加载主脚本 {@code packet/PacketCreator.js}。</li>
 *     <li>加载脚本后，会<b>扫描并缓存</b>所有JS顶层函数名到一个高性能的Set中。</li>
 *     <li>Java 中的静态方法 (如 {@code PacketCreator.getLoginFailed}) 会调用本管理器的 {@link #dispatch} 方法。</li>
 *     <li>{@code dispatch} 方法通过查询缓存来判断JS中是否存在同名函数，此操作快速且线程安全。</li>
 *     <li>如果JS函数存在，则尝试执行。成功后返回 {@link Packet}。</li>
 *     <li>如果JS函数不存在于缓存中，或执行出错，则会执行传入的Java后备方法 ({@code Supplier<Packet>})，从而保证功能的兼容性。</li>
 *     <li>支持通过 {@link #reloadScript()} 方法进行热重载，重载会同步更新缓存。</li>
 * </ol>
 * </p>
 */
@Slf4j
public class PacketCreatorManager {

    private static final String SCRIPT_PATH = "packet/PacketCreator.js";
    private static final PacketCreatorManager INSTANCE = new PacketCreatorManager();

    private ScriptEngine engine;
    private Invocable invocable;
    // 使用线程安全的Set来缓存JS中存在的函数名，避免高频调用JS引擎
    private final Set<String> functionCache = ConcurrentHashMap.newKeySet();


    /**
     * 私有构造函数，在单例初始化时加载脚本。
     */
    private PacketCreatorManager() {
        loadScript();
    }

    /**
     * 获取 PacketCreatorManager 的单例实例。
     *
     * @return PacketCreatorManager 实例。
     */
    public static PacketCreatorManager getInstance() {
        return INSTANCE;
    }

    /**
     * 加载或重新加载脚本文件。
     * 这是一个线程安全的操作，它会同步地重载脚本并刷新函数缓存。
     */
    public synchronized void reloadScript() { // 使用 synchronized 保护全局引擎和缓存的重载
//        log.info("准备重新加载封包创建脚本: {}", SCRIPT_PATH);
        loadScript();
//        log.info("封包创建脚本重新加载完毕: {}", SCRIPT_PATH);
    }

    /**
     * 核心加载逻辑。
     * 此方法会加载JS脚本，并在成功后扫描所有顶层函数名进行缓存。
     */
    private void loadScript() {
        // 在加载/重载开始时，清空旧的缓存
        this.functionCache.clear();
        this.engine = AbstractScriptManager.getInvocableScriptEngine(SCRIPT_PATH);

        if (this.engine instanceof Invocable) {
            this.invocable = (Invocable) this.engine;
//            log.info("成功加载并初始化封包创建脚本 {} 的可调用引擎。", SCRIPT_PATH);

            // 扫描脚本中的所有顶层成员并缓存其名称
            try {
                javax.script.Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
                if (bindings != null) {
                    this.functionCache.addAll(bindings.keySet());
                    log.info("成功加载并初始化封包创建脚本 {} 的可调用引擎，已缓存 {} 个来自 {} 的JS顶层函数/变量名。", SCRIPT_PATH, this.functionCache.size(), SCRIPT_PATH);
                }
            } catch (Exception e) {
                log.error("扫描并缓存脚本 {} JS函数时出错，缓存可能不完整。", SCRIPT_PATH, e);
                // 出现异常时清空缓存，以防缓存状态不一致，强制回退到Java实现
                this.functionCache.clear();
            }
        } else {
            this.invocable = null; // 明确设置为null
            this.engine = null;
            log.warn("封包创建脚本 {} 不支持调用或不存在，所有封包创建将完全回退到Java原生实现。", SCRIPT_PATH);
        }
    }

    /**
     * 核心调度方法。用于拦截 PacketCreator 的现有方法。
     * <p>
     * 尝试在JS中执行一个函数。如果失败，则执行Java后备方法。
     * </p>
     *
     * @param methodName    要在JS中调用的函数名。
     * @param fallback      如果JS调用失败，要执行的Java后备逻辑，它应该返回一个Packet。
     * @param args          传递给JS函数的参数。
     * @return              最终的封包对象。
     */
    public Packet dispatch(String methodName, Supplier<Packet> fallback, Object... args) {
        if (hasFunction(methodName)) {
            try {
                Object result = invoke(methodName, args);
                if (result instanceof Packet) {
                    log.trace("成功通过JS脚本执行方法: {}({})", methodName, Arrays.toString(args));
                    return (Packet) result;
                }
                if (result != null) {
                    log.warn("脚本函数 '{}' 的返回值类型不是 Packet，而是 {}。已忽略，将使用Java原生实现。", methodName, result.getClass().getName());
                }
            } catch (Exception e) {
                log.error("执行JS脚本 {} 的方法 {} 时发生错误. 回退到Java原生实现。", SCRIPT_PATH, methodName, e);
            }
        }
        return fallback.get();
    }

    /**
     * 安全地检查一个顶层函数是否存在于脚本中。
     * <p>
     * 此方法通过查询预加载的缓存来实现，性能极高且线程安全，
     * 避免了直接访问JS引擎带来的并发风险。
     * </p>
     *
     * @param functionName 函数名。
     * @return 如果在缓存中存在则返回 true。
     */
    public boolean hasFunction(String functionName) {
        // 从预处理缓存中检查函数是否存在，避免高频调用JS引擎
        return this.functionCache.contains(functionName);
    }

    /**
     * 内部通用的调用方法。
     *
     * @param functionName 要在JS中调用的函数名。
     * @param args         传递给JS函数的参数。
     * @return JS函数的返回值。
     * @throws NoSuchMethodException 如果方法不存在。
     * @throws ScriptException 如果脚本执行出错。
     */
    public Object invoke(String functionName, Object... args) throws ScriptException, NoSuchMethodException {
        if (invocable == null) {
            throw new ScriptException("无法调用JS函数 '" + functionName + "'，因为脚本引擎未被正确加载。");
        }
        // 注意：此处的调用本身未加锁，依赖于业务规避高频方法的并发调用。
        return invocable.invokeFunction(functionName, args);
    }
}
