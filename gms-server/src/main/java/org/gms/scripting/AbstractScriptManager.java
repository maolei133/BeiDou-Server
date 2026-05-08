/*
This file is part of the OdinMS Maple Story Server
Copyright (C) 2008 Patrick Huy <patrick.huy@frz.cc>
Matthias Butz <matze@odinms.de>
Jan Christian Meyer <vimes@odinms.de>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation version 3 as published by
the Free Software Foundation. You may not use, modify or distribute
this program under any other version of the GNU Affero General Public
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.gms.scripting;

import com.oracle.truffle.js.scriptengine.GraalJSScriptEngine;
import org.apache.logging.log4j.message.MapMessage;
import org.gms.client.Client;
import org.gms.manager.ServerManager;
import org.gms.property.ServiceProperty;
import org.gms.server.logging.AuditLogger;
import org.gms.server.logging.LogAction;
import org.gms.server.logging.LogModule;
import org.gms.util.PacketCreatorManager;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Engine;
import org.graalvm.polyglot.HostAccess;
import org.graalvm.polyglot.io.IOAccess;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * 脚本管理器的抽象基类，提供了通用的脚本执行、加载功能。
 *
 * @author Matze
 */
public abstract class AbstractScriptManager {
    private static final Logger log = LoggerFactory.getLogger(AbstractScriptManager.class);

    private static final Engine SHARED_ENGINE;
    private static final String ECMA_SCRIPT_VERSION = "2024";
    private static final boolean SYNTAX_EXTENSIONS_ENABLED = true;

    static {
        SHARED_ENGINE = Engine.newBuilder()
                .allowExperimentalOptions(true)
                .option("engine.WarnInterpreterOnly", "false")
                .build();

        log.info("============== GraalVM JS 引擎 ==============");
        log.info("GraalVM JS 版本: {}", getGraalJSVersion());
        log.info("ECMAScript 标准: {}", ECMA_SCRIPT_VERSION);
        log.info("JS 语法扩展 (js.syntax-extensions): {}", SYNTAX_EXTENSIONS_ENABLED);
        log.info("Java 主机类交互 (Java.type): 已开启");
        log.info("共享全局引擎 (节约内存模式): 已开启");
        log.info("===========================================");
    }

    /**
     * 重新加载指定路径的脚本。
     * 这是一个给GM命令等外部功能调用的入口。
     *
     * @param scriptPath 脚本的相对路径。
     * @return 如果找到了对应的处理器并成功触发重载则返回true，否则返回false。
     */
    public static boolean reloadScript(String scriptPath) {
        // 特殊处理 PacketCreator 的重载
        if ("packet/PacketCreator.js".equalsIgnoreCase(scriptPath)) {
            PacketCreatorManager.getInstance().reloadScript();
            return true;
        }

        // 这里可以为其他可重载的脚本管理器添加逻辑
        // 例如:
        // if (scriptPath.startsWith("npc/")) {
        //     NpcScriptManager.getInstance().reloadScript(scriptPath);
        //     return true;
        // }

        log.warn("无法重载脚本，因为没有找到路径为 {} 的特定重载处理器。", scriptPath);
        return false;
    }


    /**
     * 通用脚本执行器。
     * 它为脚本提供了一个可靠的执行环境，并只注入与当前执行上下文相关的实例。
     *
     * @param relativePath 脚本的相对路径 (例如 "packet/PacketProcessor.js")
     * @param bindings     一个包含本次调用特定的、要暴露给脚本的Java实例的Map (例如 client, packet)。
     */
    public static void executeScript(String relativePath, Map<String, Object> bindings) {
        // 复用语言目录解析逻辑
        Path actualPath = getActualScriptPath(relativePath);
        if (actualPath == null) {
            log.info("通用脚本执行器：在默认目录和语言目录中均未找到脚本文件 {}，跳过执行。", relativePath);
            return;
        }

        // 使用共享的 Engine 构建独立的 Context
        Context.Builder contextBuilder = Context.newBuilder("js")
                .allowExperimentalOptions(true)
                .allowHostAccess(HostAccess.ALL)
                .allowHostClassLookup(s -> true) // 关键：允许脚本使用 Java.type()
                .allowNativeAccess(true)
                .allowCreateThread(true)
                .allowIO(IOAccess.ALL)
                .option("js.syntax-extensions", String.valueOf(SYNTAX_EXTENSIONS_ENABLED))
                .option("js.ecmascript-version", ECMA_SCRIPT_VERSION);

        try (GraalJSScriptEngine engine = GraalJSScriptEngine.create(SHARED_ENGINE, contextBuilder)) {
            // 1. 注入为当前脚本创建的 Logger 实例
            Logger scriptLogger = LoggerFactory.getLogger(actualPath.toString().replace('\\', '.'));
            engine.put("log", scriptLogger);
            
            // 2. 注入一个被代理的 PacketCreator 对象，使其能够调用JS中新增的方法
            engine.put("PacketCreator", new org.gms.agent.ScriptableJavaClassProxy(org.gms.util.PacketCreator.class));

            // 3. 注入本次调用特定的上下文实例 (例如 client, packet, processor)
            if (bindings != null && !bindings.isEmpty()) {
                for (Map.Entry<String, Object> entry : bindings.entrySet()) {
                    engine.put(entry.getKey(), entry.getValue());
                }
            }

            try (BufferedReader br = Files.newBufferedReader(actualPath, StandardCharsets.UTF_8)) {
//                scriptLogger.info("开始执行脚本...");
                engine.eval(br);
//                scriptLogger.info("脚本执行完毕。");
            }

        } catch (final ScriptException | IOException t) {
            log.error("通用脚本执行器在执行脚本 [{}] 时发生错误，脚本路径：{}，错误详情：{}", actualPath.getFileName().toString(), actualPath, t.getMessage(), t);
            MapMessage data = new MapMessage()
                    .with("script", actualPath.getFileName().toString())
                    .with("path", actualPath.toString());
            AuditLogger.error(LogModule.SCRIPT, LogAction.SYSTEM_ERROR, data, t);
        }
    }

    /**
     * 获取真正意义上的 GraalJS 版本号。
     * 当不是原生运行在 GraalVM 上，而是作为普通 Maven 依赖 (如 OpenJ9 平台) 引入时，
     * 直接调用 Engine.getVersion() 会触发默认的 fallback 返回 "Development Build"。
     * 因此这里通过多种方式尝试读取，优先从 JAR 包的 Manifest 中获取版本号。
     */
    private static String getGraalJSVersion() {
        try {
            // 1. 尝试通过 Package 的 MANIFEST.MF 获取 (最适合在 OpenJ9/HotSpot 下以依赖包形式引入的场景)
            Package pkg = GraalJSScriptEngine.class.getPackage();
            if (pkg != null && pkg.getImplementationVersion() != null && !pkg.getImplementationVersion().isEmpty()) {
                return pkg.getImplementationVersion();
            }

            // 2. 尝试通过 JSR-223 ScriptEngineFactory 获取
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngineFactory factory = manager.getEngineByName("graal.js").getFactory();
            if (factory != null) {
                String version = factory.getEngineVersion();
                if (version != null && !version.equals("Development Build") && !version.isEmpty()) {
                    return version;
                }
            }
        } catch (Exception e) {
            // 忽略
        }

        // 3. 最后回退到原始的 Truffle Engine Version
        return SHARED_ENGINE.getVersion();
    }

    protected AbstractScriptManager() {
        // 不再依赖 ScriptEngineManager().getEngineByName("graal.js") 每次新生成 Engine。
    }

    /**
     * 根据相对路径，解析出脚本的最终物理路径。
     * 它会优先尝试从语言特定的脚本目录（如 scripts-zh-CN）中寻找，如果找不到，再从默认的 scripts 目录中寻找。
     *
     * @param relativePath 脚本的相对路径，例如 "npc/10100.js"
     * @return 最终的 Path 对象，如果任何目录都找不到该脚本，则返回 null。
     */
    private static Path getActualScriptPath(String relativePath) {
        String scriptName = "scripts";
        ServiceProperty serviceProperty = ServerManager.getApplicationContext().getBean(ServiceProperty.class);
        String scriptLangName = scriptName + "-" + serviceProperty.getLanguage();
        Path scriptLangPath = Path.of(scriptLangName, relativePath);
        if (Files.exists(scriptLangPath)) {
            return scriptLangPath;
        }
        Path scriptPath = Path.of(scriptName, relativePath);
        if (Files.exists(scriptPath)) {
            return scriptPath;
        }
        return null;
    }

    /**
     * 获取一个可调用的脚本引擎实例。
     *
     * @param path 脚本的相对路径。
     * @return ScriptEngine 实例，如果脚本不存在或加载失败则返回 null。
     */
    public static ScriptEngine getInvocableScriptEngine(String path) {
        Path actualPath = getActualScriptPath(path);
        if (actualPath == null) {
            return null;
        }

        Context.Builder contextBuilder = Context.newBuilder("js")
                .allowExperimentalOptions(true)
                .allowHostAccess(HostAccess.ALL)
                .allowHostClassLookup(s -> true)
                .allowNativeAccess(true)
                .allowCreateThread(true)
                .allowIO(IOAccess.ALL)
                .option("js.syntax-extensions", String.valueOf(SYNTAX_EXTENSIONS_ENABLED))
                .option("js.ecmascript-version", ECMA_SCRIPT_VERSION);
        GraalJSScriptEngine graalScriptEngine = GraalJSScriptEngine.create(SHARED_ENGINE, contextBuilder);

        // 注入一个特定于此脚本实例的日志记录器
        Logger scriptLogger = LoggerFactory.getLogger("script." + path.replace("/", "."));
        graalScriptEngine.put("log", scriptLogger);

        try (BufferedReader br = Files.newBufferedReader(actualPath, StandardCharsets.UTF_8)) {
            graalScriptEngine.eval(br);
        } catch (final ScriptException | IOException t) {
            // 获取脚本文件名
            String scriptFileName = actualPath.getFileName().toString();
            // 记录更详细的错误日志
            log.error("脚本引擎加载脚本[{}]时发生错误，脚本路径：{}，错误详情：{}", scriptFileName, actualPath, t.getMessage());

            // 使用AuditLogger记录到Loki
            MapMessage data = new MapMessage()
                    .with("script", scriptFileName)
                    .with("path", actualPath.toString());
            AuditLogger.error(LogModule.SCRIPT, LogAction.SYSTEM_ERROR, data, t);
            return null;
        }
        return graalScriptEngine;
    }

    protected ScriptEngine getInvocableScriptEngine(String path, Client c) {
        ScriptEngine engine = c.getScriptEngine("scripts/" + path);
        if (engine == null) {
            engine = getInvocableScriptEngine(path);
            c.setScriptEngine(path, engine);
        }
        return engine;
    }

    protected void resetContext(String path, Client c) {
        c.removeScriptEngine("scripts/" + path);
    }
}
