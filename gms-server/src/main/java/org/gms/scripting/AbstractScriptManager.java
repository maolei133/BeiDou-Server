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
import org.gms.util.I18nUtil;
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

/**
 * @author Matze
 */
public abstract class AbstractScriptManager {
    private static final Logger log = LoggerFactory.getLogger(AbstractScriptManager.class);

    // 【核心优化】使用全局共享的 Engine，而不是每次调用 sef.getScriptEngine() 都创建一个新的 Engine。
    // GraalVM 每次新建 Engine 都会产生极高的内存开销 (AST抽象语法树、JIT编译环境不共享)。
    // 改为单例 Engine 后，所有 ScriptEngine(Context) 将共享同一套底层的执行与优化环境，内存占用将暴降数百MB。
    private static final Engine SHARED_ENGINE;

    // 【动态配置】将脚本引擎的配置项定义为常量，确保构建与打印信息的一致性
    private static final String ECMA_SCRIPT_VERSION = "2024";
    private static final boolean SYNTAX_EXTENSIONS_ENABLED = true;

    static {
        SHARED_ENGINE = Engine.newBuilder()
                .allowExperimentalOptions(true)
                .option("engine.WarnInterpreterOnly", "false") // 忽略解释器警告
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
            // 忽略读取异常
        }
        
        // 3. 最后回退到原始的 Truffle Engine Version
        return SHARED_ENGINE.getVersion();
    }

    protected AbstractScriptManager() {
        // 不再依赖 ScriptEngineManager().getEngineByName("graal.js") 每次新生成 Engine。
    }

    protected ScriptEngine getInvocableScriptEngine(String path) {
        // 优先取语言文件夹，没有则取scripts
        String scriptName = "scripts";
        ServiceProperty serviceProperty = ServerManager.getApplicationContext().getBean(ServiceProperty.class);
        String scriptLangName = scriptName + "-" + serviceProperty.getLanguage();

        Path scriptPath = Path.of(scriptName, path);
        Path scriptLangPath = Path.of(scriptLangName, path);

        Path actualPath;
        if (Files.exists(scriptLangPath)) {
            actualPath = scriptLangPath;
        } else if (Files.exists(scriptPath)){
            actualPath = scriptPath;
        } else {
            return null;
        }

        // 使用共享的 Engine 构建独立的 Context (每个脚本仍有独立的变量作用域，但底层编译环境是共享的)
        Context.Builder contextBuilder = Context.newBuilder("js")
                .allowExperimentalOptions(true)
                .allowHostAccess(HostAccess.ALL)          // 允许脚本访问 Java 主机环境
                .allowHostClassLookup(s -> true)          // 允许脚本通过 Java.type() 查找类
                .allowNativeAccess(true)                  // 允许原生方法访问
                .allowCreateThread(true)                  // 允许创建线程
                .allowIO(IOAccess.ALL)                    // 允许 IO
                .option("js.syntax-extensions", String.valueOf(SYNTAX_EXTENSIONS_ENABLED)) // 启用 JS 语法扩展
                .option("js.ecmascript-version", ECMA_SCRIPT_VERSION); // 设置 ECMAScript 标准

        GraalJSScriptEngine graalScriptEngine = GraalJSScriptEngine.create(SHARED_ENGINE, contextBuilder);
        ScriptEngine engine = graalScriptEngine;

        // 已经通过 contextBuilder 全局授权了，下面的 enableScriptHostAccess 是兼容代码保留
        enableScriptHostAccess(graalScriptEngine);

        try (BufferedReader br = Files.newBufferedReader(actualPath, StandardCharsets.UTF_8)) {
            engine.eval(br);
        } catch (final ScriptException | IOException t) {
            // 获取脚本管理器类型
            String managerType = this.getClass().getSimpleName().replace("ScriptManager", "").toLowerCase();
            // 获取脚本文件名
            String scriptFileName = actualPath.getFileName().toString();
            // 记录更详细的错误日志
            log.error("脚本引擎[{}]加载脚本[{}]时发生错误，脚本路径：{}，错误详情：{}", managerType, scriptFileName, actualPath, t.getMessage());

            // 使用AuditLogger记录到Loki
            MapMessage data = new MapMessage()
                    .with("engine", managerType)
                    .with("script", scriptFileName)
                    .with("path", actualPath.toString());
            AuditLogger.error(LogModule.SCRIPT, LogAction.ERROR, data, t);
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

    /**
     * Allow usage of "Java.type()" in script to look up host class
     */
    private void enableScriptHostAccess(GraalJSScriptEngine engine) {
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        bindings.put("polyglot.js.allowHostAccess", true);
        bindings.put("polyglot.js.allowHostClassLookup", true);
    }

    protected void resetContext(String path, Client c) {
        c.removeScriptEngine("scripts/" + path);
    }
}
