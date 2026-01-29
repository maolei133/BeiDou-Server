package org.gms.client.command.commands.gm6;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.gms.client.Client;
import org.gms.client.command.Command;
import org.gms.server.logging.AuditLogger;

import java.util.Arrays;
import java.util.Map;

public class LogCommand extends Command {
    {
        setDescription("管理日志系统配置。用法: !log <module/level/status> [args...]");
    }

    @Override
    public void execute(Client client, String[] params) {
        if (params.length < 1) {
            client.getPlayer().dropMessage(6, "用法: !log <module/level/status> [args...]");
            return;
        }

        String subCommand = params[0].toLowerCase();

        switch (subCommand) {
            case "module":
                handleModuleCommand(client, params);
                break;
            case "level":
                handleLevelCommand(client, params);
                break;
            case "status":
                handleStatusCommand(client);
                break;
            default:
                client.getPlayer().dropMessage(6, "未知子命令: " + subCommand);
        }
    }

    private void handleModuleCommand(Client client, String[] params) {
        if (params.length < 3) {
            client.getPlayer().dropMessage(6, "用法: !log module <moduleName> <true/false>");
            return;
        }
        String module = params[1];
        boolean enabled = Boolean.parseBoolean(params[2]);
        AuditLogger.setModuleEnabled(module, enabled);
        client.getPlayer().dropMessage(6, "日志模块 [" + module + "] 已设置为: " + (enabled ? "开启" : "关闭"));
    }

    private void handleLevelCommand(Client client, String[] params) {
        if (params.length < 3) {
            client.getPlayer().dropMessage(6, "用法: !log level <loggerName> <level>");
            client.getPlayer().dropMessage(6, "示例: !log level audit DEBUG");
            client.getPlayer().dropMessage(6, "示例: !log level root INFO");
            return;
        }
        String loggerName = params[1];
        String levelStr = params[2].toUpperCase();
        
        try {
            Level level = Level.valueOf(levelStr);
            if (loggerName.equalsIgnoreCase("root")) {
                Configurator.setRootLevel(level);
            } else {
                Configurator.setLevel(loggerName, level);
            }
            client.getPlayer().dropMessage(6, "Logger [" + loggerName + "] 级别已设置为: " + level);
        } catch (IllegalArgumentException e) {
            client.getPlayer().dropMessage(6, "无效的日志级别: " + levelStr + ". 可选值: " + Arrays.toString(Level.values()));
        }
    }

    private void handleStatusCommand(Client client) {
        client.getPlayer().dropMessage(6, "=== 日志系统状态 ===");
        Map<String, Boolean> config = AuditLogger.getModuleConfig();
        if (config.isEmpty()) {
            client.getPlayer().dropMessage(6, "当前没有配置任何模块开关 (默认全部开启)。");
        } else {
            for (Map.Entry<String, Boolean> entry : config.entrySet()) {
                client.getPlayer().dropMessage(6, "模块 [" + entry.getKey() + "]: " + (entry.getValue() ? "开启" : "关闭"));
            }
        }
    }
}
