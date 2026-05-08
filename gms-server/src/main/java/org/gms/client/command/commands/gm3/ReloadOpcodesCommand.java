package org.gms.client.command.commands.gm3;

import org.gms.client.Client;
import org.gms.client.command.Command;
import org.gms.net.OpcodeManager;

/**
 * 热重载操作码（Opcodes）的 GM 指令。
 */
public class ReloadOpcodesCommand extends Command {

    public ReloadOpcodesCommand() {
        description = "热重载在 OpcodeManager.js 中定义的所有接收和发送操作码。";
    }

    @Override
    public void execute(Client client, String[] params) {
        try {
            OpcodeManager.getInstance().reloadOpcodes();
            client.getPlayer().dropMessage(1, "操作码（Opcodes）已成功热重载。");
        } catch (Exception e) {
            client.getPlayer().dropMessage(5, "热重载操作码时发生错误，请查看服务器后台日志。");
            e.printStackTrace();
        }
    }
}
