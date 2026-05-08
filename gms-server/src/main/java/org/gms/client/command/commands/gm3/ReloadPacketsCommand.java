package org.gms.client.command.commands.gm3;

import org.gms.client.Client;
import org.gms.client.command.Command;
import org.gms.net.PacketProcessor;

/**
 * 热重载数据包处理器（Packet Handlers）的 GM 指令。
 */
public class ReloadPacketsCommand extends Command {

    public ReloadPacketsCommand() {
        description = "热重载所有Java和脚本中定义的数据包处理器。";
    }

    @Override
    public void execute(Client client, String[] params) {
        try {
            PacketProcessor.reloadScripts();
            client.getPlayer().dropMessage(1, "所有数据包处理器已成功热重载。");
        } catch (Exception e) {
            client.getPlayer().dropMessage(5, "热重载数据包处理器时发生错误，请查看服务器后台日志。");
            e.printStackTrace();
        }
    }
}
