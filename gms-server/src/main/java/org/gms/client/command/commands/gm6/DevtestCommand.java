package org.gms.client.command.commands.gm6;

import org.gms.client.Client;
import org.gms.client.command.Command;
import org.gms.scripting.AbstractScriptManager;
import org.gms.util.I18nUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

public class DevtestCommand extends Command {
    {
        setDescription(I18nUtil.getMessage("DevtestCommand.message1"));
    }

    private static final Logger log = LoggerFactory.getLogger(DevtestCommand.class);

    @Override
    public void execute(Client client, String[] params) {
        // 由于 getInvocableScriptEngine 已经是静态方法，我们可以直接调用
        ScriptEngine scriptEngine = AbstractScriptManager.getInvocableScriptEngine("devtest.js");
        if (scriptEngine == null) {
            log.warn("无法加载 devtest.js 脚本，请检查脚本是否存在。");
            return;
        }
        try {
            Invocable invocable = (Invocable) scriptEngine;
            invocable.invokeFunction("run", client.getPlayer());
        } catch (ScriptException | NoSuchMethodException e) {
            log.info(I18nUtil.getMessage("DevtestCommand.message2"), e);
        }
    }
}
