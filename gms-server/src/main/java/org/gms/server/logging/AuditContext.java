package org.gms.server.logging;

import org.gms.client.Character;
import org.gms.client.Client;

import java.util.HashMap;
import java.util.Map;

/**
 * 审计日志上下文
 * 用于在当前线程中存储玩家上下文信息，防止对象下线后的空指针问题。
 */
public class AuditContext {
    private static final ThreadLocal<Map<String, String>> context = ThreadLocal.withInitial(HashMap::new);

    /**
     * 设置当前线程的上下文信息
     * @param client 客户端对象
     */
    public static void set(Client client) {
        if (client == null) {
            return;
        }
        Map<String, String> data = context.get();
        data.clear();

        // 基础账号信息
        data.put("accId", String.valueOf(client.getAccID()));
        
        // 角色信息 (如果已登录)
        Character chr = client.getPlayer();
        if (chr != null) {
            data.put("chrId", String.valueOf(chr.getId()));
            data.put("chr", chr.getName());
            data.put("map", String.valueOf(chr.getMapId()));
        }
    }

    /**
     * 获取当前上下文数据
     * @return 上下文数据副本
     */
    public static Map<String, String> get() {
        return new HashMap<>(context.get());
    }

    /**
     * 清理当前线程的上下文
     */
    public static void clear() {
        context.remove();
    }
}
