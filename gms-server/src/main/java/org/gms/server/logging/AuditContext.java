/**
 * 审计日志上下文
 * 用于在当前线程中存储玩家上下文信息，防止对象下线后的空指针问题。
 */
package org.gms.server.logging;

import com.alibaba.fastjson2.JSON;
import org.gms.client.Client;
import org.gms.client.Character;
import org.gms.server.maps.MapleMap;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

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
        data.put("aid", String.valueOf(client.getAccID()));
        if (client.getAccountName() != null) {
            data.put("acc", client.getAccountName());
        }
        
        // 客户端网络信息
        String ip = client.getRemoteAddress();
        if (ip != null) {
            data.put("ip", ip);
        }
        
        Set<String> macs = client.getMacs();
        if (macs != null && !macs.isEmpty()) {
            // 直接使用 FastJson2 序列化为 JSON 数组字符串
            data.put("macs", JSON.toJSONString(macs));
        }
        
        if (client.getHwid() != null) {
            data.put("hwid", client.getHwid().hwid());
        }
        
        // 角色信息 (如果已登录)
        Character chr = client.getPlayer();
        if (chr != null) {
            data.put("cid", String.valueOf(chr.getId()));
            data.put("chr", chr.getName());
            
            MapleMap map = chr.getMap();
            if (map != null) {
                data.put("map", String.valueOf(map.getId()));
                // 尝试获取地图名称，如果为空则不记录或记录默认值
                String mapName = map.getMapName();
                if (mapName != null && !mapName.isEmpty()) {
                    data.put("mapName", mapName);
                }
            }
            
            data.put("lvl", String.valueOf(chr.getLevel())); // 角色等级
            
            if (chr.getJob() != null) {
                data.put("job", String.valueOf(chr.getJob().getId()));
                data.put("jobName", chr.getJob().getName());
            }
        }
    }

    /**
     * 手动添加上下文信息
     * @param key 键
     * @param value 值
     */
    public static void put(String key, String value) {
        if (key != null && value != null) {
            context.get().put(key, value);
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
