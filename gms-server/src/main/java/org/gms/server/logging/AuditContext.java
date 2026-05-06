/**
 * 审计日志上下文
 * 用于在当前线程中存储玩家上下文信息，防止对象下线后的空指针问题。
 */
package org.gms.server.logging;

import com.alibaba.fastjson2.JSON;
import org.gms.client.Client;
import org.gms.client.Character;
import org.gms.dao.entity.CharactersDO;
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
     * 移除当前线程中的单个上下文字段。
     */
    public static void remove(String key) {
        if (key != null) {
            context.get().remove(key);
        }
    }

    /**
     * 用快照替换当前线程中的审计上下文。
     */
    public static void replace(Map<String, String> snapshot) {
        Map<String, String> data = context.get();
        data.clear();
        if (snapshot != null && !snapshot.isEmpty()) {
            data.putAll(snapshot);
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

    /**
     * 根据详细参数构建审计日志数据。
     * 此方法允许调用者传入独立的审计字段值，并将它们打包成一个 Map 返回。
     * 对于任何为 null 的参数，该字段将不会被添加到返回的 Map 中。
     *
     * @param aid 账号ID
     * @param acc 账号名称
     * @param ip IP地址
     * @param macs MAC地址列表 (JSON格式)
     * @param hwid 硬件ID
     * @param cid 角色ID
     * @param chr 角色名称
     * @param map 地图ID
     * @param mapName 地图名称
     * @param lvl 角色等级
     * @param job 职业ID
     * @param jobName 职业名称
     * @return 包含所提供审计数据的 Map
     */
    public static Map<String, String> buildAuditData(String aid, String acc, String ip, String macs, String hwid, String cid, String chr, String map, String mapName, String lvl, String job, String jobName) {
        Map<String, String> data = context.get();
        data.clear();
        if (aid != null) data.put("aid", aid);
        if (acc != null) data.put("acc", acc);
        if (ip != null) data.put("ip", ip);
        if (macs != null) data.put("macs", macs);
        if (hwid != null) data.put("hwid", hwid);
        if (cid != null) data.put("cid", cid);
        if (chr != null) data.put("chr", chr);
        if (map != null) data.put("map", map);
        if (mapName != null) data.put("mapName", mapName);
        if (lvl != null) data.put("lvl", lvl);
        if (job != null) data.put("job", job);
        if (jobName != null) data.put("jobName", jobName);
        return data;
    }
}
