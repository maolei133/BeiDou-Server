package org.gms.client.charhelper;

import org.gms.client.Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录→频道过渡编排器。
 *
 * <p>管理 TransitionSession 的生命周期：prepare（存储）、consume（原子消费）、
 * release（清理）。key 为 {@code remoteAddress:charId}，登录服 Client 和频道服 Client
 * 通过 Proxy Protocol 共享相同的 getRemoteAddress()（真实客户端 IP）。</p>
 *
 * <p>单例模式，替代原来散落在 Server.java 中的 transitioningChars/Macs 两 Map。</p>
 */
public final class LoginCoordinator {

    private static final Logger log = LoggerFactory.getLogger(LoginCoordinator.class);

    private static final LoginCoordinator INSTANCE = new LoginCoordinator();

    /**
     * 过渡数据缓存。key = "remoteAddress:charId"。
     */
    private final ConcurrentHashMap<String, TransitionSession> pendingTransitions = new ConcurrentHashMap<>();

    private LoginCoordinator() {}

    public static LoginCoordinator getInstance() {
        return INSTANCE;
    }

    // ============================================================
    //  Public API
    // ============================================================

    /**
     * 存储过渡数据（登录服选角后调用）。
     *
     * @param client 登录连接 Client
     * @param charId 角色 ID
     */
    public void prepare(Client client, int charId, int gmLevel) {
        TransitionSession session = TransitionSession.builder(client, charId)
                .gmLevel(gmLevel)
                .build();
        String key = makeKey(client, charId);
        pendingTransitions.put(key, session);
        log.debug("LoginCoordinator.prepare: key={} account={}", key, client.getAccountName());
    }

    /**
     * 原子消费过渡数据（频道服 PlayerLoggedinHandler 调用）。
     *
     * <p>取出 → 校验 charId → 返回；不存在或校验失败返回 null。</p>
     *
     * @param client 频道连接 Client
     * @param charId 角色 ID
     * @return 过渡数据；未找到或校验失败返回 null
     */
    public TransitionSession consume(Client client, int charId) {
        String key = makeKey(client, charId);
        TransitionSession session = pendingTransitions.remove(key);
        if (session == null) {
            log.warn("LoginCoordinator.consume: key={} 未找到", key);
            return null;
        }
        if (session.getCharId() != charId) {
            log.warn("LoginCoordinator.consume: key={} charId 不匹配 expected={} actual={}",
                    key, charId, session.getCharId());
            return null;
        }
        log.debug("LoginCoordinator.consume: key={} ok", key);
        return session;
    }

    /**
     * 释放指定账号的所有过渡数据（断连时清理）。
     *
     * @return 被释放的 charId（如果有）；-1 表示无待处理过渡数据
     */
    public int release(int accountId) {
        int[] found = {-1};
        pendingTransitions.values().removeIf(s -> {
            if (s.getAccountId() == accountId) {
                found[0] = s.getCharId();
                return true;
            }
            return false;
        });
        return found[0];
    }

    /**
     * 检查是否有待消费的过渡数据（用于 Client.disconnect 判断）。
     */
    public boolean hasPending(Client client) {
        // key 前缀匹配（IP: 开头）
        String prefix = client.getRemoteAddress() + ":";
        for (String key : pendingTransitions.keySet()) {
            if (key.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    // ============================================================
    //  Internal
    // ============================================================

    /** key = remoteAddress:charId */
    private String makeKey(Client client, int charId) {
        return client.getRemoteAddress() + ":" + charId;
    }
}
