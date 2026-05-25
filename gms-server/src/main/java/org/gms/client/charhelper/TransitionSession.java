package org.gms.client.charhelper;

import org.gms.client.Client;
import org.gms.net.server.coordinator.session.Hwid;

/**
 * 登录→频道过渡期间的跨连接数据对象。
 *
 * <p>玩家在登录服选角后、频道服登入前，需要将登录连接的状态
 * 传递给频道连接。此类将所有需要传递的数据集中管理，替代原来
 * 分散在 Server.transitioningChars/Macs 中的设计。</p>
 *
 * <p>原子消费：通过 {@code consume} 模式一次性取出并验证，
 * 消除原方案中 "先删除再读取" 导致的数据丢失问题。</p>
 */
public class TransitionSession {

    private final int accountId;
    private final String accountName;
    private final int charId;
    private final String macs;
    private final Hwid hwid;
    private final byte characterSlots;
    private final int language;
    private final int gmLevel;
    private final String remoteAddress;
    private final String physicalAddress;

    TransitionSession(int accountId, String accountName, int charId, String macs,
                      Hwid hwid, byte characterSlots, int language, int gmLevel,
                      String remoteAddress, String physicalAddress) {
        this.accountId = accountId;
        this.accountName = accountName;
        this.charId = charId;
        this.macs = macs;
        this.hwid = hwid;
        this.characterSlots = characterSlots;
        this.language = language;
        this.gmLevel = gmLevel;
        this.remoteAddress = remoteAddress;
        this.physicalAddress = physicalAddress;
    }

    public int getAccountId() {
        return accountId;
    }

    public String getAccountName() {
        return accountName;
    }

    public int getCharId() {
        return charId;
    }

    public String getMacs() {
        return macs;
    }

    public Hwid getHwid() {
        return hwid;
    }

    public byte getCharacterSlots() {
        return characterSlots;
    }

    public int getLanguage() {
        return language;
    }

    public int getGmLevel() {
        return gmLevel;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public String getPhysicalAddress() {
        return physicalAddress;
    }

    /**
     * 将过渡数据回填到频道连接的 Client 对象。
     */
    public void applyTo(Client c) {
        c.setAccID(accountId);
        c.setAccountName(accountName);
        c.setMacs(macs);
        c.setHwid(hwid);
        c.setCharacterSlots(characterSlots);
        c.setLanguage(language);
    }

    /* ********** Builder  ********** */

    public static Builder builder(Client client, int charId) {
        return new Builder(client, charId);
    }

    public static class Builder {
        private final Client client;
        private final int charId;
        private int gmLevel;

        Builder(Client client, int charId) {
            this.client = client;
            this.charId = charId;
        }

        public Builder gmLevel(int gmLevel) {
            this.gmLevel = gmLevel;
            return this;
        }

        public TransitionSession build() {
            return new TransitionSession(
                    client.getAccID(),
                    client.getAccountName(),
                    charId,
                    String.join(", ", client.getMacs()),
                    client.getHwid(),
                    (byte) client.getCharacterSlots(),
                    client.getLanguage(),
                    gmLevel,
                    client.getRemoteAddress(),
                    client.getEffectiveAddress()
            );
        }
    }
}
