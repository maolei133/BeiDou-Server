package org.gms.log;

import org.gms.constants.net.ServerConstants;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 增强型日志条目类
 * 包含更详细的日志信息，如IP、MAC、HWID、账号、角色等
 */
public class EnhancedLogEntry {
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private String version = ServerConstants.BEI_DOU_VERSION;  // 版本号
    private String timestamp;  // 时间戳
    private String majorCategory;  // 日志大类
    private String minorCategory;  // 日志小类
    private String message;  // 日志消息
    private String ip;  // IP地址
    private String mac;  // MAC地址
    private String hwid;  // 硬件ID
    private String account;  // 账号
    private Long accountId;  // 账号ID
    private String character;  // 角色名
    private Long characterId;  // 角色ID
    private Integer level;  // 等级

    public EnhancedLogEntry() {
        this.timestamp = DATE_FORMAT.format(new Date());
    }

    // 构建日志格式字符串
    public String toLogString() {
        StringBuilder sb = new StringBuilder();
        sb.append(timestamp);
        sb.append(" [").append(version).append("]");
        
        if (ip != null) {
            sb.append(" [IP:").append(ip).append("]");
        }
        
        if (mac != null) {
            sb.append(" [MAC:").append(mac).append("]");
        }
        
        if (hwid != null) {
            sb.append(" [HWID:").append(hwid).append("]");
        }
        
        if (account != null) {
            sb.append(" [Account:").append(account).append("]");
        }
        
        if (accountId != null) {
            sb.append(" [AccountId:").append(accountId).append("]");
        }
        
        if (character != null) {
            sb.append(" [Character:").append(character).append("]");
        }
        
        if (characterId != null) {
            sb.append(" [CharacterId:").append(characterId).append("]");
        }
        
        if (level != null) {
            sb.append(" [Level:").append(level).append("]");
        }
        
        sb.append(" ").append(message);
        return sb.toString();
    }

    // Getters and Setters
    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getMajorCategory() {
        return majorCategory;
    }

    public void setMajorCategory(String majorCategory) {
        this.majorCategory = majorCategory;
    }

    public String getMinorCategory() {
        return minorCategory;
    }

    public void setMinorCategory(String minorCategory) {
        this.minorCategory = minorCategory;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getHwid() {
        return hwid;
    }

    public void setHwid(String hwid) {
        this.hwid = hwid;
    }

    public String getAccount() {
        return account;
    }

    public void setAccount(String account) {
        this.account = account;
    }

    public Long getAccountId() {
        return accountId;
    }

    public void setAccountId(Long accountId) {
        this.accountId = accountId;
    }

    public String getCharacter() {
        return character;
    }

    public void setCharacter(String character) {
        this.character = character;
    }

    public Long getCharacterId() {
        return characterId;
    }

    public void setCharacterId(Long characterId) {
        this.characterId = characterId;
    }

    public Integer getLevel() {
        return level;
    }

    public void setLevel(Integer level) {
        this.level = level;
    }
}