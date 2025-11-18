package org.gms.log;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.gms.constants.net.ServerConstants;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 基础日志条目类
 * 包含客户端和角色的基本信息
 * 
 * 日志结构优化：
 * 1. 字段缩写以减少日志文件大小
 * 2. 按重要性排序字段（时间、版本在前，模块信息在后）
 */
@JsonPropertyOrder({"t", "v", "ip", "mac", "hwid", "acc", "accId", "chr", "chrId", "map","mId", "mod", "cf"})
public class BaseLogEntry {
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String USERDATA_FILE = "logs/userdata.json";
    
    // 用户数据缓存，用于前端筛选
    private static final Map<String, Set<String>> userDataCache = new ConcurrentHashMap<>();
    // 标记用户数据是否已更改，需要写入文件
    private static volatile boolean userDataChanged = false;
    // 用户数据写入线程
    private static final Thread userDataWriterThread;
    
    static {
        // 初始化缓存
        userDataCache.put("ips", ConcurrentHashMap.newKeySet());
        userDataCache.put("macs", ConcurrentHashMap.newKeySet());
        userDataCache.put("hwids", ConcurrentHashMap.newKeySet());
        userDataCache.put("accounts", ConcurrentHashMap.newKeySet());
        userDataCache.put("accountIds", ConcurrentHashMap.newKeySet());
        userDataCache.put("characters", ConcurrentHashMap.newKeySet());
        userDataCache.put("characterIds", ConcurrentHashMap.newKeySet());
        
        // 启动用户数据写入线程
        userDataWriterThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    if (userDataChanged) {
                        writeUserDataToFile();
                        userDataChanged = false;
                    }
                    Thread.sleep(5000); // 每5秒检查一次
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    // 忽略写入错误
                }
            }
        });
        userDataWriterThread.setDaemon(true);
        userDataWriterThread.start();
        
        // 加载现有的用户数据
        loadUserDataFromFile();
    }
    
    // 缩写字段以减少日志大小
    protected String v = String.valueOf(ServerConstants.BEI_DOU_VERSION);  // 版本号
    protected String t;  // 时间戳
    protected String ip;  // IP地址
    protected List<String> mac;  // MAC地址列表
    protected String hwid;  // 硬件ID
    protected String acc;  // 账号
    protected Long accId;  // 账号ID
    protected String chr;  // 角色名
    protected Long chrId;  // 角色ID
    protected String map;       // 地图名称
    protected Long mId;  // 地图ID
    protected String mod; // 模块名
    protected Map<String, Object> customFields = new HashMap<>(); // 自定义字段 (缩写为 cf)

    public BaseLogEntry() {
        this.t = DATE_FORMAT.format(new Date());
        this.mac = new ArrayList<>();
    }

    /**
     * 更新用户数据缓存
     */
    protected void updateUserDataCache() {
        boolean changed = false;
        if (ip != null && !ip.isEmpty()) {
            changed |= userDataCache.get("ips").add(ip);
        }
        if (mac != null && !mac.isEmpty()) {
            for (String macAddr : mac) {
                if (macAddr != null && !macAddr.isEmpty()) {
                    changed |= userDataCache.get("macs").add(macAddr);
                }
            }
        }
        if (hwid != null && !hwid.isEmpty()) {
            changed |= userDataCache.get("hwids").add(hwid);
        }
        if (acc != null && !acc.isEmpty()) {
            changed |= userDataCache.get("accounts").add(acc);
        }
        if (accId != null) {
            changed |= userDataCache.get("accountIds").add(String.valueOf(accId));
        }
        if (chr != null && !chr.isEmpty()) {
            changed |= userDataCache.get("characters").add(chr);
        }
        if (chrId != null) {
            changed |= userDataCache.get("characterIds").add(String.valueOf(chrId));
        }
        
        if (changed) {
            userDataChanged = true;
        }
    }
    
    /**
     * 从文件加载用户数据
     */
    private static void loadUserDataFromFile() {
        try {
            File file = new File(USERDATA_FILE);
            if (file.exists()) {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode rootNode = mapper.readTree(file);
                
                // 读取IP数据
                JsonNode ipsNode = rootNode.get("ips");
                if (ipsNode != null && ipsNode.isArray()) {
                    for (JsonNode ipNode : ipsNode) {
                        userDataCache.get("ips").add(ipNode.asText());
                    }
                }
                
                // 读取MAC数据
                JsonNode macsNode = rootNode.get("macs");
                if (macsNode != null && macsNode.isArray()) {
                    for (JsonNode macNode : macsNode) {
                        userDataCache.get("macs").add(macNode.asText());
                    }
                }
                
                // 读取HWID数据
                JsonNode hwidsNode = rootNode.get("hwids");
                if (hwidsNode != null && hwidsNode.isArray()) {
                    for (JsonNode hwidNode : hwidsNode) {
                        userDataCache.get("hwids").add(hwidNode.asText());
                    }
                }
                
                // 读取账号数据
                JsonNode accountsNode = rootNode.get("accounts");
                if (accountsNode != null && accountsNode.isArray()) {
                    for (JsonNode accountNode : accountsNode) {
                        userDataCache.get("accounts").add(accountNode.asText());
                    }
                }
                
                // 读取角色数据
                JsonNode charactersNode = rootNode.get("characters");
                if (charactersNode != null && charactersNode.isArray()) {
                    for (JsonNode characterNode : charactersNode) {
                        userDataCache.get("characters").add(characterNode.asText());
                    }
                }
            }
        } catch (Exception e) {
            // 忽略加载错误
            e.printStackTrace();
        }
    }
    
    /**
     * 将用户数据写入文件
     */
    private static synchronized void writeUserDataToFile() {
        try {
            // 确保目录存在
            File dir = new File("logs");
            if (!dir.exists()) {
                dir.mkdirs();
            }
            
            ObjectNode rootNode = objectMapper.createObjectNode();
            
            for (Map.Entry<String, Set<String>> entry : userDataCache.entrySet()) {
                ArrayNode arrayNode = objectMapper.createArrayNode();
                for (String value : entry.getValue()) {
                    arrayNode.add(value);
                }
                rootNode.set(entry.getKey(), arrayNode);
            }
            
            // 写入文件
            try (FileOutputStream fos = new FileOutputStream(USERDATA_FILE);
                 OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
                objectMapper.writeValue(osw, rootNode);
            }
        } catch (Exception e) {
            // 忽略写入错误
        }
    }

    /**
     * 获取用户数据缓存
     * 
     * @return 用户数据缓存
     */
    @JsonIgnore
    public static Map<String, Set<String>> getUserDataCache() {
        return userDataCache;
    }

    /**
     * 获取用户数据的JSON表示
     * 
     * @return JSON字符串
     */
    public static String getUserDataJson() {
        try {
            ObjectNode rootNode = objectMapper.createObjectNode();
            
            for (Map.Entry<String, Set<String>> entry : userDataCache.entrySet()) {
                ArrayNode arrayNode = objectMapper.createArrayNode();
                for (String value : entry.getValue()) {
                    arrayNode.add(value);
                }
                rootNode.set(entry.getKey(), arrayNode);
            }
            
            return objectMapper.writeValueAsString(rootNode);
        } catch (Exception e) {
            return "{}";
        }
    }

    // Getters and Setters (使用缩写字段名)
    public String getV() {
        return v;
    }

    public void setV(String v) {
        this.v = v;
    }

    public String getT() {
        return t;
    }

    public void setT(String t) {
        this.t = t;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public List<String> getMac() {
        return mac;
    }

    public void setMac(List<String> mac) {
        this.mac = mac;
    }

    public String getHwid() {
        return hwid;
    }

    public void setHwid(String hwid) {
        this.hwid = hwid;
    }

    public String getAcc() {
        return acc;
    }

    public void setAcc(String acc) {
        this.acc = acc;
    }

    public Long getAccId() {
        return accId;
    }

    public void setAccId(Long accId) {
        this.accId = accId;
    }

    public String getChr() {
        return chr;
    }

    public void setChr(String chr) {
        this.chr = chr;
    }

    public Long getChrId() {
        return chrId;
    }

    public void setChrId(Long chrId) {
        this.chrId = chrId;
    }

    public String getMap() {
        return map;
    }

    public void setMap(String map) {
        this.map = map;
    }

    @JsonProperty("mId")
    public Long getMId() {
        return mId;
    }

    public void setMid(Long mId) {
        this.mId = mId;
    }

    public String getMod() {
        return mod;
    }

    public void setMod(String mod) {
        this.mod = mod;
    }
    
    @JsonProperty("cf")
    public Map<String, Object> getCustomFields() {
        return customFields;
    }
    
    public void setCustomFields(Map<String, Object> customFields) {
        this.customFields = customFields;
    }
    
    public void addCustomField(String key, Object value) {
        this.customFields.put(key, value);
    }
}