package org.gms.log;

import com.alibaba.fastjson2.JSON;
import org.gms.client.Character;
import org.gms.client.Client;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * 基础日志记录器，提供通用的日志记录功能
 */
public class BaseLogger {
    private static final String LOG_DIRECTORY = "logs";
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter FILE_DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final ZoneId ZONE_ID = ZoneId.systemDefault();
    private static final int LOG_RETENTION_DAYS = 10; // 日志保留天数
    
    private final String moduleName;
    private final ConcurrentLinkedQueue<BaseLogEntry> logQueue = new ConcurrentLinkedQueue<>();
    private final Lock fileLock = new ReentrantLock();
    private final PrintWriter logWriter;
    
    private volatile boolean running = true;
    private final Thread logWriterThread;
    
    public BaseLogger(String majorCategory, String minorCategory) throws IOException {
        this.moduleName = majorCategory + File.separator + minorCategory;
        
        // 创建日志目录
        Path logDir = Paths.get(LOG_DIRECTORY);
        if (!Files.exists(logDir)) {
            Files.createDirectories(logDir);
        }
        
        // 创建模块目录
        Path moduleDir = Paths.get(LOG_DIRECTORY, "custom", majorCategory, minorCategory);
        if (!Files.exists(moduleDir)) {
            Files.createDirectories(moduleDir);
        }
        
        // 清理过期日志文件
        cleanupOldLogFiles(moduleDir);
        
        // 创建基于日期的日志文件
        String currentDate = LocalDate.now().format(FILE_DATE_FORMAT);
        String logFileName = LOG_DIRECTORY + File.separator + "custom" + File.separator + majorCategory + File.separator + minorCategory + File.separator + currentDate + ".log";
        FileOutputStream fos = new FileOutputStream(logFileName, true);
        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
        this.logWriter = new PrintWriter(osw, true);
        
        // 启动日志写入线程
        this.logWriterThread = new Thread(this::writeLogs, "BaseLogger-" + majorCategory + "-" + minorCategory);
        this.logWriterThread.setDaemon(true);
        this.logWriterThread.start();
    }
    
    // 为了向后兼容，保留旧的构造函数
    public BaseLogger(String moduleName) throws IOException {
        // 解析moduleName，如果包含分隔符则拆分
        if (moduleName.contains(File.separator)) {
            String[] parts = moduleName.split(File.separator);
            if (parts.length >= 2) {
                // 如果moduleName已经是"大类/小类"格式，则使用新的构造函数
                this.moduleName = moduleName;
                
                // 创建日志目录
                Path logDir = Paths.get(LOG_DIRECTORY);
                if (!Files.exists(logDir)) {
                    Files.createDirectories(logDir);
                }
                
                // 创建模块目录
                Path moduleDir = Paths.get(LOG_DIRECTORY, "custom", parts[0], parts[1]);
                if (!Files.exists(moduleDir)) {
                    Files.createDirectories(moduleDir);
                }
                
                // 清理过期日志文件
                cleanupOldLogFiles(moduleDir);
                
                // 创建基于日期的日志文件
                String currentDate = LocalDate.now().format(FILE_DATE_FORMAT);
                String logFileName = LOG_DIRECTORY + File.separator + "custom" + File.separator + parts[0] + File.separator + parts[1] + File.separator + currentDate + ".log";
                FileOutputStream fos = new FileOutputStream(logFileName, true);
                OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
                this.logWriter = new PrintWriter(osw, true);
                
                // 启动日志写入线程
                this.logWriterThread = new Thread(this::writeLogs, "BaseLogger-" + parts[0] + "-" + parts[1]);
                this.logWriterThread.setDaemon(true);
                this.logWriterThread.start();
                return;
            }
        }
        
        // 如果moduleName不包含分隔符，则使用旧的逻辑
        this.moduleName = moduleName;
        
        // 创建日志目录
        Path logDir = Paths.get(LOG_DIRECTORY);
        if (!Files.exists(logDir)) {
            Files.createDirectories(logDir);
        }
        
        // 创建模块目录
        Path moduleDir = Paths.get(LOG_DIRECTORY, "custom", moduleName);
        if (!Files.exists(moduleDir)) {
            Files.createDirectories(moduleDir);
        }
        
        // 清理过期日志文件
        cleanupOldLogFiles(moduleDir);
        
        // 创建基于日期的日志文件
        String currentDate = LocalDate.now().format(FILE_DATE_FORMAT);
        String logFileName = LOG_DIRECTORY + File.separator + "custom" + File.separator + moduleName + File.separator + currentDate + ".log";
        FileOutputStream fos = new FileOutputStream(logFileName, true);
        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
        this.logWriter = new PrintWriter(osw, true);
        
        // 启动日志写入线程
        this.logWriterThread = new Thread(this::writeLogs, "BaseLogger-" + moduleName);
        this.logWriterThread.setDaemon(true);
        this.logWriterThread.start();
    }
    
    /**
     * 清理过期日志文件
     * 
     * @param moduleDir 模块目录
     */
    private void cleanupOldLogFiles(Path moduleDir) {
        try {
            Files.list(moduleDir)
                .filter(Files::isRegularFile)
                .filter(path -> path.toString().endsWith(".log"))
                .forEach(path -> {
                    try {
                        String fileName = path.getFileName().toString();
                        String datePart = fileName.substring(0, fileName.length() - 4); // 移除 .log 后缀
                        LocalDate fileDate = LocalDate.parse(datePart, FILE_DATE_FORMAT);
                        LocalDate cutoffDate = LocalDate.now().minusDays(LOG_RETENTION_DAYS);
                        
                        if (fileDate.isBefore(cutoffDate)) {
                            Files.delete(path);
                        }
                    } catch (Exception e) {
                        // 忽略单个文件删除失败
                    }
                });
        } catch (Exception e) {
            // 忽略清理错误
        }
    }
    
    /**
     * 记录日志条目
     * 
     * @param entry 日志条目
     */
    public void log(BaseLogEntry entry) {
        // 更新用户数据缓存
        entry.updateUserDataCache();
        logQueue.offer(entry);
    }
    
    /**
     * 从客户端和角色对象填充日志条目基本信息
     * 
     * @param entry 日志条目
     * @param client 客户端对象
     * @param player 角色对象
     */
    public void populateBaseInfo(BaseLogEntry entry, Client client, Character player) {
        entry.setT(Instant.now().atZone(ZONE_ID).format(DATE_FORMAT));
        entry.setMod(moduleName);
        
        if (client != null) {
            entry.setIp(client.getRemoteAddress());
            
            // 设置MAC地址列表
            entry.setMac(new ArrayList<>(client.getMacs()));
            
            entry.setHwid(client.getHwid() != null ? client.getHwid().hwid() : "");
            entry.setAcc(client.getAccountName());
            entry.setAccId((long) client.getAccID());
        }
        
        if (player != null) {
            entry.setChr(player.getName());
            entry.setChrId((long) player.getId());
            entry.setMap(player.getMap().getMapName());
            entry.setMid((long) player.getMapId());
        } else if (client != null && client.getPlayer() != null) {
            Character chr = client.getPlayer();
            entry.setChr(chr.getName());
            entry.setChrId((long) chr.getId());
            entry.setMap(chr.getMap().getMapName());
            entry.setMid((long) chr.getMapId());
        }
        
        // 尝试获取当前线程关联的客户端
        /*if (entry.getAccId() == null) {
            Client currentClient = Server.getInstance().getCurrentClient();
            if (currentClient != null) {
                entry.setAcc(currentClient.getAccountName());
                entry.setAccId((long) currentClient.getAccID());
                
                if (currentClient.getPlayer() != null) {
                    Character chr = currentClient.getPlayer();
                    entry.setChr(chr.getName());
                    entry.setChrId((long) chr.getId());
                    entry.setWId((long) chr.getWorld());
                    entry.setMId((long) chr.getMapId());
                }
            }
        }*/
    }
    
    /**
     * 写入日志到文件
     */
    private void writeLogs() {
        while (running) {
            try {
                BaseLogEntry entry = logQueue.poll();
                if (entry != null) {
                    fileLock.lock();
                    try {
                        logWriter.println(JSON.toJSONString(entry));
                        logWriter.flush();
                    } finally {
                        fileLock.unlock();
                    }
                } else {
                    // 如果队列为空，等待一段时间
                    SECONDS.sleep(1);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // 使用统一的日志系统记录错误信息，而不是printStackTrace
                System.err.println("写入日志时出错: " + e.getMessage());
            }
        }
    }
    
    /**
     * 关闭日志记录器
     */
    public void shutdown() {
        running = false;
        if (logWriterThread != null) {
            try {
                logWriterThread.join(5000); // 等待最多5秒
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        if (logWriter != null) {
            logWriter.close();
        }
    }
    
    /**
     * 创建基础日志条目
     * 
     * @param client 客户端对象
     * @param chr 角色对象
     * @return 基础日志条目
     */
    public static BaseLogEntry createBaseLogEntry(Client client, Character chr) {
        BaseLogEntry entry = new BaseLogEntry();
        // 这里应该使用具体的BaseLogger实例来填充信息
        return entry;
    }
    
    /**
     * 异步记录日志
     * 
     * @param majorCategory 主分类
     * @param minorCategory 次分类
     * @param baseEntry 基础日志条目
     * @param moduleData 模块特定数据
     */
    public static void logAsync(String majorCategory, String minorCategory, BaseLogEntry baseEntry, Map<String, Object> moduleData) {
        // 实现异步日志记录逻辑
    }
    
    /**
     * 获取用户数据缓存
     * 
     * @return 用户数据缓存
     */
    public static Map<String, java.util.Set<String>> getUserDataCache() {
        return BaseLogEntry.getUserDataCache();
    }
}