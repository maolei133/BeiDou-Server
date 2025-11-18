package org.gms.log;

import org.gms.client.Client;
import org.gms.client.Character;
import org.gms.net.server.coordinator.session.Hwid;

import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 日志系统性能测试类
 * 用于测试日志系统在高并发场景下的性能表现
 */
public class LogPerformanceTest {
    
    private static final String[] IPS = {
        "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103", "192.168.1.104"
    };
    
    private static final String[] MACS = {
        "00:11:22:33:44:55", "00:11:22:33:44:56", "00:11:22:33:44:57", "00:11:22:33:44:58", "00:11:22:33:44:59"
    };
    
    private static final String[] HWIDS = {
        "ABC123DEF456", "ABC123DEF457", "ABC123DEF458", "ABC123DEF459", "ABC123DEF460"
    };
    
    private static final String[] ACCOUNTS = {
        "testuser001", "testuser002", "testuser003", "testuser004", "testuser005"
    };
    
    private static final String[] CHARACTERS = {
        "TestCharacter001", "TestCharacter002", "TestCharacter003", "TestCharacter004", "TestCharacter005"
    };
    
    private static final Random RANDOM = new Random();
    
    /**
     * 执行性能测试
     * 
     * @param threadCount 线程数
     * @param logCount 每个线程记录的日志数量
     */
    public static void runPerformanceTest(int threadCount, int logCount) {
        System.out.println("开始性能测试...");
        System.out.println("线程数: " + threadCount + ", 每线程日志数: " + logCount);
        
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        
        long startTime = System.currentTimeMillis();
        
        // 启动多个线程并发记录日志
        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < logCount; j++) {
                        // 模拟客户端和角色对象
                        Client client = createMockClient(threadId, j);
                        Character character = createMockCharacter(threadId, j);
                        
                        // 随机记录不同类型的日志
                        int logType = RANDOM.nextInt(6);
                        switch (logType) {
                            case 0:
                                ModuleLogger.logPlayerLogin(client, character);
                                break;
                            case 1:
                                ModuleLogger.logPlayerLogout(client, character);
                                break;
                            case 2:
                                ModuleLogger.logItemObtain(client, character, "测试物品", RANDOM.nextInt(100), "测试来源");
                                break;
                            case 3:
                                ModuleLogger.logTrade(client, character, "测试玩家", "测试物品", RANDOM.nextInt(100), RANDOM.nextInt(1000000));
                                break;
                            case 4:
                                ModuleLogger.logSkillUse(client, character, "测试技能", RANDOM.nextInt(1000000), RANDOM.nextInt(20));
                                break;
                            case 5:
                                ModuleLogger.logMonsterKill(client, character, "测试怪物", RANDOM.nextInt(1000000), RANDOM.nextInt(1000000000));
                                break;
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    latch.countDown();
                }
            });
        }
        
        try {
            // 等待所有线程完成
            latch.await();
            
            long endTime = System.currentTimeMillis();
            long totalTime = endTime - startTime;
            
            System.out.println("性能测试完成!");
            System.out.println("总耗时: " + totalTime + " ms");
            System.out.println("总日志数: " + (threadCount * logCount));
            System.out.println("平均响应时间: " + (totalTime / (double) (threadCount * logCount)) + " ms");
            System.out.println("TPS: " + (threadCount * logCount) / (totalTime / 1000.0));
            
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }
    
    /**
     * 创建模拟的客户端对象
     */
    private static Client createMockClient(int threadId, int logIndex) {
        // 创建一个模拟的客户端对象
        Client client = Client.createMock();
        
        // 设置客户端属性（通过反射或者其他方式）
        // 注意：这里只是示例，实际使用时需要根据Client类的具体实现来设置属性
        
        return client;
    }
    
    /**
     * 创建模拟的角色对象
     */
    private static Character createMockCharacter(int threadId, int logIndex) {
        // 创建一个模拟的角色对象，使用Character的getDefault方法
        Client mockClient = Client.createMock();
        Character character = Character.getDefault(mockClient);
        character.setName(CHARACTERS[RANDOM.nextInt(CHARACTERS.length)]);
        
        return character;
    }
    
    public static void main(String[] args) {
        // 执行性能测试: 10个线程，每个线程记录1000条日志
        runPerformanceTest(10, 1000);
    }
}