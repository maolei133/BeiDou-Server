/* This file is part of the BeiDou Maple Story Server
Copyright (C) 2025 BeiDou Server https://github.com/BeiDouMS/BeiDou-Server
Magical-H https://github.com/Magical-H

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation version 3 as published by
the Free Software Foundation. You may not use, modify or distribute
this program under any otheer version of the GNU Affero General Public
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; witout even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.


You should have received a copy of the GNU Affero General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
*/

package org.gms.logsystem.cache;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.config.LogConfig;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 用户数据缓存服务
 * 将角色信息缓存到日志目录的userdata.json文件中
 * 用于前端查询页面的下拉列表选择
 */
@Slf4j
@Service
public class UserDataCacheService {

    private final LogConfig logConfig;
    private final Map<Integer, AccountInfo> accountCache = new ConcurrentHashMap<>();
    private final Map<Integer, CharacterInfo> characterCache = new ConcurrentHashMap<>();
    private final Map<Integer, JobInfo> jobCache = new ConcurrentHashMap<>();
    private final Map<Integer, MapInfo> mapCache = new ConcurrentHashMap<>();

    public UserDataCacheService(LogConfig logConfig) {
        this.logConfig = logConfig;
        loadCache();
        initializeJobData();
    }

    /**
     * 加载缓存
     */
    public void loadCache() {
        Path cacheFile = getCacheFilePath();
        if (Files.exists(cacheFile)) {
            try {
                String content = Files.readString(cacheFile, StandardCharsets.UTF_8);
                if (content == null || content.trim().isEmpty()) {
                    log.warn("缓存文件为空，跳过加载");
                    return;
                }
                
                JSONObject data = JSON.parseObject(content);
                if (data == null) {
                    log.warn("无法解析缓存文件，跳过加载");
                    return;
                }
                
                // 加载账号
                JSONArray accounts = data.getJSONArray("accounts");
                if (accounts != null) {
                    for (int i = 0; i < accounts.size(); i++) {
                        try {
                            Object item = accounts.get(i);
                            if (item instanceof JSONObject) {
                                JSONObject acc = (JSONObject) item;
                                AccountInfo info = new AccountInfo();
                                info.setAccountId(acc.getIntValue("accountId"));
                                info.setAccountName(acc.getString("accountName"));
                                accountCache.put(info.getAccountId(), info);
                            }
                        } catch (Exception e) {
                            log.warn("加载账号数据失败: {}", e.getMessage());
                        }
                    }
                }
                
                // 加载角色
                JSONArray characters = data.getJSONArray("characters");
                if (characters != null) {
                    for (int i = 0; i < characters.size(); i++) {
                        try {
                            Object item = characters.get(i);
                            if (item instanceof JSONObject) {
                                JSONObject chr = (JSONObject) item;
                                CharacterInfo info = new CharacterInfo();
                                info.setCharacterId(chr.getIntValue("characterId"));
                                info.setCharacterName(chr.getString("characterName"));
                                info.setAccountId(chr.getIntValue("accountId"));
                                info.setLevel(chr.getIntValue("level"));
                                info.setJobId(chr.getIntValue("jobId"));
                                characterCache.put(info.getCharacterId(), info);
                            }
                        } catch (Exception e) {
                            log.warn("加载角色数据失败: {}", e.getMessage());
                        }
                    }
                }
                
                // 加载地图
                JSONArray maps = data.getJSONArray("maps");
                if (maps != null) {
                    for (int i = 0; i < maps.size(); i++) {
                        try {
                            Object item = maps.get(i);
                            if (item instanceof JSONObject) {
                                JSONObject map = (JSONObject) item;
                                MapInfo info = new MapInfo();
                                info.setMapId(map.getIntValue("mapId"));
                                info.setMapName(map.getString("mapName"));
                                mapCache.put(info.getMapId(), info);
                            }
                        } catch (Exception e) {
                            log.warn("加载地图数据失败: {}", e.getMessage());
                        }
                    }
                }
                
                log.info("用户数据缓存加载完成: {} 账号, {} 角色, {} 地图",
                        accountCache.size(), characterCache.size(), mapCache.size());
            } catch (Exception e) {
                log.error("加载用户数据缓存失败，将使用空缓存", e);
                // 清空可能损坏的缓存
                accountCache.clear();
                characterCache.clear();
                mapCache.clear();
            }
        } else {
            log.info("缓存文件不存在，将创建新缓存");
        }
    }

    /**
     * 初始化职业数据
     */
    private void initializeJobData() {
        // 冒险家系列
        addJob(0, "新手");
        addJob(100, "战士");
        addJob(110, "剑客");
        addJob(111, "勇士");
        addJob(112, "英雄");
        addJob(120, "准骑士");
        addJob(121, "骑士");
        addJob(122, "圣骑士");
        addJob(130, "枪战士");
        addJob(131, "龙骑士");
        addJob(132, "黑骑士");
        
        addJob(200, "魔法师");
        addJob(210, "火毒法师");
        addJob(211, "火毒巫师");
        addJob(212, "火毒大魔导师");
        addJob(220, "冰雷法师");
        addJob(221, "冰雷巫师");
        addJob(222, "冰雷大魔导师");
        addJob(230, "牧师");
        addJob(231, "祭司");
        addJob(232, "主教");
        
        addJob(300, "弓箭手");
        addJob(310, "猎人");
        addJob(311, "射手");
        addJob(312, "神射手");
        addJob(320, "弩弓手");
        addJob(321, "游侠");
        addJob(322, "箭神");
        
        addJob(400, "飞侠");
        addJob(410, "刺客");
        addJob(411, "无影人");
        addJob(412, "隐士");
        addJob(420, "侠客");
        addJob(421, "独行客");
        addJob(422, "侠盗");
        
        addJob(500, "海盗");
        addJob(510, "拳手");
        addJob(511, "斗士");
        addJob(512, "冲锋队长");
        addJob(520, "火枪手");
        addJob(521, "大副");
        addJob(522, "船长");
        
        // 骑士团
        addJob(1000, "初心者(贵族)");
        addJob(1100, "魂骑士");
        addJob(1110, "魂骑士2");
        addJob(1111, "魂骑士3");
        addJob(1112, "魂骑士4");
        addJob(1200, "炎术士");
        addJob(1210, "炎术士2");
        addJob(1211, "炎术士3");
        addJob(1212, "炎术士4");
        addJob(1300, "风灵使者");
        addJob(1310, "风灵使者2");
        addJob(1311, "风灵使者3");
        addJob(1312, "风灵使者4");
        addJob(1400, "夜行者");
        addJob(1410, "夜行者2");
        addJob(1411, "夜行者3");
        addJob(1412, "夜行者4");
        addJob(1500, "奇袭者");
        addJob(1510, "奇袭者2");
        addJob(1511, "奇袭者3");
        addJob(1512, "奇袭者4");
        
        // 战神
        addJob(2000, "战童");
        addJob(2100, "战神");
        addJob(2110, "战神2");
        addJob(2111, "战神3");
        addJob(2112, "战神4");
    }

    private void addJob(int jobId, String jobName) {
        JobInfo info = new JobInfo();
        info.setJobId(jobId);
        info.setJobName(jobName);
        jobCache.put(jobId, info);
    }

    /**
     * 保存缓存
     */
    public void saveCache() {
        try {
            Path cacheFile = getCacheFilePath();
            Files.createDirectories(cacheFile.getParent());
            
            JSONObject data = new JSONObject();
            
            // 转换账号数据
            JSONArray accountsArray = new JSONArray();
            for (AccountInfo info : accountCache.values()) {
                JSONObject acc = new JSONObject();
                acc.put("accountId", info.getAccountId());
                acc.put("accountName", info.getAccountName());
                accountsArray.add(acc);
            }
            data.put("accounts", accountsArray);
            
            // 转换角色数据
            JSONArray charactersArray = new JSONArray();
            for (CharacterInfo info : characterCache.values()) {
                JSONObject chr = new JSONObject();
                chr.put("characterId", info.getCharacterId());
                chr.put("characterName", info.getCharacterName());
                chr.put("accountId", info.getAccountId());
                chr.put("level", info.getLevel());
                chr.put("jobId", info.getJobId());
                charactersArray.add(chr);
            }
            data.put("characters", charactersArray);
            
            // 转换职业数据
            JSONArray jobsArray = new JSONArray();
            for (JobInfo info : jobCache.values()) {
                JSONObject job = new JSONObject();
                job.put("jobId", info.getJobId());
                job.put("jobName", info.getJobName());
                jobsArray.add(job);
            }
            data.put("jobs", jobsArray);
            
            // 转换地图数据
            JSONArray mapsArray = new JSONArray();
            for (MapInfo info : mapCache.values()) {
                JSONObject map = new JSONObject();
                map.put("mapId", info.getMapId());
                map.put("mapName", info.getMapName());
                mapsArray.add(map);
            }
            data.put("maps", mapsArray);
            
            data.put("lastUpdate", System.currentTimeMillis());
            
            Files.writeString(cacheFile, JSON.toJSONString(data), StandardCharsets.UTF_8);
            log.info("用户数据缓存已保存到: {}", cacheFile);
        } catch (IOException e) {
            log.error("保存用户数据缓存失败", e);
        }
    }

    private Path getCacheFilePath() {
        return Paths.get(logConfig.getLogDir(), "userdata.json");
    }

    /**
     * 更新账号信息
     */
    public void updateAccount(int accountId, String accountName) {
        AccountInfo info = accountCache.computeIfAbsent(accountId, k -> new AccountInfo());
        info.setAccountId(accountId);
        info.setAccountName(accountName);
        saveCache();
    }

    /**
     * 更新角色信息
     */
    public void updateCharacter(int characterId, String characterName, int accountId, int level, int jobId) {
        CharacterInfo info = characterCache.computeIfAbsent(characterId, k -> new CharacterInfo());
        info.setCharacterId(characterId);
        info.setCharacterName(characterName);
        info.setAccountId(accountId);
        info.setLevel(level);
        info.setJobId(jobId);
        saveCache();
    }

    /**
     * 更新地图信息
     */
    public void updateMap(int mapId, String mapName) {
        MapInfo info = mapCache.computeIfAbsent(mapId, k -> new MapInfo());
        info.setMapId(mapId);
        info.setMapName(mapName);
        saveCache();
    }

    /**
     * 获取账号列表（带格式化标签）
     */
    public List<Map<String, Object>> getAccountList() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (AccountInfo info : accountCache.values()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("value", info.getAccountId());
            item.put("label", info.getAccountName() + " - [" + info.getAccountId() + "]");
            item.put("accountId", info.getAccountId());
            item.put("accountName", info.getAccountName());
            result.add(item);
        }
        return result;
    }

    /**
     * 获取角色列表（带格式化标签）
     */
    public List<Map<String, Object>> getCharacterList() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (CharacterInfo info : characterCache.values()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("value", info.getCharacterId());
            item.put("label", info.getCharacterName() + " - [" + info.getCharacterId() + "]");
            item.put("characterId", info.getCharacterId());
            item.put("characterName", info.getCharacterName());
            item.put("accountId", info.getAccountId());
            item.put("level", info.getLevel());
            item.put("jobId", info.getJobId());
            result.add(item);
        }
        return result;
    }

    /**
     * 获取职业列表（带格式化标签）
     */
    public List<Map<String, Object>> getJobList() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (JobInfo info : jobCache.values()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("value", info.getJobId());
            item.put("label", info.getJobName() + " - [" + info.getJobId() + "]");
            item.put("jobId", info.getJobId());
            item.put("jobName", info.getJobName());
            result.add(item);
        }
        // 按jobId排序
        result.sort(Comparator.comparingInt(a -> (Integer) a.get("jobId")));
        return result;
    }

    /**
     * 获取地图列表（带格式化标签）
     */
    public List<Map<String, Object>> getMapList() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (MapInfo info : mapCache.values()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("value", info.getMapId());
            item.put("label", info.getMapName() + " - [" + info.getMapId() + "]");
            item.put("mapId", info.getMapId());
            item.put("mapName", info.getMapName());
            result.add(item);
        }
        return result;
    }

    /**
     * 获取所有缓存数据
     */
    public Map<String, Object> getAllCacheData() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("accounts", getAccountList());
        result.put("characters", getCharacterList());
        result.put("jobs", getJobList());
        result.put("maps", getMapList());
        result.put("stats", Map.of(
                "accountCount", accountCache.size(),
                "characterCount", characterCache.size(),
                "jobCount", jobCache.size(),
                "mapCount", mapCache.size()
        ));
        return result;
    }

    // 数据实体类
    @Data
    public static class AccountInfo {
        private int accountId;
        private String accountName;
    }

    @Data
    public static class CharacterInfo {
        private int characterId;
        private String characterName;
        private int accountId;
        private int level;
        private int jobId;
    }

    @Data
    public static class JobInfo {
        private int jobId;
        private String jobName;
    }

    @Data
    public static class MapInfo {
        private int mapId;
        private String mapName;
    }
}
