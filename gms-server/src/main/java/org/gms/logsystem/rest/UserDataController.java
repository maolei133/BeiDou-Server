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

package org.gms.logsystem.rest;

import lombok.extern.slf4j.Slf4j;
import org.gms.logsystem.cache.UserDataCacheService;
import org.gms.model.dto.ResultBody;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 用户数据缓存REST API控制器
 * 提供角色信息缓存数据查询功能，用于前端下拉列表
 */
@Slf4j
@RestController("logSystemUserDataController")
@RequestMapping("/logsystem/userdata")
public class UserDataController {

    private final UserDataCacheService userDataCacheService;

    public UserDataController(UserDataCacheService userDataCacheService) {
        this.userDataCacheService = userDataCacheService;
    }

    /**
     * 获取所有缓存数据
     */
    @GetMapping
    public ResultBody<Map<String, Object>> getAllData() {
        return ResultBody.success(userDataCacheService.getAllCacheData());
    }

    /**
     * 获取账号列表
     */
    @GetMapping("/accounts")
    public ResultBody<List<Map<String, Object>>> getAccounts() {
        return ResultBody.success(userDataCacheService.getAccountList());
    }

    /**
     * 获取角色列表
     */
    @GetMapping("/characters")
    public ResultBody<List<Map<String, Object>>> getCharacters() {
        return ResultBody.success(userDataCacheService.getCharacterList());
    }

    /**
     * 获取职业列表
     */
    @GetMapping("/jobs")
    public ResultBody<List<Map<String, Object>>> getJobs() {
        return ResultBody.success(userDataCacheService.getJobList());
    }

    /**
     * 获取地图列表
     */
    @GetMapping("/maps")
    public ResultBody<List<Map<String, Object>>> getMaps() {
        return ResultBody.success(userDataCacheService.getMapList());
    }

    /**
     * 更新账号缓存
     */
    @PostMapping("/accounts")
    public ResultBody<Boolean> updateAccount(@RequestBody Map<String, Object> data) {
        int accountId = (Integer) data.get("accountId");
        String accountName = (String) data.get("accountName");
        userDataCacheService.updateAccount(accountId, accountName);
        return ResultBody.success(true);
    }

    /**
     * 更新角色缓存
     */
    @PostMapping("/characters")
    public ResultBody<Boolean> updateCharacter(@RequestBody Map<String, Object> data) {
        int characterId = (Integer) data.get("characterId");
        String characterName = (String) data.get("characterName");
        int accountId = (Integer) data.getOrDefault("accountId", 0);
        int level = (Integer) data.getOrDefault("level", 1);
        int jobId = (Integer) data.getOrDefault("jobId", 0);
        userDataCacheService.updateCharacter(characterId, characterName, accountId, level, jobId);
        return ResultBody.success(true);
    }

    /**
     * 更新地图缓存
     */
    @PostMapping("/maps")
    public ResultBody<Boolean> updateMap(@RequestBody Map<String, Object> data) {
        int mapId = (Integer) data.get("mapId");
        String mapName = (String) data.get("mapName");
        userDataCacheService.updateMap(mapId, mapName);
        return ResultBody.success(true);
    }

    /**
     * 刷新缓存
     */
    @PostMapping("/refresh")
    public ResultBody<Boolean> refreshCache() {
        userDataCacheService.loadCache();
        return ResultBody.success(true);
    }

    /**
     * 保存缓存
     */
    @PostMapping("/save")
    public ResultBody<Boolean> saveCache() {
        userDataCacheService.saveCache();
        return ResultBody.success(true);
    }
}
