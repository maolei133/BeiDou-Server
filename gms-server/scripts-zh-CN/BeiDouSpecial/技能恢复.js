/*
 * 技能恢复脚本 (NextLevel 语法版)
 * 功能：
 * 1. 移除白名单限制，适用于所有冒险家职业
 * 2. 4转技能上限解锁 (Master Level) - 需完成对应任务或已习得技能
 * 3. 智能SP修正：根据等级计算理论SP，对比实际SP(已分配+剩余)，多退少补 (不包含新手技能SP)
 * 4. 恢复生活技能 (需检查任务完成状态)
 */

var SkillFactory = Java.type("org.gms.client.SkillFactory");
var GameConstants = Java.type("org.gms.constants.game.GameConstants");
var PacketCreator = Java.type("org.gms.util.PacketCreator");
var Stat = Java.type("org.gms.client.Stat");
var Pair = Java.type("org.gms.util.Pair");
var ArrayList = Java.type("java.util.ArrayList");

// ================= 配置区域 =================
// 需要恢复的生活技能列表
// 格式: [技能ID, 技能等级, 技能上限]
// 如果技能等级为 -1，则表示恢复到该技能的最高等级
var beginnerSkillsToRecover = [
    [   8, 1, 1],   // 群宠
    [1003, 1, 1],   // 匠人之魂 (Legendary Spirit)
    [1004, 1, 1],   // 骑兽技能 (Monster Rider)
    [1005, 1, 1],   // 英雄之回声 (Echo of Hero)
    [1007, 3, 3],   // 锻造 (Maker)
    // [1009, 1, 1],   // 流星竹雨 (Bamboo Rain)
    // [1010, 1, 1],   // 金刚霸体 (Invincible Barrier)
    // [1011, 1, 1],   // 狂暴战魂 (Power Explosion)
    // [1013, 2, 2],   // 宇宙船 (Spaceship)
    // [1014, 1, 1],   // 超时空冲锋 (Space Dash)
    // [1017, 1, 1],   // 白雪人骑宠 (Yeti Mount)
    // [1018, 1, 1],   // 白雪人骑宠 (Yeti Mount)
    // [1019, 1, 1],   // 魔女的扫把 (Witch Broomstick)
    // [1031, 1, 1]    // 蝙蝠怪 (Balrog Mount)
];

// 生活技能前置任务映射表 (Skill ID : Quest ID)
var skillQuestMap = {
       8: 4647,
    1003: 6000, // 匠人之魂
    1004: 6002, // 骑兽技能
    1005: 6800, // 英雄之回声
    1007: 6029  // 锻造
};

// 4转技能前置任务映射表 (Skill ID : Quest ID)
var skillQuestMap4th = {
    // 英雄
    1121002: 6192, // 稳如泰山
    1121010: 6153, // 葵花宝典
    1120005: 6180, // 寒冰掌
    1121011: 6304, // 勇士的意志
    1121006: 6110, // 突进

    // 圣骑士
    1221002: 6192, // 稳如泰山
    1221011: 6153, // 圣域
    1220006: 6180, // 寒冰掌
    1221003: 6280, // 圣灵之剑
    1221004: 6280, // 圣灵之锤
    1221012: 6304, // 勇士的意志
    1221007: 6110, // 突进

    // 黑骑士
    1321002: 6192, // 稳如泰山
    1320006: 6153, // 恶龙附身
    1320008: 6291, // 灵魂治愈
    1320009: 6295, // 灵魂祝福
    1321010: 6304, // 勇士的意志
    1321003: 6110, // 突进

    // 火毒魔导师
    2121007: 6167, // 天降落星
    2121005: 6225, // 冰破魔兽
    2121008: 6304, // 勇士的意志

    // 冰雷魔导师
    2221007: 6168, // 落霜冰破
    2221005: 6315, // 火魔兽
    2221008: 6304, // 勇士的意志

    // 主教
    2321008: 6169, // 圣光普照
    2321003: 6120, // 强化圣龙
    2321006: 6134, // 复活术
    2321009: 6304, // 勇士的意志

    // 神射手
    3121008: 6108, // 集中精力
    3121006: 6241, // 火凤凰
    3121004: 6250, // 暴风箭雨
    3121009: 6304, // 勇士的意志

    // 箭神
    3221007: 6108, // 一击要害箭
    3221005: 6243, // 冰凤凰
    3221001: 6251, // 穿透箭
    3221008: 6304, // 勇士的意志

    // 隐士
    4121004: 6141, // 忍者伏击
    4121008: 6231, // 忍者冲击
    4121009: 6304, // 勇士的意志

    // 侠盗
    4221004: 6141, // 忍者伏击
    4221001: 6202, // 暗杀
    4221008: 6304, // 勇士的意志

    // 冲锋队长
    5121010: 6363, // 伺机待发
    5121003: 6330, // 超能量
    5121004: 6350, // 金手指
    5121005: 6340, // 索命
    5121009: 6304, // 勇士的意志

    // 船长
    5221006: 6370, // 武装
    5221007: 6380, // 急速射
    5221008: 6390, // 重量炮击
    5221003: 6400, // 地毯式空袭
    5221009: 6410, // 心灵控制
    5221010: 6304  // 勇士的意志
};

// 4转职业技能静态配置 (Job ID : { Skill ID : Max Level })
var jobSkills = {
    112: { // 英雄
        1121000: 30, // 冒险岛勇士
        1121001: 30, // 磁石
        1121002: 30, // 稳如泰山
        1120003: 30, // 进阶斗气
        1120004: 30, // 阿基里斯
        1120005: 30, // 寒冰掌
        1121006: 30, // 突进
        1121008: 30, // 轻舞飞扬
        1121010: 30, // 葵花宝典
        1121011: 5   // 勇士的意志
    },
    122: { // 圣骑士
        1221000: 30, // 冒险岛勇士
        1221001: 30, // 磁石
        1221002: 30, // 稳如泰山
        1221003: 20, // 圣灵之剑
        1221004: 20, // 圣灵之锤
        1220005: 30, // 阿基里斯
        1220006: 30, // 寒冰掌
        1221007: 30, // 突进
        1221009: 30, // 连环环破
        1220010: 10, // 万佛归一破
        1221011: 30, // 圣域
        1221012: 5   // 勇士的意志
    },
    132: { // 黑骑士
        1321000: 30, // 冒险岛勇士
        1321001: 30, // 磁石
        1321002: 30, // 稳如泰山
        1321003: 30, // 突进
        1320005: 30, // 阿基里斯
        1320006: 30, // 恶龙附身
        1321007: 10, // 灵魂助力
        1320008: 25, // 灵魂治愈
        1320009: 25, // 灵魂祝福
        1321010: 5   // 勇士的意志
    },
    212: { // 火毒魔导师
        2121000: 30, // 冒险岛勇士
        2121001: 30, // 创世之破
        2121002: 30, // 魔法反击
        2121003: 30, // 火凤球
        2121004: 30, // 终极无限
        2121005: 30, // 冰破魔兽
        2121006: 30, // 连环爆破
        2121007: 30, // 天降落星
        2121008: 5   // 勇士的意志
    },
    222: { // 冰雷魔导师
        2221000: 30, // 冒险岛勇士
        2221001: 30, // 创世之破
        2221002: 30, // 魔法反击
        2221003: 30, // 冰凤球
        2221004: 30, // 终极无限
        2221005: 30, // 火魔兽
        2221006: 30, // 链环闪电
        2221007: 30, // 落霜冰破
        2221008: 5   // 勇士的意志
    },
    232: { // 主教
        2321000: 30, // 冒险岛勇士
        2321001: 30, // 创世之破
        2321002: 30, // 魔法反击
        2321003: 30, // 强化圣龙
        2321004: 30, // 终极无限
        2321005: 40, // 圣灵之盾
        2321006: 10, // 复活术
        2321007: 30, // 光芒飞箭
        2321008: 30, // 圣光普照
        2321009: 5   // 勇士的意志
    },
    312: { // 神射手
        3121000: 30, // 冒险岛勇士
        3121002: 30, // 火眼晶晶
        3121003: 30, // 飞龙冲击波
        3121004: 30, // 暴风箭雨
        3120005: 30, // 神箭手
        3121006: 30, // 火凤凰
        3121007: 30, // 击退箭
        3121008: 30, // 集中精力
        3121009: 5   // 勇士的意志
    },
    322: { // 箭神
        3221000: 30, // 冒险岛勇士
        3221001: 30, // 穿透箭
        3221002: 30, // 火眼晶晶
        3221003: 30, // 飞龙冲击波
        3220004: 30, // 神弩手
        3221005: 30, // 冰凤凰
        3221006: 30, // 刺眼箭
        3221007: 30, // 一击要害箭
        3221008: 5   // 勇士的意志
    },
    412: { // 隐士
        4121000: 30, // 冒险岛勇士
        4120002: 30, // 假动作
        4121003: 30, // 挑衅
        4121004: 30, // 忍者伏击
        4120005: 30, // 武器用毒液
        4121006: 30, // 暗器伤人
        4121007: 30, // 三连环光击破
        4121008: 30, // 忍者冲击
        4121009: 5   // 勇士的意志
    },
    422: { // 侠盗
        4221000: 30, // 冒险岛勇士
        4221001: 30, // 暗杀
        4220002: 30, // 假动作
        4221003: 30, // 挑衅
        4221004: 30, // 忍者伏击
        4220005: 30, // 武器用毒液
        4221006: 30, // 烟雾弹
        4221007: 30, // 一出双击
        4221008: 5   // 勇士的意志
    },
    512: { // 冲锋队长
        5121000: 30, // 冒险岛勇士
        5121001: 30, // 潜龙出渊
        5121002: 30, // 超能量
        5121003: 20, // 超级变身
        5121004: 30, // 金手指
        5121005: 30, // 索命
        5121007: 30, // 光速拳
        5121008: 5,  // 勇士的意志
        5121009: 20, // 极速领域
        5121010: 30  // 伺机待发
    },
    522: { // 船长
        5221000: 30, // 冒险岛勇士
        5220001: 30, // 属性强化
        5220002: 30, // 超级章鱼炮台
        5221003: 30, // 地毯式空袭
        5221004: 30, // 金属风暴
        5221006: 10, // 武装
        5221007: 30, // 急速射
        5221008: 30, // 重量炮击
        5221009: 20, // 心灵控制
        5221010: 5,  // 勇士的意志
        5220011: 20  // 导航辅助
    }
};
// ===========================================

function start() {
    levelMain();
}

function level() {
    cm.dispose();
}

function levelMain() {
    var player = cm.getPlayer();
    var jobId = player.getJob().getId();

    // 1. 检查职业是否为冒险家
    // 冒险家职业ID范围：100-522
    if (!(jobId >= 100 && jobId <= 522 && jobId < 1000)) {
        cm.sendOkLevel("End", "该脚本仅适用于冒险家职业。\r\n当前职业ID: " + jobId);
        return;
    }

    cm.sendYesNoLevel("End", "DoRecovery", "您好，我是技能恢复助手。\r\n职业: " + player.getJob().getName() + " (ID: " + jobId + ")\r\n等级: " + player.getLevel() + "\r\n\r\n是否开始执行技能恢复？\r\n#b1. 解锁4转技能上限(如果已4转)。\r\n2. 智能修正SP (多退少补)。\r\n3. 恢复生活技能。#k");
}

function levelDoRecovery() {
    var player = cm.getPlayer();
    var jobId = player.getJob().getId();
    var level = player.getLevel();
    var logMsg = "";

    // ================= 4转 技能恢复逻辑 =================
    var countUnlocked = 0;
    var targetSkills = jobSkills[jobId];
    
    if (targetSkills != null) {
        // 条件1: 检查是否为4转职业
        var is4thJob = (jobId % 10 == 2);
        
        if (is4thJob) {
            // ================= 原有的4转技能恢复逻辑 =================
            // 判断是否需要恢复4转技能
            var needRecover4th = false;
            
            // 基本条件：等级>120 + 总SP<预期SP
            // 先计算SP相关数据
            var jobLevel = 0;
            if (jobId % 100 == 0) jobLevel = 1;      // 1转
            else if (jobId % 10 == 0) jobLevel = 2; // 2转
            else if (jobId % 10 == 1) jobLevel = 3; // 3转
            else if (jobId % 10 == 2) jobLevel = 4; // 4转
                    
            var extraSP = jobLevel; // 每次转职送1点，共jobLevel点
                    
            var startLevel = 10;
            if (Math.floor(jobId / 100) == 2) { // 法师系
                startLevel = 8;
            }
                    
            var totalShouldHaveSP = (level - startLevel) * 3 + extraSP;
                    
            // 统计实际已分配SP (只统计职业技能)
            var totalAllocated = 0;
            var allSkills = player.getSkills();
            var skillIter = allSkills.keySet().iterator();
            while (skillIter.hasNext()) {
                var s = skillIter.next();
                var sId = s.getId();
                        
                // 排除新手技能 (技能ID < 10000)
                // 排除通用/特殊技能 (技能ID >= 10000000)
                if (sId >= 10000 && sId < 10000000) {
                    totalAllocated += player.getSkillLevel(s);
                }
            }
                    
            // 获取当前剩余职业SP
            var currentRemaining = 0;
            var sps = player.getRemainingSps();
            if (sps != null && sps.length > 0) {
                currentRemaining = sps[0];
            }
                    
            // 基本条件1：等级>120
            var levelOver120 = (level > 120);
                    
            // 基本条件2：总SP<预期SP
            var totalCurrentSP = totalAllocated + currentRemaining;
            var spLessThanExpected = (totalCurrentSP < totalShouldHaveSP);
                    
            // 基本条件满足
            var basicConditionMet = levelOver120 && spLessThanExpected;
                    
            // 附加条件1: 检查1~3转技能是否全为0级 且 存在1~3转技能
            var lowLevelSkillsZero = true;
            var hasLowLevelSkills = false;
            
            // 遍历1~3转技能
            for (var sId in targetSkills) {
                var skillId = parseInt(sId);
                // 判断是否为1~3转技能 (排除4转技能)
                if (skillId % 10000 < 1000) { // 1~3转技能ID特征
                    var skill = SkillFactory.getSkill(skillId);
                    if (skill != null) {
                        hasLowLevelSkills = true;
                        var currentLvl = player.getSkillLevel(skill);
                        if (currentLvl > 0) {
                            lowLevelSkillsZero = false;
                            break;
                        }
                    }
                }
            }
            
            // 附加条件2: 检查是否有已完成但技能缺失的4转任务
            var hasCompletedMissingSkills = false;
            for (var sId in targetSkills) {
                var skillId = parseInt(sId);
                // 检查4转技能
                if (skillId % 10000 >= 1000) { // 4转技能ID特征
                    var questId = skillQuestMap4th[skillId];
                    if (questId != null && cm.getQuestStatus(questId) == 2) {
                        var skill = SkillFactory.getSkill(skillId);
                        if (skill != null) {
                            var currentLvl = player.getSkillLevel(skill);
                            if (currentLvl <= 0) {
                                hasCompletedMissingSkills = true;
                                break;
                            }
                        }
                    }
                }
            }
            
            // 满足基本条件 + 任意一个附加条件就需要恢复
            var additionalConditionMet = (lowLevelSkillsZero && hasLowLevelSkills) || hasCompletedMissingSkills;
            needRecover4th = basicConditionMet && additionalConditionMet;
            
            // 执行4转技能恢复
            if (needRecover4th) {
                for (var sId in targetSkills) {
                    var skillId = parseInt(sId);
                    var maxLevel = targetSkills[sId];
                    
                    var skill = SkillFactory.getSkill(skillId);
                    if (skill != null) {
                        var currentLvl = player.getSkillLevel(skill);
                        if (currentLvl < 0) currentLvl = 0;
                        var masterLvl = player.getMasterLevel(skill);
                        
                        var shouldRecover = false;
                        
                        // 1. 检查是否为任务技能
                        if (skillQuestMap4th[skillId] != null) {
                            var questId = skillQuestMap4th[skillId];
                            if (cm.getQuestStatus(questId) == 2) {
                                shouldRecover = true;
                            }
                        } 
                        // 2. 所有4转技能都应该恢复（不再检查Master Level）
                        else {
                            shouldRecover = true;
                        }
                        
                        if (shouldRecover) {
                            if (masterLvl < maxLevel) {
                                cm.teachSkill(skillId, currentLvl, maxLevel, -1);
                                countUnlocked++;
                            }
                        }
                    }
                }
                logMsg += "【4转技能恢复】 已恢复 " + countUnlocked + " 个4转职业技能。\r\n";
            } else {
                logMsg += "【4转技能】 4转技能状态正常，无需恢复。\r\n";
            }
            
            // ================= 单独检测已完成任务但缺失的技能 =================
            var missingTaskSkillsCount = 0;
            
            // 重新遍历所有4转技能，检测任务完成但技能缺失的情况
            for (var sId in targetSkills) {
                var skillId = parseInt(sId);
                // 只检查4转技能中的任务绑定技能
                if (skillId % 10000 >= 1000) {
                    var questId = skillQuestMap4th[skillId];
                    if (questId != null) {
                        // 检查任务是否已完成
                        if (cm.getQuestStatus(questId) == 2) {
                            var skill = SkillFactory.getSkill(skillId);
                            if (skill != null) {
                                var currentLvl = player.getSkillLevel(skill);
                                // 如果技能等级为0或不存在，则需要恢复
                                if (currentLvl <= 0) {
                                    var masterLvl = player.getMasterLevel(skill);
                                    if (masterLvl < targetSkills[sId]) {
                                        cm.teachSkill(skillId, 0, targetSkills[sId], -1);
                                        missingTaskSkillsCount++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if (missingTaskSkillsCount > 0) {
                logMsg += "【任务技能补发】 额外恢复了 " + missingTaskSkillsCount + " 个已完成任务对应的技能。\r\n";
            }
        } else {
            logMsg += "【4转技能】 非4转职业，跳过4转技能检测。\r\n";
        }
    } else {
        logMsg += "【4转技能】 未找到对应职业的技能配置。\r\n";
    }

    // ================= 生活技能恢复逻辑 =================
    var countBeginner = 0;
    for (var i = 0; i < beginnerSkillsToRecover.length; i++) {
        var bSkillId = beginnerSkillsToRecover[i][0];
        var bSkillLevel = beginnerSkillsToRecover[i][1];
        var bSkillMaster = beginnerSkillsToRecover[i][2];

        // 检查前置任务
        if (skillQuestMap[bSkillId] != null) {
            var questId = skillQuestMap[bSkillId];
            if (cm.getQuestStatus(questId) != 2) {
                // 任务未完成，跳过
                continue;
            }
        }

        // 如果配置为-1，则尝试获取技能最大等级
        if (bSkillLevel == -1 || bSkillMaster == -1) {
            var bSkill = SkillFactory.getSkill(bSkillId);
            if (bSkill != null) {
                if (bSkillLevel == -1) bSkillLevel = bSkill.getMaxLevel();
                if (bSkillMaster == -1) bSkillMaster = bSkill.getMaxLevel();
            } else {
                // 技能不存在，跳过
                continue;
            }
        }

        // 检查玩家是否已拥有该技能且等级达标
        var currentBLvl = player.getSkillLevel(bSkillId);
        if (currentBLvl < bSkillLevel) {
            cm.teachSkill(bSkillId, bSkillLevel, bSkillMaster, -1);
            countBeginner++;
        }
    }
    if (countBeginner > 0) {
        logMsg += "【生活技能】 已恢复 " + countBeginner + " 个生活技能。\r\n";
    } else {
        logMsg += "【生活技能】 状态正常。\r\n";
    }

    // ================= 职业 SP 计算与修正逻辑 =================
    // 1. 计算转职阶段和额外SP
    var jobLevel = 0;
    if (jobId % 100 == 0) jobLevel = 1;      // 1转
    else if (jobId % 10 == 0) jobLevel = 2; // 2转
    else if (jobId % 10 == 1) jobLevel = 3; // 3转
    else if (jobId % 10 == 2) jobLevel = 4; // 4转
    
    var extraSP = jobLevel; // 每次转职送1点，共jobLevel点
    
    // 2. 计算理论总SP
    // 法师系 (200-299) 8级转职，其他 10级转职
    // 公式: (Level - 转职起始等级) * 3 + 转职赠送SP
    // 不包含新手技能的3点
    
    var startLevel = 10;
    if (Math.floor(jobId / 100) == 2) { // 法师系
        startLevel = 8;
    }
    
    var totalShouldHaveSP = (level - startLevel) * 3 + extraSP;
    
    // 3. 统计实际已分配SP (只统计职业技能)
    var totalAllocated = 0;
    var allSkills = player.getSkills();
    var skillIter = allSkills.keySet().iterator();
    while (skillIter.hasNext()) {
        var s = skillIter.next();
        var sId = s.getId();
        
        // 排除新手技能 (技能ID < 10000)
        // 排除通用/特殊技能 (技能ID >= 10000000)
        if (sId >= 10000 && sId < 10000000) {
            totalAllocated += player.getSkillLevel(s);
        }
    }
    
    // 4. 获取当前剩余职业SP
    // 冒险家职业SP在索引0 (包含新手SP和职业SP)
    // 注意：这里假设索引0是职业SP池。如果新手SP也在这里，可能会有偏差，但根据用户反馈，gainSp不处理新手SP
    var currentRemaining = 0;
    var sps = player.getRemainingSps();
    if (sps != null && sps.length > 0) {
        currentRemaining = sps[0];
    }
    
    // 5. 计算差值
    var targetRemaining = totalShouldHaveSP - totalAllocated;
    if (targetRemaining < 0) targetRemaining = 0;
    
    var gap = targetRemaining - currentRemaining;
    
    logMsg += "【SP计算】 等级: " + level + ", 起始: " + startLevel + ", 转职次数: " + jobLevel + "\r\n";
    logMsg += "【SP计算】 理论总SP: " + totalShouldHaveSP + " (升级" + ((level - startLevel) * 3) + " + 转职" + extraSP + ")\r\n";
    logMsg += "【SP计算】 已分配SP: " + totalAllocated + "\r\n";
    logMsg += "【SP计算】 当前剩余SP: " + currentRemaining + "\r\n";
    logMsg += "【SP计算】 目标剩余SP: " + targetRemaining + "\r\n";
    
    if (gap != 0) {
        // 修正SP (支持负数扣除)
        // 冒险家职业使用索引0
        player.gainSp(gap, 0, true); 
        
        if (gap > 0) {
            logMsg += "【SP修正】 补发 " + gap + " 点职业SP。\r\n";
        } else {
            logMsg += "【SP修正】 扣除 " + (-gap) + " 点职业SP。\r\n";
        }
        
        // 发送更新包
        var stats = new ArrayList();
        stats.add(new Pair(Stat.AVAILABLESP, player.getRemainingSp()));
        player.getClient().sendPacket(PacketCreator.updatePlayerStats(stats, true, player));
    } else {
        logMsg += "【SP修正】 职业SP点数正常，无需调整。\r\n";
    }

    cm.sendOkLevel("End", "技能恢复执行完毕！\r\n\r\n" + logMsg);
}

function levelEnd() {
    cm.dispose();
}
