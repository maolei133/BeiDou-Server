/*
脚本：累计签到系统
作者：Magical-h
日期：2025-09-30
备注：北斗开发组 - 累计签到奖励脚本
*/

/* 活动配置区域 - JSON格式 */
var config = {
    // 活动基本信息
    "activityName": "2025国庆七天乐",
    "activityDesc": "欢度国庆，累计签到赢好礼！",
    "activityId": "NATIONAL_DAY_2025",

    // 活动时间配置
    "startTime": "2025-10-01 00:00:00",
    "endTime": "2025-10-07 23:59:59",

    // 签到要求
    "requireOnlineMinutes": 4 * 60, // 需要在线分钟数才能签到

    // 测试模式配置
    "testMode": false, // 开启测试模式
    "testDay": 1, // 测试指定天数

    // 每日奖励配置 - 每天可以多个奖励
    "dailyRewards": {
        1: [
            { "id": 0, "qty": 1_000_000, "name": "金币" },
            { "id": 1, "qty": 50_000, "name": "经验值" },
            { "id": 4031179, "qty": 1, "name": "时空裂缝的碎片 D" },
            { "id": 4001017, "qty": 1, "name": "火焰的眼" },
            { "id": 2450000, "qty": 1, "name": "幸运的狩猎" , "desc": "30分钟内打怪获得的经验值增加2倍"},
        ],
        2: [
            { "id": 0, "qty": 2_000_000, "name": "金币" },
            { "id": 1, "qty": 100_000, "name": "经验值" },
            { "id": 4031179, "qty": 2, "name": "时空裂缝的碎片 D" },
            { "id": 4001017, "qty": 2, "name": "火焰的眼" },
            { "id": 2450000, "qty": 2, "name": "幸运的狩猎"  , "desc": "30分钟内打怪获得的经验值增加2倍"},
        ],
        3: [
            { "id": 0, "qty": 3_000_000, "name": "金币" },
            { "id": 1, "qty": 150_000, "name": "经验值" },
            { "id": 4031179, "qty": 2, "name": "时空裂缝的碎片 D" },
            { "id": 4001017, "qty": 2, "name": "火焰的眼" },
            // { "id": 2340000, "qty": 1, "name": "祝福卷轴" },
            { "id": 2450000, "qty": 3, "name": "幸运的狩猎"  , "desc": "30分钟内打怪获得的经验值增加2倍"},
            { "id": 2022070, "qty": 1, "name": "管理者的祝福" ,"flag" : 1 , "desc": "管理者给的神秘魔法，1小时内：攻击力与魔力增加20、防御力增加100、命中率与回避率增加50、移动速度与跳跃力增加10"},
        ],
        4: [
            { "id": 0, "qty": 4_000_000, "name": "金币" },
            { "id": 1, "qty": 200_000, "name": "经验值" },
            { "id": 4031179, "qty": 2, "name": "时空裂缝的碎片 D" },
            { "id": 4001017, "qty": 2, "name": "火焰的眼" },
            { "id": 2340000, "qty": 1, "name": "祝福卷轴" ,"flag" : 1 },
            { "id": 2450000, "qty": 3, "name": "幸运的狩猎"  , "desc": "30分钟内打怪获得的经验值增加2倍"},
            { "id": 2022070, "qty": 2, "name": "管理者的祝福" ,"flag" : 1 , "desc": "管理者给的神秘魔法，1小时内：攻击力与魔力增加20、防御力增加100、命中率与回避率增加50、移动速度与跳跃力增加10"},
        ],
        5: [
            { "id": 0, "qty": 5_000_000, "name": "金币" },
            { "id": 1, "qty": 250_000, "name": "经验值" },
            { "id": 4031179, "qty": 2, "name": "时空裂缝的碎片 D" },
            { "id": 4001017, "qty": 2, "name": "火焰的眼" },
            { "id": 2340000, "qty": 1, "name": "祝福卷轴" ,"flag" : 1 },
            { "id": 2450000, "qty": 3, "name": "幸运的狩猎"  , "desc": "30分钟内打怪获得的经验值增加2倍"},
            { "id": 2022070, "qty": 2, "name": "管理者的祝福" ,"flag" : 1 , "desc": "管理者给的神秘魔法，1小时内：攻击力与魔力增加20、防御力增加100、命中率与回避率增加50、移动速度与跳跃力增加10"},
        ],
        6: [
            { "id": 0, "qty": 6_000_000, "name": "金币" },
            { "id": 1, "qty": 300_000, "name": "经验值" },
            { "id": 4031179, "qty": 2, "name": "时空裂缝的碎片 D" },
            { "id": 4001017, "qty": 2, "name": "火焰的眼" },
            { "id": 2340000, "qty": 1, "name": "祝福卷轴" ,"flag" : 1 },
            { "id": 2450000, "qty": 4, "name": "幸运的狩猎"  , "desc": "30分钟内打怪获得的经验值增加2倍"},
            { "id": 2022070, "qty": 3, "name": "管理者的祝福" ,"flag" : 1 , "desc": "管理者给的神秘魔法，1小时内：攻击力与魔力增加20、防御力增加100、命中率与回避率增加50、移动速度与跳跃力增加10"},
        ],
        7: [
            { "id": 0, "qty": 7_000_000, "name": "金币" },
            { "id": 1, "qty": 350_000, "name": "经验值" },
            { "id": 4031179, "qty": 2, "name": "时空裂缝的碎片 D" },
            { "id": 4001017, "qty": 2, "name": "火焰的眼" },
            { "id": 2340000, "qty": 2, "name": "祝福卷轴" ,"flag" : 1 },
            { "id": 2450000, "qty": 5, "name": "幸运的狩猎"  , "desc": "30分钟内打怪获得的经验值增加2倍"},
            { "id": 2022070, "qty": 4, "name": "管理者的祝福"  ,"flag" : 1 , "desc": "管理者给的神秘魔法，1小时内：攻击力与魔力增加20、防御力增加100、命中率与回避率增加50、移动速度与跳跃力增加10"},
        ]
    },

    // 累计签到额外奖励
    "finalReward": {
        "requireDays": 7, // 需要累计签到天数
        "rewards": [
            { "id": 2340000, "qty": 5, "name": "祝福卷轴" ,"flag" : 1 },
            { "id": 2450000, "qty": 5, "name": "幸运的狩猎"  , "desc": "30分钟内打怪获得的经验值增加2倍"},
            { "id": 2022070, "qty": 4, "name": "管理者的祝福"  ,"flag" : 1 , "desc": "管理者给的神秘魔法，1小时内：攻击力与魔力增加20、防御力增加100、命中率与回避率增加50、移动速度与跳跃力增加10"},
        ]
    }
};

/* 常量定义 */
const STORAGE_KEY = "国庆签到记录";
const ITEM_TEMPLATES = {
    0: '#fUI/Basic.img/BtCoin/normal/0#   #fUI/UIWindow.img/QuestIcon/7/0#',
    1: '#fUI/CashShop.img/CashItem/0#   #e#b点券#k#n',
    2: '#fUI/CashShop.img/CashItem/0#   #e#b抵用券#k#n',
    4: '#fUI/CashShop.img/CashItem/0#   #e#b信用点#k#n',
    5: '#fUI/UIWindow.img/AriantMatch/characterIcon/2#   #fUI/UIWindow.img/QuestIcon/8/0#'
};
const ITEM_NAME = {
    0: '金币',
    1: '点券',
    2: '抵用券',
    4: '信用点',
    5: '经验值'
};

/* 全局变量 */
var player;
var today;
var signData;
var canSignToday = false;
var hasFinalReward = false;
var currentDay = 1; // 当前是第几天
var todayCanSign = false; // 今天是否可以签到
var totalActivityDays = 0; // 活动总天数

// 计算活动总天数
function calculateTotalDays() {
    const startTime = parseDateTime(config.startTime);
    const endTime = parseDateTime(config.endTime);
    const oneDay = 24 * 60 * 60 * 1000; // 一天的毫秒数

    // 计算从开始日期到结束日期的天数差
    const dayDiff = Math.floor((endTime - startTime) / oneDay) + 1;

    return Math.max(1, dayDiff);
}

// 时间解析函数
function parseDateTime(dateTimeStr) {
    const [datePart, timePart] = dateTimeStr.split(" ");
    const [year, month, day] = datePart.split("-").map(Number);
    const [hours, minutes, seconds] = timePart.split(":").map(Number);
    return new Date(year, month - 1, day, hours, minutes, seconds).getTime();
}

// 获取当前日期字符串 (YYYY-MM-DD)
function getTodayString() {
    const now = new Date();
    return now.getFullYear() + "-" +
        String(now.getMonth() + 1).padStart(2, '0') + "-" +
        String(now.getDate()).padStart(2, '0');
}

// 获取当前时间字符串 (YYYY-MM-DD HH:MM:SS)
function getCurrentTimeString() {
    const now = new Date();
    return now.getFullYear() + "-" +
        String(now.getMonth() + 1).padStart(2, '0') + "-" +
        String(now.getDate()).padStart(2, '0') + " " +
        String(now.getHours()).padStart(2, '0') + ":" +
        String(now.getMinutes()).padStart(2, '0') + ":" +
        String(now.getSeconds()).padStart(2, '0');
}

// 计算当前是第几天
function calculateCurrentDay() {
    if (config.testMode) {
        return config.testDay; // 测试模式使用指定天数
    }

    const startTime = parseDateTime(config.startTime);
    const currentTime = Date.now();
    const oneDay = 24 * 60 * 60 * 1000; // 一天的毫秒数

    // 计算从开始日期到现在的天数差
    const dayDiff = Math.floor((currentTime - startTime) / oneDay) + 1;

    // 确保天数在有效范围内
    return Math.max(1, Math.min(totalActivityDays, dayDiff));
}

// 获取某一天的奖励配置（支持回退机制）
function getRewardsForDay(day) {
    // 如果当天有配置，直接返回
    if (config.dailyRewards[day]) {
        return config.dailyRewards[day];
    }

    // 否则向前查找最近的有配置的天数
    for (let prevDay = day - 1; prevDay >= 1; prevDay--) {
        if (config.dailyRewards[prevDay]) {
            return config.dailyRewards[prevDay];
        }
    }

    // 如果都没有配置，返回空数组
    return [];
}

// 获取签到存储数据
function getSignData() {
    const storageJson = cm.getAccountExtendValue(STORAGE_KEY);
    try {
        if (!storageJson) return null;
        const data = JSON.parse(storageJson);

        // 检查活动ID是否匹配
        if (data.activityId !== config.activityId) {
            cm.saveOrUpdateAccountExtendValue(STORAGE_KEY, "");
            return null;
        }

        return data;
    } catch (e) {
        return null;
    }
}

// 更新签到数据
function updateSignData(day) {
    let currentTime;

    if (config.testMode) {
        // 测试模式下，基于当前时间加上指定天数计算签到时间
        const now = new Date();
        const simulatedDate = new Date(now.getTime() + (day - 1) * 24 * 60 * 60 * 1000);
        currentTime = simulatedDate.getFullYear() + "-" +
            String(simulatedDate.getMonth() + 1).padStart(2, '0') + "-" +
            String(simulatedDate.getDate()).padStart(2, '0') + " " +
            String(now.getHours()).padStart(2, '0') + ":" +
            String(now.getMinutes()).padStart(2, '0') + ":" +
            String(now.getSeconds()).padStart(2, '0');
    } else {
        currentTime = getCurrentTimeString();
    }

    let data = getSignData() || {};

    if (!data.activityId) {
        // 新签到记录
        data = {
            activityId: config.activityId,
            activityName: config.activityName,
            signRecords: {}, // 记录每天的具体签到时间
            rewardRecords: {}, // 新增：记录每天发放的奖励
            totalSigned: 0,
            rewardHistory: [],
            finalRewardClaimed: false
        };
    }

    // 更新签到信息
    if (!data.signRecords[day]) {
        data.signRecords[day] = currentTime;
        // 记录发放的奖励
        const dayRewards = getRewardsForDay(day).map(item => {
            const {id,name,flag} = item;
            return {"id":id,"name":name,"flag":flag};
        });
        data.rewardRecords[day] = dayRewards;
        data.totalSigned = Object.keys(data.signRecords).length;
    }

    cm.saveOrUpdateAccountExtendValue(STORAGE_KEY, JSON.stringify(data));
    return data;
}

// 检查活动状态
function checkActivityStatus() {
    const currentTime = Date.now();
    const startTime = parseDateTime(config.startTime);
    const endTime = parseDateTime(config.endTime);

    if (currentTime < startTime) {
        return "not_started";
    } else if (currentTime > endTime) {
        return "ended";
    } else {
        return "active";
    }
}

// 检查今天是否可以签到
function checkTodaySignStatus() {
    today = getTodayString();
    signData = getSignData();
    currentDay = calculateCurrentDay();

    if (!signData) {
        return true; // 新玩家可以签到
    }

    if (config.testMode) {
        // 测试模式下，检查指定天数是否已经签到
        return !signData.signRecords || !signData.signRecords[currentDay];
    } else {
        // 正常模式下，检查今天是否已经签到
        const todaySignRecord = Object.entries(signData.signRecords || {}).find(([day, time]) => {
            return time.startsWith(today);
        });

        return !todaySignRecord;
    }
}

// 检查背包空间
function checkInventorySpace(rewards) {
    const normalItems = rewards.filter(reward => reward.id >= 1000000);

    for (const reward of normalItems) {
        if (!player.canHold(reward.id, reward.qty)) {
            return false;
        }
    }

    return true;
}

// 发放奖励
function giveRewards(rewards) {
    const successItems = [];

    for (const reward of rewards) {
        const { id, qty ,name,flag,desc} = reward;

        if (id >= 1000000) {
            // 物品奖励
            if (flag == 1) {
                try {
                    cm.gainItem(id, qty, 0x08 | 0x200, config.activityName + " (不可交换)");
                } catch (e) {
                    createUntradeableItem(id, qty,config.activityName + " (不可交换)");
                }
            } else {
                cm.gainItem(id, qty);
            }
            successItems.push(`#i${id}#   #e#b#t${id}##k#n × #r${getTimeImage(qty,6)}#k${desc ? "\r\n(" + desc + ")": ""}`);
        } else {
            // 虚拟货币奖励
            switch (id) {
                case 0: // 金币
                    cm.gainMeso(qty);
                    successItems.push(`${ITEM_TEMPLATES[id]} × #r${getTimeImage(qty,6)}#k`);
                    break;
                case 1: // 点券
                case 2: // 抵用券
                case 4: // 信用点
                    player.getCashShop().gainCash(id, qty);
                    player.dropMessage(5,`获取 ${ITEM_NAME[id]} × ${qty}`);
                    successItems.push(`${ITEM_TEMPLATES[id]} × #r${getTimeImage(qty,6)}#k`);
                    break;
                case 5: // 经验值
                    cm.gainExp(qty);
                    successItems.push(`${ITEM_TEMPLATES[id]} × #r${getTimeImage(qty,6)}#k`);
                    break;
            }
        }
    }

    return successItems;
}

// 格式化奖励显示 - 参考在线奖励_nextlevel.js的getRewardList方法
function formatRewardDisplay(rewards) {
    return rewards.map(reward => {
        const { id, qty ,flag ,name,desc} = reward;
        let itemshow = ITEM_TEMPLATES[id] ?? '';

        // 处理不同物品类型的显示逻辑
        if (id >= 1000000) {
            itemshow = `#i${id}#   #e#b#t${id}##k#n${flag == 1 ? "#r(不可交换)#k" : ""} × #r${getTimeImage(qty,6)}#k${desc ? "\r\n   (" + desc + ")": ""}`;
        } else if (itemshow) {
            itemshow += ` × #r${getTimeImage(qty,6)}#k`;
        } else {
            itemshow = `#fUI/UIWindow.img/KeyConfig/BtHelp/mouseOver/0# #e#r未知物品ID：[#k ${id} #r]#k#n`;
        }

        return `\t#fUI/CashShop.img/CSDiscount/arrow#${itemshow}`;
    }).join('\r\n');
}

// 生成进度条显示
function generateProgressBar() {
    const signedCount = signData ? signData.totalSigned : 0;
    const progress = Math.floor((signedCount / totalActivityDays) * 100);

    let progressBar = `\r\n#e签到进度：#k#n`;
    progressBar += `#B${progress}#`;
    progressBar += `#e${getTimeImage(signedCount,6)}#k#n / #e${getTimeImage(totalActivityDays,6)}#k#n 天 (${progress}%)\r\n\r\n`;

    return progressBar;
}

// 生成奖励预览和签到选项
function generateRewardPreview() {
    let preview = "#e#b【每日奖励预览】#k#n";

    for (let day = 1; day <= totalActivityDays; day++) {
        const dayRewards = getRewardsForDay(day);
        const isSigned = signData && signData.signRecords && signData.signRecords[day];

        // 判断签到状态
        let statusText;
        let LL = "";
        if (isSigned) {
            statusText = "【#g已签到#k】";
        } else if (day < currentDay) {
            statusText = "【#r未签到#k】";
        } else if (day === currentDay) {
            // 如果是今天且未签到，添加签到选项
            if (!isSigned && todayCanSign) {
                LL = `#L${day}#`;
                statusText = `【#g#e立即签到#k#n】#l\r\n`;
            } else {
                statusText = "【#b待签到#k】";
            }
        } else {
            statusText = "【#b待签到#k】";
        }

        preview += `\r\n\r\n${LL}#e第 ${getTimeImage(day,8)} 天奖励 ${statusText}#n\r\n\r\n`;
        preview += formatRewardDisplay(dayRewards);
        preview += "\r\n─────────────────────────";
    }

    // 累计奖励预览
    preview += `\r\n\r\n\r\n#e#d【累计奖励】#k#n\r\n\r\n`;
    preview += `累计签到#e#r${getTimeImage(config.finalReward.requireDays,6)}天#k#n可获得:\r\n\r\n`;
    preview += formatRewardDisplay(config.finalReward.rewards);

    return preview;
}

/* NextLevel 函数 */
function start() {
    player = cm.getPlayer();
    if (config.testMode) {
        if (!player.isGM()) {
            config.testMode = false;//非GM玩家不允许使用测试模式
        } else {
            config.requireOnlineMinutes = 0;
        }
    }

    // 计算活动总天数
    totalActivityDays = calculateTotalDays();
    levelMain();
}

function levelMain() {
    // 检查活动状态
    const activityStatus = checkActivityStatus();
    const startTime = new Date(parseDateTime(config.startTime)).toLocaleString();
    const endTime = new Date(parseDateTime(config.endTime)).toLocaleString();

    /*    if (activityStatus === "not_started") {
            cm.sendOkLevel("",
                `#e#r【${config.activityName}】#k#n\r\n
                #b活动尚未开始！#k\r\n
                开始时间: ${config.startTime}\r\n
                结束时间: ${config.endTime}\r\n\r\n
                #e请耐心等待活动开启哦！#k`
            );
            return;
        } else */
    if (activityStatus === "ended") {
        cm.sendOkLevel("",
            `#e#r【${config.activityName}】#k#n\r\n
            #b活动已结束！#k\r\n
            开始时间: ${config.startTime}\r\n
            结束时间: ${config.endTime}\r\n\r\n
            #e感谢您的参与，期待下次活动！#k`
        );
        return;
    }

    // 检查签到状态
    canSignToday = activityStatus === "active" && checkTodaySignStatus();
    signData = getSignData();
    currentDay = calculateCurrentDay();

    // 检查今天是否可以签到
    const onlineMinutes = Math.floor(cm.getOnlineTime() / 60);
    todayCanSign = canSignToday && onlineMinutes >= config.requireOnlineMinutes;

    let welcomeMsg = `#e#r【${config.activityName}】#k#n\r\n`;
    welcomeMsg += `#b${config.activityDesc}#k\r\n\r\n`;

    // 显示活动时间
    welcomeMsg += `活动时间\r\n${config.startTime}\r\n`;
    welcomeMsg += `${config.endTime}\r\n\r\n`;

    // 显示当前天数（测试模式下显示）
    if (config.testMode) {
        welcomeMsg += `#e测试模式：当前第 ${currentDay} 天#k#n\r\n\r\n`;
    }

    // 显示签到要求
    welcomeMsg += `签到要求: 每日在线 ${getLevelImage(config.requireOnlineMinutes,5)}#b分钟#k\r\n`;

    // 显示今日在线时间
    const onlineTimeDisplay = onlineMinutes >= 60 ?
        `${Math.floor(onlineMinutes / 60)}小时${onlineMinutes % 60}分钟` :
        `${onlineMinutes}分钟`;

    welcomeMsg += `今日在线: #e#b${onlineTimeDisplay}#k#n\r\n\r\n`;

    // 显示签到进度条
    welcomeMsg += generateProgressBar();

    // 显示签到进度
    if (signData) {
        // welcomeMsg += `签到进度: #e#b${signData.totalSigned || 0}#k#n / ${totalActivityDays} 天\r\n`;

        // 显示最后签到时间
        if (signData.signRecords && Object.keys(signData.signRecords).length > 0) {
            const lastSignDay = Math.max(...Object.keys(signData.signRecords).map(Number));
            const lastSignTime = signData.signRecords[lastSignDay];
            welcomeMsg += `最后签到: ${lastSignTime}\r\n\r\n`;
        } else {
            welcomeMsg += `最后签到: 暂无\r\n\r\n`;
        }
    } else {
        // welcomeMsg += `签到进度: #e#b0#k#n / ${totalActivityDays} 天\r\n`;
        welcomeMsg += `最后签到: 暂无\r\n\r\n`;
    }

    // 检查是否可以领取最终奖励
    hasFinalReward = signData &&
        signData.totalSigned >= config.finalReward.requireDays &&
        !signData.finalRewardClaimed;

    if (hasFinalReward) {
        welcomeMsg += `#e#g恭喜！你可以领取累计签到奖励！#k#n\r\n\r\n`;
    }

    // 生成奖励预览和签到选项
    welcomeMsg += generateRewardPreview();

    // 添加最终奖励选项（如果有）
    if (hasFinalReward) {
        welcomeMsg += `\r\n#L0#领取累计签到奖励#l\r\n`;
    }

    if (todayCanSign) {
        // 今天可以签到，显示签到选项
        cm.sendNextSelectLevel("handleSelection", welcomeMsg);
    } else if (hasFinalReward) {
        // 不能签到但有最终奖励可领
        cm.sendNextSelectLevel("handleSelection", welcomeMsg);
    } else {
        // 既不能签到也没有最终奖励
        cm.sendOkLevel("", welcomeMsg);
    }
}

function levelhandleSelection(selection) {
    if (selection >= 1 && selection <= totalActivityDays) {
        // 签到处理
        levelSignDay(selection);
    } else if (selection === 0) {
        // 领取累计奖励
        levelClaimFinalReward();
    } else {
        levelMain();
    }
}

function levelSignDay(day) {
    // 获取对应天数的奖励（使用回退机制）
    const dayRewards = getRewardsForDay(day);

    if (dayRewards.length === 0) {
        cm.sendOkLevel("", `#e#r第${day}天没有配置奖励！#k#n`);
        return;
    }

    // 检查是否已经签到过这一天
    if (signData && signData.signRecords && signData.signRecords[day]) {
        cm.sendOkLevel("", `#e#r第${day}天已经签到过了！#k#n\r\n请勿重复签到。`);
        return;
    }

    // 检查背包空间
    if (!checkInventorySpace(dayRewards)) {
        cm.sendOkLevel("",
            `#e#r背包空间不足！#k#n\r\n\r\n
            请清理背包后再来签到第${day}天。\r\n
            需要足够的空格子来接收物品奖励。`
        );
        return;
    }

    // 发放奖励
    const successItems = giveRewards(dayRewards);

    // 更新签到记录（包含奖励记录）
    signData = updateSignData(day);

    player.dropMessage(0,`已领取第 ${day} 天签到奖励！`);
    let successMsg = `#e#g签到成功！#k#n\r\n\r\n`;
    successMsg += `恭喜你完成第#e#b${day}#k#n天签到！\r\n\r\n`;
    successMsg += `获得奖励:\r\n`;
    successMsg += successItems.map(item => `#fUI/Basic.img/CheckBox/1# ${item}`).join('\r\n');
    successMsg += `\r\n\r\n`;
    successMsg += `当前进度: #e#b${signData.totalSigned}#k#n / ${totalActivityDays} 天\r\n`;

    // 检查是否可以领取最终奖励
    if (signData.totalSigned >= config.finalReward.requireDays && !signData.finalRewardClaimed) {
        successMsg += `\r\n#e#g恭喜！你已经达到累计签到要求，可以领取最终奖励！#k#n`;
    }

    cm.sendOkLevel("", successMsg);
}

function levelClaimFinalReward() {
    if (!hasFinalReward) {
        cm.sendOkLevel("", `#e#r你还没有达到领取累计奖励的条件！#k#n`);
        return;
    }

    // 检查背包空间
    if (!checkInventorySpace(config.finalReward.rewards)) {
        cm.sendOkLevel("",
            `#e#r背包空间不足！#k#n\r\n\r\n
            请清理背包后再来领取累计签到奖励。\r\n
            需要足够的空格子来接收所有物品奖励。`
        );
        return;
    }

    const rewardDisplay = formatRewardDisplay(config.finalReward.rewards);

    cm.sendYesNoLevel("main", "confirmFinalReward",
        `#e#b确认领取累计签到奖励吗？#k#n\r\n\r\n
#e恭喜累计签到 #r${config.finalReward.requireDays}天#e！#k\r\n\r\n
你将获得以下奖励:\r\n\r\n
${rewardDisplay}\r\n\r\n
#e累计奖励只能领取一次，确认领取吗？#k`
    );
}

function levelconfirmFinalReward() {
    // 发放最终奖励
    const successItems = giveRewards(config.finalReward.rewards);

    // 更新签到记录，标记最终奖励已领取
    signData.finalRewardClaimed = true;
    signData.rewardHistory.push({
        date: getCurrentTimeString(),
        type: "final",
        rewards: config.finalReward.rewards
    });

    cm.saveOrUpdateAccountExtendValue(STORAGE_KEY, JSON.stringify(signData));

    let successMsg = `#e#g累计奖励领取成功！#k#n\r\n\r\n`;
    successMsg += `感谢你坚持签到#e#r${config.finalReward.requireDays}天#k#n！\r\n\r\n`;
    successMsg += `获得累计奖励:\r\n`;
    successMsg += successItems.map(item => `#fUI/Basic.img/CheckBox/1# ${item}`).join('\r\n');
    successMsg += `\r\n\r\n`;
    successMsg += `#e期待在下次活动中与你再见！#k`;

    cm.sendOkLevel("", successMsg);
}

/**
 * 生成不可交易物品的JS方法
 * @param {number} itemId - 物品ID
 * @param {number} quantity - 数量
 * @param {string} playerName - 玩家名称（可选，默认当前玩家）
 * @returns {boolean} 是否成功生成
 */
function createUntradeableItem(itemId, quantity, playerName) {
    try {
        // 引用必要的Java类
        var InventoryManipulator = Java.type('org.gms.client.inventory.manipulator.InventoryManipulator');
        var ItemConstants = Java.type('org.gms.constants.inventory.ItemConstants');
        var ItemInformationProvider = Java.type('org.gms.server.ItemInformationProvider').getInstance();

        // 获取当前玩家和客户端
        var client = player.getClient();

        // 设置不可交易标志位
        var flag = ItemConstants.UNTRADEABLE | ItemConstants.MERGE_UNTRADEABLE;

        // 使用玩家名称或默认值
        var ownerName = (playerName || player.getName());

        // 调用添加物品方法
        var success = InventoryManipulator.addById(
            client,      // 客户端
            itemId,      // 物品ID
            quantity,    // 数量
            ownerName,   // 所有者
            -1,          // petId (-1表示非宠物)
            flag,        // 标志位（包含UNTRADEABLE）
            -1           // 过期时间 (-1表示永不过期)
        );
        return success;

    } catch (e) {
        console.log("生成不可交易物品时发生错误: " + e.toString());
        return false;
    }
}

/**
 * 生成不可交易的宠物
 * @param {number} petItemId - 宠物物品ID
 * @param {number} days - 有效期（天数）
 * @param {string} playerName - 玩家名称（可选）
 * @returns {boolean} 是否成功生成
 */
function createUntradeablePet(petItemId, days, playerName) {
    try {
        var InventoryManipulator = Java.type('org.gms.client.inventory.manipulator.InventoryManipulator');
        var ItemConstants = Java.type('org.gms.constants.inventory.ItemConstants');
        var ItemInformationProvider = Java.type('org.gms.server.ItemInformationProvider').getInstance();
        var DAYS = Java.type('java.util.concurrent.TimeUnit').DAYS;

        var player = typeof c !== 'undefined' ? c.getPlayer() : null;
        var client = typeof c !== 'undefined' ? c : null;

        if (!player || !client) {
            print("错误: 无法获取玩家或客户端对象");
            return false;
        }

        // 验证是否为宠物物品
        if (!ItemConstants.isPet(petItemId)) {
            player.yellowMessage("该物品不是宠物");
            return false;
        }

        // 设置有效期
        var expirationDays = Math.max(1, days || 30);
        var expiration = Java.type('java.lang.System').currentTimeMillis() + DAYS.toMillis(expirationDays);

        // 创建宠物ID
        var petid = Pet.createPet(petItemId);

        // 设置不可交易标志
        var flag = ItemConstants.UNTRADEABLE;
        if (player.gmLevel() < 3) {
            flag |= ItemConstants.ACCOUNT_SHARING;
        }

        var ownerName = playerName || player.getName();

        // 调用添加宠物方法（注意：宠物数量固定为1）
        return InventoryManipulator.addById(
            client,
            petItemId,
            1,           // 宠物数量始终为1
            ownerName,
            petid,       // 宠物ID
            flag,        // 标志位
            expiration   // 过期时间
        );

    } catch (e) {
        print("生成不可交易宠物时发生错误: " + e.toString());
        return false;
    }
}

/**
 * 生成带有自定义标志位的物品（高级用法）
 * @param {number} itemId - 物品ID
 * @param {number} quantity - 数量
 * @param {number} customFlags - 自定义标志位组合
 * @param {string} playerName - 玩家名称（可选）
 * @returns {boolean} 是否成功生成
 */
function createCustomFlagItem(itemId, quantity, customFlags, playerName) {
    try {
        var InventoryManipulator = Java.type('org.gms.client.inventory.manipulator.InventoryManipulator');
        var ItemInformationProvider = Java.type('org.gms.server.ItemInformationProvider').getInstance();

        var player = typeof c !== 'undefined' ? c.getPlayer() : null;
        var client = typeof c !== 'undefined' ? c : null;

        if (!player || !client) {
            print("错误: 无法获取玩家或客户端对象");
            return false;
        }

        // 验证物品
        if (ItemInformationProvider.getName(itemId) == null) {
            player.yellowMessage("物品ID " + itemId + " 不存在");
            return false;
        }

        var ownerName = playerName || player.getName();

        return InventoryManipulator.addById(
            client,
            itemId,
            quantity,
            ownerName,
            -1,
            customFlags,
            -1
        );

    } catch (e) {
        print("生成自定义标志物品时发生错误: " + e.toString());
        return false;
    }
}

/**
 * 生成数字图标
 * @param level 数字
 * @param type 类型（ 0 ~ 4 ）
 * @returns {string[]}
 */
function getLevelImage(level,type) {
    let UI = []
    UI.push('Basic/LevelNo/');
    UI.push('Basic/ItemNo/');
    UI.push('UIWindow/SkillEx/SpNum/');
    UI.push('UIWindow/VegaSpell/Count/');
    UI.push('UIWindow/ToolTip/Equip/GrowthEnabled/');
    UI.push('UIWindow/PartyRace/Stage/number2/');
    type = !type ? 0 : type;
    type = type > UI.length ? UI.length : type;
    UI = UI[type];
    return [...level.toString()].map(str => `#fUI/${UI + str}#`).join("");
}

function getTimeImage(time,type) {
    let UI = []
    UI.push('Basic/LevelNo/');
    UI.push('Basic/ItemNo/');
    UI.push('UIWindow/SkillEx/SpNum/');
    UI.push('UIWindow/VegaSpell/Count/');
    UI.push('UIWindow/ToolTip/Equip/GrowthEnabled/');
    UI.push('UIWindow/PartyRace/Stage/number2/');
    UI.push('UIWindow/MonsterKilling/Count/number2/');
    UI.push('UIWindow/MonsterKilling/Result/number2/');
    UI.push('UIWindow/Minigame/MemoryGame/number/');
    type = !type ? 0 : type;
    type = type > UI.length ? UI.length : type;
    UI = UI[type];
    return [...time.toString()].map(str => {
        if (str != ":" && str != " " && str >= 0 && str <= 9) {str = `#fUI/${UI + str}#`};
        return str;
    }).join("");
}

function level() {
    cm.dispose();
}
