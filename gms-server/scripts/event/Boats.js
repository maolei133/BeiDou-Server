// 渡轮地图 ID 常量
const MAP_ID = {
    ORBIS_BTF:       200000112,  // 候船室<开往魔法密林>
    BOAT_TO_ORBIS:   200090010,  // 开往天空之城
    ORBIS_CABIN:     200090011,  // 船仓<开往天空之城>
    ORBIS_DOCKED:    200000111,  // 码头<开往魔法密林>
    ELLINIA_BTF:     101000301,  // 候船室<开往天空之城>
    BOAT_TO_ELLINIA: 200090000,  // 开往魔法密林
    ELLINIA_CABIN:   200090001,  // 船仓<开往魔法密林>
    ELLINIA_DOCKED:  101000300,  // 魔法密林码头
    ORBIS_STATION:   200000100,  // 天空之城售票处
    CRIMSON_BALROG:  8150000,    // 蝙蝠魔怪物 ID
};

/** 本趟航行涉及的所有地图（用于航行期间pin保活） */
const RIDE_MAPS = [
    MAP_ID.BOAT_TO_ORBIS, MAP_ID.ORBIS_CABIN,
    MAP_ID.BOAT_TO_ELLINIA, MAP_ID.ELLINIA_CABIN,
];
/** 等候室地图（用于广播倒计时） */
const WAIT_MAPS = [MAP_ID.ORBIS_BTF, MAP_ID.ELLINIA_BTF];

// 时间设置（毫秒），会被 getTransportationTime() 修正
let closeTime         = 4 * 60 * 1000;   // 关闭登船入口 (4分钟)
let beginTime         = 5 * 60 * 1000;   // 启航准备时间 (5分钟)
let rideTime          = 30 * 60 * 1000;  // 航行时间 (10分钟)
let invasionStartTime = 3 * 60 * 1000;   // 蝙蝠魔接近时间 (3分钟)
let invasionDelayTime = 1 * 60 * 1000;   // 蝙蝠魔延迟 (1分钟)
let invasionDelay     = 5 * 1000;        // 蝙蝠魔生成延迟 (5秒)

const PacketCreator = Java.type('org.gms.util.PacketCreator');
// 倒计时配置
const REBROADCAST_INTERVAL = 10000;   // 广播刷新间隔（毫秒）
const COUNTDOWN_OFFSET_MS  = 1000;    // 倒计时提前量（毫秒），确保客户端00:00前事件已触发

const LifeFactory   = Java.type('org.gms.server.life.LifeFactory');

// ========== 辅助函数 ==========

function getMap(mapId) {
    return em.getChannelServer().getMapFactory().getMap(mapId);
}

function mapFactory() {
    return em.getChannelServer().getMapFactory();
}

/** 向等候室广播倒计时（基于 takeoffTime 计算剩余秒数） */
function broadcastWaitCountdown() {
    const takeoffTime = Number(em.getProperty("takeoffTime"));
    if (!takeoffTime) return;
    const sec = Math.max(1, Math.floor((takeoffTime - Date.now()) / 1000) + Math.ceil(COUNTDOWN_OFFSET_MS / 1000)); for (let i = 0; i < WAIT_MAPS.length; i++) { const id = WAIT_MAPS[i]; if (mapFactory().isMapLoaded(id)) { getMap(id).broadcastClock(sec); } }
}

/** 每隔30秒刷新等候室倒计时（新进入的玩家也能看到） */
function broadcastRideCountdown() { const rideEnd = em.getProperty("rideEndTime"); if (!rideEnd || rideEnd === "0") return; const sec = Math.max(1, Math.floor((Number(rideEnd) - Date.now()) / 1000) + Math.ceil(COUNTDOWN_OFFSET_MS / 1000)); for (let i = 0; i < RIDE_MAPS.length; i++) { const id = RIDE_MAPS[i]; if (mapFactory().isMapLoaded(id)) { getMap(id).broadcastClock(sec); } } }
function rebroadcastRide() { broadcastRideCountdown(); const rideEnd = em.getProperty("rideEndTime"); if (rideEnd && Number(rideEnd) > Date.now()) { em.schedule("rebroadcastRide", REBROADCAST_INTERVAL); } }
function rebroadcastWait() {
    broadcastWaitCountdown();
    if (em.getProperty("entry") === "true") {
        em.schedule("rebroadcastWait", REBROADCAST_INTERVAL);
    }
}

// ========== 生命周期 ==========

function init() {
    closeTime         = em.getTransportationTime(closeTime);
    beginTime         = em.getTransportationTime(beginTime);
    rideTime          = em.getTransportationTime(rideTime);
    invasionStartTime = em.getTransportationTime(invasionStartTime);
    invasionDelayTime = em.getTransportationTime(invasionDelayTime);

    if (mapFactory().isMapLoaded(MAP_ID.ELLINIA_DOCKED)) { getMap(MAP_ID.ELLINIA_DOCKED).setDocked(true); }
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_DOCKED)) { getMap(MAP_ID.ORBIS_DOCKED).setDocked(true); }

    scheduleNew();
}

function scheduleNew() {
    em.setProperty("docked", "true");
    em.setProperty("entry", "true");
    em.setProperty("haveBalrog", "false");
    em.setProperty("takeoffTime", String(Date.now() + beginTime));

    broadcastWaitCountdown();
    em.schedule("rebroadcastWait", REBROADCAST_INTERVAL);    // 每10秒刷新等候室倒计时
    em.schedule("stopentry", closeTime);
    em.schedule("takeoff", beginTime);
}

function stopentry() {
    em.setProperty("entry", "false");
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_CABIN)) { getMap(MAP_ID.ORBIS_CABIN).clearMapObjects(); }
    if (mapFactory().isMapLoaded(MAP_ID.ELLINIA_CABIN)) { getMap(MAP_ID.ELLINIA_CABIN).clearMapObjects(); }
}

function takeoff() {
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_BTF)) { getMap(MAP_ID.ORBIS_BTF).warpEveryone(MAP_ID.BOAT_TO_ELLINIA); }
    if (mapFactory().isMapLoaded(MAP_ID.ELLINIA_BTF)) { getMap(MAP_ID.ELLINIA_BTF).warpEveryone(MAP_ID.BOAT_TO_ORBIS); }
    if (mapFactory().isMapLoaded(MAP_ID.ELLINIA_DOCKED)) { getMap(MAP_ID.ELLINIA_DOCKED).broadcastShip(false); }
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_DOCKED)) { getMap(MAP_ID.ORBIS_DOCKED).broadcastShip(false); }

    em.setProperty("docked", "false");
    em.setProperty("rideEndTime", String(Date.now() + rideTime));

    // 航行期间pin运输地图，防止船舱无人被驱逐
    for (let i = 0; i < RIDE_MAPS.length; i++) {
        mapFactory().pinMap(RIDE_MAPS[i]);
    }

    // 给运输地图上的玩家发送倒计时
    const clockSec = Math.max(1, Math.floor(rideTime / 1000));
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ORBIS))   { getMap(MAP_ID.BOAT_TO_ORBIS).broadcastClock(clockSec); }
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ELLINIA)) { getMap(MAP_ID.BOAT_TO_ELLINIA).broadcastClock(clockSec); }
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_CABIN))     { getMap(MAP_ID.ORBIS_CABIN).broadcastClock(clockSec); }
    if (mapFactory().isMapLoaded(MAP_ID.ELLINIA_CABIN))   { getMap(MAP_ID.ELLINIA_CABIN).broadcastClock(clockSec); }

    if (Math.random() < 0.42) {
        em.schedule("approach", invasionStartTime + Math.trunc(Math.random() * invasionDelayTime));
    }

    em.schedule("rebroadcastRide", REBROADCAST_INTERVAL);
    em.schedule("arrived", rideTime);
}

function arrived() {
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ORBIS)) { getMap(MAP_ID.BOAT_TO_ORBIS).warpEveryone(MAP_ID.ORBIS_STATION, 0); }
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_CABIN)) { getMap(MAP_ID.ORBIS_CABIN).warpEveryone(MAP_ID.ORBIS_STATION, 0); }
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ELLINIA)) { getMap(MAP_ID.BOAT_TO_ELLINIA).warpEveryone(MAP_ID.ELLINIA_DOCKED, 1); }
    if (mapFactory().isMapLoaded(MAP_ID.ELLINIA_CABIN)) { getMap(MAP_ID.ELLINIA_CABIN).warpEveryone(MAP_ID.ELLINIA_DOCKED, 1); }

    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_DOCKED)) { getMap(MAP_ID.ORBIS_DOCKED).broadcastShip(true); }
    if (mapFactory().isMapLoaded(MAP_ID.ELLINIA_DOCKED)) { getMap(MAP_ID.ELLINIA_DOCKED).broadcastShip(true); }

    // 清除倒计时和蝙蝠魔
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ORBIS))   { getMap(MAP_ID.BOAT_TO_ORBIS).broadcastRemoveClock(); }
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ELLINIA)) { getMap(MAP_ID.BOAT_TO_ELLINIA).broadcastRemoveClock(); }
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ORBIS)) { getMap(MAP_ID.BOAT_TO_ORBIS).broadcastEnemyShip(false); }
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ELLINIA)) { getMap(MAP_ID.BOAT_TO_ELLINIA).broadcastEnemyShip(false); }
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ORBIS)) { getMap(MAP_ID.BOAT_TO_ORBIS).killAllMonsters(); }
    if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ELLINIA)) { getMap(MAP_ID.BOAT_TO_ELLINIA).killAllMonsters(); }
    em.setProperty("haveBalrog", "false");
    em.setProperty("rideEndTime", "0");

    // 航行结束，解除运输地图pin
    for (let i = 0; i < RIDE_MAPS.length; i++) {
        mapFactory().unpinMap(RIDE_MAPS[i]);
    }

    scheduleNew();
}

function approach() {
    if (Math.floor(Math.random() * 10) < 10) {
        em.setProperty("haveBalrog", "true");
        if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ORBIS)) { getMap(MAP_ID.BOAT_TO_ORBIS).broadcastEnemyShip(true); }
        if (mapFactory().isMapLoaded(MAP_ID.BOAT_TO_ELLINIA)) { getMap(MAP_ID.BOAT_TO_ELLINIA).broadcastEnemyShip(true); }

        getMap(MAP_ID.BOAT_TO_ORBIS).broadcastMessage(PacketCreator.musicChange("Bgm04/ArabPirate"));
        getMap(MAP_ID.BOAT_TO_ELLINIA).broadcastMessage(PacketCreator.musicChange("Bgm04/ArabPirate"));

        em.schedule("invasion", invasionDelay);
    }
}

function invasion() {
    const balrog = LifeFactory.getMonster(MAP_ID.CRIMSON_BALROG);
    getMap(MAP_ID.BOAT_TO_ELLINIA).spawnMonsterOnGroundBelow(balrog,  new java.awt.Point(-538, 143));
    getMap(MAP_ID.BOAT_TO_ELLINIA).spawnMonsterOnGroundBelow(balrog,  new java.awt.Point(-538, 143));
    getMap(MAP_ID.BOAT_TO_ORBIS).spawnMonsterOnGroundBelow(balrog,    new java.awt.Point(339, 148));
    getMap(MAP_ID.BOAT_TO_ORBIS).spawnMonsterOnGroundBelow(balrog,    new java.awt.Point(339, 148));
}

function cancelSchedule() {}

// ========== FILLER ==========
function dispose() {}
function setup(eim, leaderid) {}
function monsterValue(eim, mobid) { return 0; }
function disbandParty(eim, player) {}
function playerDisconnected(eim, player) {}
function playerEntry(eim, player) {}
function monsterKilled(mob, eim) {}
function scheduledTimeout(eim) {}
function afterSetup(eim) {}
function changedLeader(eim, leader) {}
function playerExit(eim, player) {}
function leftParty(eim, player) {}
function clearPQ(eim) {}
function allMonstersDead(eim) {}
function playerUnregistered(eim, player) {}
