// 地铁地图 ID 常量
const MAP_ID = {
    KC_WAITING:   600010004,  // 候车室<开往新叶城>
    NLC_WAITING:  600010002,  // 候车室<开往废弃都市>
    SUBWAY_TO_KC: 600010003,  // 开往废弃都市
    SUBWAY_TO_NLC:600010005,  // 开往新叶城
    KC_DOCKED:    103000100,  // 废弃都市地铁售票处
    NLC_DOCKED:   600010001,  // 新叶城地铁站
};

const RIDE_MAPS = [MAP_ID.SUBWAY_TO_KC, MAP_ID.SUBWAY_TO_NLC];
const WAIT_MAPS = [MAP_ID.KC_WAITING, MAP_ID.NLC_WAITING];

let closeTime = 50 * 1000;       // 关闭入口 (50秒)
let beginTime = 1 * 60 * 1000;   // 发车准备 (1分钟)
let rideTime  = 4 * 60 * 1000;   // 行驶时间 (4分钟)

const REBROADCAST_INTERVAL = 10000;   // 广播刷新间隔（毫秒）
const COUNTDOWN_OFFSET_MS  = 1000;    // 倒计时提前量（毫秒），确保客户端00:00前事件已触发


function getMap(mapId) {
    return em.getChannelServer().getMapFactory().getMap(mapId);
}

function mapFactory() {
    return em.getChannelServer().getMapFactory();
}

function broadcastWaitCountdown() {
    const takeoffTime = Number(em.getProperty("takeoffTime"));
    if (!takeoffTime) return;
    const sec = Math.max(1, Math.floor((takeoffTime - Date.now()) / 1000) + Math.ceil(COUNTDOWN_OFFSET_MS / 1000)); for (let i = 0; i < WAIT_MAPS.length; i++) { const id = WAIT_MAPS[i]; if (mapFactory().isMapLoaded(id)) { getMap(id).broadcastClock(sec); } }
}

function broadcastRideCountdown() { const rideEnd = em.getProperty("rideEndTime"); if (!rideEnd || rideEnd === "0") return; const sec = Math.max(1, Math.floor((Number(rideEnd) - Date.now()) / 1000) + Math.ceil(COUNTDOWN_OFFSET_MS / 1000)); for (let i = 0; i < RIDE_MAPS.length; i++) { const id = RIDE_MAPS[i]; if (mapFactory().isMapLoaded(id)) { getMap(id).broadcastClock(sec); } } }
function rebroadcastRide() { broadcastRideCountdown(); const rideEnd = em.getProperty("rideEndTime"); if (rideEnd && Number(rideEnd) > Date.now()) { em.schedule("rebroadcastRide", REBROADCAST_INTERVAL); } }
function rebroadcastWait() {
    broadcastWaitCountdown();
    if (em.getProperty("entry") === "true") {
        em.schedule("rebroadcastWait", REBROADCAST_INTERVAL);  // 每30秒刷新
    }
}

function init() {
    closeTime = em.getTransportationTime(closeTime);
    beginTime = em.getTransportationTime(beginTime);
    rideTime  = em.getTransportationTime(rideTime);
    scheduleNew();
}

function scheduleNew() {
    em.setProperty("docked", "true");
    em.setProperty("entry", "true");
    em.setProperty("takeoffTime", String(Date.now() + beginTime));

    broadcastWaitCountdown();
    em.schedule("rebroadcastWait", REBROADCAST_INTERVAL);
    em.schedule("stopEntry", closeTime);
    em.schedule("takeoff", beginTime);
}

function stopEntry() {
    em.setProperty("entry", "false");
}

function takeoff() {
    em.setProperty("docked", "false");
    em.setProperty("rideEndTime", String(Date.now() + rideTime));
    if (mapFactory().isMapLoaded(MAP_ID.KC_WAITING)) { getMap(MAP_ID.KC_WAITING).warpEveryone(MAP_ID.SUBWAY_TO_NLC); }
    if (mapFactory().isMapLoaded(MAP_ID.NLC_WAITING)) { getMap(MAP_ID.NLC_WAITING).warpEveryone(MAP_ID.SUBWAY_TO_KC); }

    for (let i = 0; i < RIDE_MAPS.length; i++) {
        mapFactory().pinMap(RIDE_MAPS[i]);
    }

    for (let i = 0; i < RIDE_MAPS.length; i++) {
        if (mapFactory().isMapLoaded(RIDE_MAPS[i])) { getMap(RIDE_MAPS[i]).broadcastClock(Math.max(1, Math.floor(rideTime / 1000) - 1)); }
    }

    em.schedule("rebroadcastRide", REBROADCAST_INTERVAL);
    em.schedule("arrived", rideTime);
}

function arrived() {
    if (mapFactory().isMapLoaded(MAP_ID.SUBWAY_TO_KC)) { getMap(MAP_ID.SUBWAY_TO_KC).warpEveryone(MAP_ID.KC_DOCKED, 0); }
    if (mapFactory().isMapLoaded(MAP_ID.SUBWAY_TO_NLC)) { getMap(MAP_ID.SUBWAY_TO_NLC).warpEveryone(MAP_ID.NLC_DOCKED, 0); }

    for (let i = 0; i < RIDE_MAPS.length; i++) {
        if (mapFactory().isMapLoaded(RIDE_MAPS[i])) { getMap(RIDE_MAPS[i]).broadcastRemoveClock(); }
        mapFactory().unpinMap(RIDE_MAPS[i]);
    }

    em.setProperty("rideEndTime", "0");
    scheduleNew();
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
