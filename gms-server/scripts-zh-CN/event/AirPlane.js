// 飞机地图 ID 常量
const MAP_ID = {
    KC_BFD:      540010100,  // 候机室<开往 CBD>
    CBD_BFD:     540010001,  // 候机室<开往废弃都市>
    PLANE_TO_CBD:540010101,  // 开往 CBD
    PLANE_TO_KC: 540010002,  // 开往废弃都市
    CBD_DOCKED:  540010000,  // CBD 机场
    KC_DOCKED:   103000000,  // 废弃都市
};

const RIDE_MAPS = [MAP_ID.PLANE_TO_CBD, MAP_ID.PLANE_TO_KC];
const WAIT_MAPS = [MAP_ID.KC_BFD, MAP_ID.CBD_BFD];

let closeTime = 4 * 60 * 1000;
let beginTime = 5 * 60 * 1000;
let rideTime  = 1 * 60 * 1000;

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
        em.schedule("rebroadcastWait", REBROADCAST_INTERVAL);
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
    if (mapFactory().isMapLoaded(MAP_ID.KC_BFD)) { getMap(MAP_ID.KC_BFD).warpEveryone(MAP_ID.PLANE_TO_CBD); }
    if (mapFactory().isMapLoaded(MAP_ID.CBD_BFD)) { getMap(MAP_ID.CBD_BFD).warpEveryone(MAP_ID.PLANE_TO_KC); }

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
    if (mapFactory().isMapLoaded(MAP_ID.PLANE_TO_CBD)) { getMap(MAP_ID.PLANE_TO_CBD).warpEveryone(MAP_ID.CBD_DOCKED, 0); }
    if (mapFactory().isMapLoaded(MAP_ID.PLANE_TO_KC)) { getMap(MAP_ID.PLANE_TO_KC).warpEveryone(MAP_ID.KC_DOCKED, 7); }

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
