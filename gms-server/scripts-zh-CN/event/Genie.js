// 精灵渡轮地图 ID 常量
const MAP_ID = {
    ORBIS_BTF:       200000152,  // 候船室<开往阿里安特>
    ARIANT_BTF:      260000110,  // 候船室<开往天空之城>
    GENIE_TO_ORBIS:  200090410,  // 开往天空之城
    GENIE_TO_ARIANT: 200090400,  // 开往阿里安特
    ORBIS_DOCKED:    200000151,  // 码头<开往阿里安特>
    ARIANT_DOCKED:   260000100,  // 阿里安特码头
    ORBIS_STATION:   200000100,  // 天空之城售票处
};

const RIDE_MAPS = [MAP_ID.GENIE_TO_ORBIS, MAP_ID.GENIE_TO_ARIANT];
const WAIT_MAPS = [MAP_ID.ORBIS_BTF, MAP_ID.ARIANT_BTF];

let closeTime = 4 * 60 * 1000;
let beginTime = 5 * 60 * 1000;
let rideTime  = 5 * 60 * 1000;

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
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_DOCKED)) { getMap(MAP_ID.ORBIS_DOCKED).setDocked(true); }
    if (mapFactory().isMapLoaded(MAP_ID.ARIANT_DOCKED)) { getMap(MAP_ID.ARIANT_DOCKED).setDocked(true); }
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
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_BTF)) { getMap(MAP_ID.ORBIS_BTF).warpEveryone(MAP_ID.GENIE_TO_ARIANT); }
    if (mapFactory().isMapLoaded(MAP_ID.ARIANT_BTF)) { getMap(MAP_ID.ARIANT_BTF).warpEveryone(MAP_ID.GENIE_TO_ORBIS); }
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_DOCKED)) { getMap(MAP_ID.ORBIS_DOCKED).broadcastShip(false); }
    if (mapFactory().isMapLoaded(MAP_ID.ARIANT_DOCKED)) { getMap(MAP_ID.ARIANT_DOCKED).broadcastShip(false); }

    em.setProperty("docked", "false");
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_DOCKED)) { getMap(MAP_ID.ORBIS_DOCKED).setDocked(false); }
    if (mapFactory().isMapLoaded(MAP_ID.ARIANT_DOCKED)) { getMap(MAP_ID.ARIANT_DOCKED).setDocked(false); }
    em.setProperty("rideEndTime", String(Date.now() + rideTime));

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
    if (mapFactory().isMapLoaded(MAP_ID.GENIE_TO_ORBIS)) { getMap(MAP_ID.GENIE_TO_ORBIS).warpEveryone(MAP_ID.ORBIS_STATION, 0); }
    if (mapFactory().isMapLoaded(MAP_ID.GENIE_TO_ARIANT)) { getMap(MAP_ID.GENIE_TO_ARIANT).warpEveryone(MAP_ID.ARIANT_DOCKED, 1); }
    if (mapFactory().isMapLoaded(MAP_ID.ORBIS_DOCKED)) { getMap(MAP_ID.ORBIS_DOCKED).broadcastShip(true); }
    if (mapFactory().isMapLoaded(MAP_ID.ARIANT_DOCKED)) { getMap(MAP_ID.ARIANT_DOCKED).broadcastShip(true); }

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
