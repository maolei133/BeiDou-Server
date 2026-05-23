// 通天塔电梯 — 配合 scripts/portal/elevator.js 使用
// 两车厢交替运行：下层车厢(222020110)→上层，上层车厢(222020210)→下层
// 等候 waitTime → 运输 rideTime → 抵达后反向开放，循环
// 电梯地图体积极小、频繁使用，全量 pinMap 避免 reactor 状态被驱逐重建破坏

const MAP_ID = {
    DOWN_WAIT:   222020100,  // 下层等候室（电梯外）
    UP_WAIT:     222020200,  // 上层等候室（电梯外）
    DOWN_RIDE:   222020110,  // 下层车厢内部（开往上层的电梯，等候出发）
    UP_RIDE:     222020210,  // 上层车厢内部（开往下层的电梯，等候出发）
    DOWN_ARRIVE: 222020111,  // 下层车厢运输中（正开往上层）
    UP_ARRIVE:   222020211,  // 上层车厢运输中（正开往下层）
};

/** 所有电梯内部地图（需周期性刷新等候倒计时） */
const RIDE_MAPS = [MAP_ID.DOWN_RIDE, MAP_ID.UP_RIDE];

/** 电梯等候时间（毫秒），受 getTransportationTime 调整 */
let waitTime = 60 * 1000;
/** 电梯运输时间（毫秒），受 getTransportationTime 调整 */
let rideTime = 60 * 1000;
/** 倒计时补偿秒数：Math.floor 截断不足1秒的零头，+1 使客户端00:00与实际发车对齐 */
const COUNTDOWN_OFFSET_SEC = 1;

/**
 * 初始化：pin 全部电梯地图、重置 reactor、开始首轮循环（下层车厢先发）。
 */
function init() {
    waitTime = em.getTransportationTime(waitTime);
    rideTime = em.getTransportationTime(rideTime);

    const mf = em.getChannelServer().getMapFactory();
    Object.values(MAP_ID).forEach(id => mf.pinMap(id));
    mf.getMap(MAP_ID.DOWN_WAIT).resetReactors();
    mf.getMap(MAP_ID.UP_WAIT).resetReactors();

    scheduleNew();
}

/**
 * 开放上行：下层车厢可进入，等候后发往上行。
 * 由 init / goUp 调用。
 */
function scheduleNew() {
    em.setProperty("goingUp", "false");                    // 下层可进入
    em.setProperty("goingDown", "true");                   // 上层不可进入

    const mf = em.getChannelServer().getMapFactory();
    mf.getMap(MAP_ID.DOWN_WAIT).resetReactors();
    mf.getMap(MAP_ID.UP_WAIT).setReactorState();

    em.schedule("goingUpNow", waitTime);
    startRideBroadcast();
}

/**
 * 开放下行：上层车厢可进入，等候后发往下行。
 * 由 isUpNow 调用。
 */
function goDown() {
    em.setProperty("goingUp", "true");                     // 下层不可进入
    em.setProperty("goingDown", "false");                  // 上层可进入

    em.schedule("goingDownNow", waitTime);
    startRideBroadcast();
}

/**
 * 开放上行（同 scheduleNew，由 isDownNow 调用）。
 */
function goUp() {
    scheduleNew();
}

// ========== 运输阶段 ==========

/**
 * 下层车厢出发上行：222020110 → 222020111，广播运输倒计时。
 * 由 scheduleNew / goUp 调度触发。
 */
function goingUpNow() {
    em.setProperty("goingUp", "true");                     // 运输中，禁止进入
    const mf = em.getChannelServer().getMapFactory();
    mf.getMap(MAP_ID.DOWN_RIDE).warpEveryone(MAP_ID.DOWN_ARRIVE);
    mf.getMap(MAP_ID.DOWN_ARRIVE).broadcastClock(
        Math.max(1, Math.floor(rideTime / 1000) + COUNTDOWN_OFFSET_SEC));
    mf.getMap(MAP_ID.DOWN_WAIT).setReactorState();
    em.schedule("isUpNow", rideTime);
}

/**
 * 上层车厢出发下行：222020210 → 222020211，广播运输倒计时。
 * 由 goDown 调度触发。
 */
function goingDownNow() {
    em.setProperty("goingDown", "true");                   // 运输中，禁止进入
    const mf = em.getChannelServer().getMapFactory();
    mf.getMap(MAP_ID.UP_RIDE).warpEveryone(MAP_ID.UP_ARRIVE);
    mf.getMap(MAP_ID.UP_ARRIVE).broadcastClock(
        Math.max(1, Math.floor(rideTime / 1000) + COUNTDOWN_OFFSET_SEC));
    mf.getMap(MAP_ID.UP_WAIT).setReactorState();
    em.schedule("isDownNow", rideTime);
}

/**
 * 上行抵达：下层车厢到达上层等候室，开放下行。
 * 由 goingUpNow 调度触发。
 */
function isUpNow() {
    const mf = em.getChannelServer().getMapFactory();
    mf.getMap(MAP_ID.UP_WAIT).resetReactors();
    mf.getMap(MAP_ID.DOWN_ARRIVE).broadcastRemoveClock();
    mf.getMap(MAP_ID.DOWN_ARRIVE).warpEveryone(MAP_ID.UP_WAIT, 0);
    goDown();
}

/**
 * 下行抵达：上层车厢到达下层等候室，开放上行。
 * 由 goingDownNow 调度触发。
 */
function isDownNow() {
    const mf = em.getChannelServer().getMapFactory();
    mf.getMap(MAP_ID.DOWN_WAIT).resetReactors();
    mf.getMap(MAP_ID.UP_ARRIVE).broadcastRemoveClock();
    mf.getMap(MAP_ID.UP_ARRIVE).warpEveryone(MAP_ID.DOWN_WAIT, 4);
    goUp();
}

// ========== 倒计时广播 ==========

/**
 * 启动等候阶段车厢内部倒计时广播链。
 * 记录出发时间戳 → 立即广播一次 → 调度周期性刷新。
 */
function startRideBroadcast() {
    em.setProperty("nextDeparture", String(Date.now() + waitTime));
    broadcastRideCountdown();
    em.schedule("rebroadcastRide", 10000);
}

/**
 * 基于 nextDeparture 计算剩余秒数，向所有等候出发的车厢地图广播倒计时。
 */
function broadcastRideCountdown() {
    const departure = Number(em.getProperty("nextDeparture"));
    if (!departure) return;
    const sec = Math.max(1, Math.floor((departure - Date.now()) / 1000) + COUNTDOWN_OFFSET_SEC);
    RIDE_MAPS.forEach(id => {
        em.getChannelServer().getMapFactory().getMap(id).broadcastClock(sec);
    });
}

/**
 * 每隔10秒刷新车厢等候倒计时（新进入的玩家立即看到）。
 * 出发时间到后自动终止。
 */
function rebroadcastRide() {
    broadcastRideCountdown();
    const departure = Number(em.getProperty("nextDeparture"));
    if (departure && departure > Date.now()) {
        em.schedule("rebroadcastRide", 10000);
    }
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
