/**
 * 通天塔电梯传送门。
 * 玩家触发传送门时，检查电梯事件状态：
 *   - goingUp/Down === "false" → 电梯在本层，可进入
 *   - === "true" → 电梯移动中，拒绝
 * 进入后倒计时由 Elevator.js 的 rebroadcastRide 负责。
 */
function enter(pi) {
    try {
        var elevator = pi.getEventManager("Elevator");
        var mapid = pi.getMapId();
        if (elevator == null) {
            pi.getPlayer().dropMessage(5, "电梯正在维修中");
            return false;
        }
        var isGoingThisDir = elevator.getProperty(
            mapid == 222020100 ? "goingUp" : "goingDown"
        );
        if (isGoingThisDir === "false") {
            pi.playPortalSound();
            pi.warp(mapid == 222020100 ? 222020110 : 222020210, 2);
            // 通知事件立即刷新电梯内部倒计时（新进入的玩家立即看到剩余时间）
            elevator.schedule("broadcastRideCountdown", 0);
            return true;
        } else if (isGoingThisDir === "true") {
            pi.getPlayer().dropMessage(5, "电梯正在移动中");
        } else {
            pi.getPlayer().dropMessage(5, "电梯系统有异常，请联系管理员处理。");
        }
    } catch (e) {
        pi.getPlayer().dropMessage(5, "系统错误：" + e);
    }
    return false;
}