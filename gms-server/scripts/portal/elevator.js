/**
 * Ludibrium Eos Tower elevator portal.
 * Checks the Elevator event status:
 *   - goingUp/Down === "false" → elevator at this floor, allow entry
 *   - === "true" → elevator moving, deny
 * Countdown is managed by Elevator.js rebroadcastRide.
 */
function enter(pi) {
    try {
        var elevator = pi.getEventManager("Elevator");
        if (elevator == null) {
            pi.getPlayer().dropMessage(5, "The elevator is under maintenance.");
            return false;
        }
        var isGoingThisDir = elevator.getProperty(
            pi.getMapId() == 222020100 ? "goingUp" : "goingDown"
        );
        if (isGoingThisDir === "false") {
            pi.playPortalSound();
            pi.warp(pi.getMapId() == 222020100 ? 222020110 : 222020210, 0);
            // Notify the event to immediately refresh ride countdown for the new player
            elevator.schedule("broadcastRideCountdown", 0);
            return true;
        } else if (isGoingThisDir === "true") {
            pi.getPlayer().dropMessage(5, "The elevator is currently moving.");
        } else {
            pi.getPlayer().dropMessage(5, "Dafuq is happening?!");
        }
    } catch (e) {
        pi.getPlayer().dropMessage(5, "Error: " + e);
    }
    return false;
}