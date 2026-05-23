const ENTRY_MAP_ID = 922000000;
const EXIT_MAP_ID  = 922000009;
var eventLength = 20;

function init() {
    em.setProperty("noEntry", "false");
}

function setup(level, lobbyid) {
    var eim = em.newInstance("q3239_" + lobbyid);
    eim.setExclusiveItems([4031092]);
    return eim;
}

function playerEntry(eim, player) {
    var im = eim.getInstanceMap(ENTRY_MAP_ID);

    // Reset instance
    im.clearDrops();
    im.resetReactors();
    im.shuffleReactors();

    // Start timer
    eim.startEventTimer(eventLength * 60 * 1000);

    // Warp player and mark event as occupied
    player.changeMap(ENTRY_MAP_ID, 0);
    em.setProperty("noEntry", "true");
}

function changedMap(eim, player, mapid) {
    if (mapid != ENTRY_MAP_ID)
        playerExit(eim, player);
}

function playerExit(eim, player) {
    end(eim);
}

function playerDisconnected(eim, player) {
    end(eim);
}

function scheduledTimeout(eim) {
    end(eim);
}

function end(eim) {
    var party = eim.getPlayers(); // should only ever be one player
    for (var i = 0; i < party.size(); i++) {
        var player = party.get(i);
        eim.unregisterPlayer(player);
        player.changeMap(EXIT_MAP_ID);
    }

    eim.dispose();
    em.setProperty("noEntry", "false");
}

// Stub/filler functions

function disbandParty(eim, player) {}
function afterSetup(eim) {}
function playerUnregistered(eim, player) {}
function changedLeader(eim, leader) {}
function leftParty(eim, player) {}
function clearPQ(eim) {}
function dispose() {}
function cancelSchedule() {}
function allMonstersDead(eim) {}
function monsterValue(eim, mobId) {}
function monsterKilled(mob, eim) {}
