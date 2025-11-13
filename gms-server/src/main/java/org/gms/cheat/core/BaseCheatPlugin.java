package org.gms.cheat.core;

import lombok.Getter;
import lombok.Setter;
import org.gms.client.Character;
import org.gms.net.server.Server;

/**
 * 作弊插件基类
 * 提供通用功能的默认实现
 */
@Getter
public abstract class BaseCheatPlugin implements CheatPlugin {
    protected Character player;
    
    @Getter
    @Setter
    protected boolean running = false;
    
    protected static long currentServerTime() {
        return Server.getInstance().getCurrentTime();
    }
    
    @Override
    public void initialize(Character player) {
        this.player = player;
    }
    
    @Override
    public void start() {
        if (!running) {
            running = true;
            onStart();
        }
    }
    
    @Override
    public void stop() {
        if (running) {
            running = false;
            onStop();
        }
    }
    
    /**
     * 子类可以重写此方法以实现启动逻辑
     */
    protected void onStart() {
        // 默认实现为空
    }
    
    /**
     * 子类可以重写此方法以实现停止逻辑
     */
    protected void onStop() {
        // 默认实现为空
    }
}