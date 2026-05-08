package org.gms.agent;

import net.bytebuddy.implementation.bind.annotation.AllArguments;
import net.bytebuddy.implementation.bind.annotation.Origin;
import net.bytebuddy.implementation.bind.annotation.SuperCall;
import org.gms.net.packet.Packet;
import org.gms.util.PacketCreatorManager;

import java.lang.reflect.Method;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * PacketCreator 方法的拦截器。
 * <p>
 * Byte Buddy 会将对 PacketCreator 中符合条件的方法的调用，重定向到这个类的 intercept 方法。
 */
public class PacketCreatorInterceptor {

    /**
     * 拦截方法。
     *
     * @param originalMethod 被拦截的原始方法 (例如 getLoginFailed)。
     * @param originalCaller 一个可以调用原始方法实现的 Callable。
     * @param args           调用时传入的所有参数。
     * @return 最终的 Packet 对象。
     */
    public static Packet intercept(@Origin Method originalMethod, @SuperCall Callable<Packet> originalCaller, @AllArguments Object[] args) {
        
        // 将 Callable 包装成 Supplier，以符合 dispatch 方法的需要
        Supplier<Packet> fallback = () -> {
            try {
                return originalCaller.call();
            } catch (Exception e) {
                // 如果原始方法调用出错，则抛出运行时异常
                throw new RuntimeException("执行原始数据包创建方法时出错: " + originalMethod.getName(), e);
            }
        };

        // 调用我们之前设计的 dispatch 方法
        return PacketCreatorManager.getInstance().dispatch(
                originalMethod.getName(),
                fallback,
                args
        );
    }
}
