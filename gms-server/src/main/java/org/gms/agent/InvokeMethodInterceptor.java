package org.gms.agent;

import net.bytebuddy.implementation.bind.annotation.AllArguments;
import net.bytebuddy.implementation.bind.annotation.Argument;
import org.gms.net.packet.Packet;
import org.gms.util.PacketCreatorManager;

import javax.script.ScriptException;

/**
 * 为 PacketCreator 动态生成的 invoke 方法的拦截器。
 * <p>
 * 当调用 PacketCreator.invoke("methodName", args...) 时，
 * Byte Buddy 会将调用委托到此类的 intercept 方法。
 */
public class InvokeMethodInterceptor {

    /**
     * 拦截对动态生成的 PacketCreator.invoke 方法的调用。
     *
     * @param methodName 第一个参数，即要在JS中调用的函数名。
     * @param args       第二个参数，即传递给JS函数的参数数组。
     * @return JS函数的返回值，通常是一个 Packet 对象。
     */
    public static Packet intercept(@Argument(0) String methodName, @Argument(1) Object[] args) throws Exception {
        Object result = PacketCreatorManager.getInstance().invoke(methodName, args);
        if (result instanceof Packet) {
            return (Packet) result;
        }
        // 如果JS函数没有返回Packet，或者调用失败，则返回null
        return null;
    }
}
