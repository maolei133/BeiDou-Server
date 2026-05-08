package org.gms.agent;

import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.proxy.ProxyExecutable;
import org.graalvm.polyglot.proxy.ProxyObject;
import org.gms.util.PacketCreatorManager;

import javax.script.ScriptException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * 一个多语言代理，它将一个Java类“伪装”成一个JS对象，并动态地添加了JS脚本中定义的方法。
 */
public class ScriptableJavaClassProxy implements ProxyObject {

    private final Class<?> javaClass;

    public ScriptableJavaClassProxy(Class<?> javaClass) {
        this.javaClass = javaClass;
    }

    /**
     * 将 GraalVM 的 Value 对象安全地转换为 Java 对象。
     * @param value 要转换的 Value 对象。
     * @return 对应的 Java 对象。
     */
    private Object convertValue(Value value) {
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.isHostObject()) {
            return value.asHostObject();
        }
        if (value.isString()) {
            return value.asString();
        }
        if (value.isBoolean()) {
            return value.asBoolean();
        }
        if (value.isNumber()) {
            double d = value.asDouble();
            if (d == (long) d) {
                if (d >= Integer.MIN_VALUE && d <= Integer.MAX_VALUE) {
                    return (int) d;
                }
                return (long) d;
            }
            return d;
        }
        // 对于其他类型（如JS数组、对象），可以根据需要添加更多转换逻辑
        // 默认情况下，返回原始的 Value 对象，让 GraalVM 自行处理
        return value;
    }

    @Override
    public Object getMember(String key) {
        // 1. 优先查找Java类中是否已存在同名的 public static 方法
        try {
            Method realMethod = Arrays.stream(javaClass.getMethods())
                    .filter(m -> m.getName().equals(key) && Modifier.isStatic(m.getModifiers()))
                    .findFirst()
                    .orElse(null);

            if (realMethod != null) {
                // 关键修复：将找到的Java方法也包装成一个ProxyExecutable
                return (ProxyExecutable) (arguments) -> {
                    try {
                        Object[] args = Stream.of(arguments).map(this::convertValue).toArray();
                        // 通过反射调用静态Java方法。
                        // 这个调用会被我们之前设置的ByteBuddy拦截器捕获。
                        return realMethod.invoke(null, args); // 'null' for static methods
                    } catch (Exception e) {
                        throw new RuntimeException("Error invoking proxied Java method: " + key, e);
                    }
                };
            }
        } catch (Exception e) {
            // 忽略，继续尝试从JS中查找
        }

        // 2. 如果Java中不存在，则检查JS脚本中是否存在该函数
        if (PacketCreatorManager.getInstance().hasFunction(key)) {
            // 如果函数存在，返回一个可执行的代理。
            return (ProxyExecutable) (arguments) -> {
                Object[] args = Stream.of(arguments).map(this::convertValue).toArray();
                // 真正执行JS函数
                try {
                    return PacketCreatorManager.getInstance().invoke(key, args);
                } catch (ScriptException | NoSuchMethodException e) {
                    throw new RuntimeException(e);
                }
            };
        }

        // Java和JS中都没有找到该成员，返回null
        return null;
    }

    @Override
    public Object getMemberKeys() {
        // 为了简单起见，我们不暴露所有键
        return null;
    }

    @Override
    public boolean hasMember(String key) {
        // 检查Java中是否存在该静态方法
        try {
            Method realMethod = Arrays.stream(javaClass.getMethods())
                    .filter(m -> m.getName().equals(key) && Modifier.isStatic(m.getModifiers()))
                    .findFirst()
                    .orElse(null);
            if (realMethod != null) {
                return true;
            }
        } catch (Exception e) {
            // 忽略
        }

        // 检查JS中是否存在该函数
        return PacketCreatorManager.getInstance().hasFunction(key);
    }

    @Override
    public void putMember(String key, Value value) {
        // 不支持设置成员
    }
}
