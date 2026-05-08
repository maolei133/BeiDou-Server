package org.gms.agent;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.modifier.Ownership;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.implementation.MethodDelegation;

import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.net.URL;
import java.net.URLClassLoader;
import org.gms.net.packet.Packet;

import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * 自定义类加载器，用于在加载时使用 Byte Buddy 增强特定类的字节码。
 */
public class ByteBuddyClassLoader extends URLClassLoader {

    private static final String PACKET_CREATOR_CLASS = "org.gms.util.PacketCreator";
    private final ClassFileTransformer transformer;

    public ByteBuddyClassLoader(URL[] urls, ClassLoader parent) {
        super(urls, parent);
        // 创建一个 ClassFileTransformer，它只对 PacketCreator 类生效
        this.transformer = new AgentBuilder.Default()
                .type(named(PACKET_CREATOR_CLASS))
                .transform((builder, typeDescription, classLoader, javaModule, protectionDomain) -> builder
                        // 规则1: 拦截所有已存在的 public static Packet 方法
                        .method(isPublic().and(isStatic()).and(returns(named("org.gms.net.packet.Packet"))))
                        .intercept(MethodDelegation.to(PacketCreatorInterceptor.class))
                        // 规则2: 动态定义一个新的 invoke 方法
                        .defineMethod("invoke", Packet.class, Visibility.PUBLIC, Ownership.STATIC)
                        .withParameter(String.class, "methodName")
                        .withParameter(Object[].class, "args")
                        .intercept(MethodDelegation.to(InvokeMethodInterceptor.class))
                ).makeRaw();
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        // 只对我们的目标类进行特殊处理
        if (PACKET_CREATOR_CLASS.equals(name)) {
            // 首先检查该类是否已经被加载过，如果已加载，直接返回，避免重复加载
            Class<?> loadedClass = findLoadedClass(name);
            if (loadedClass != null) {
                return loadedClass;
            }

            try {
                // 找到类的 .class 文件资源
                String path = name.replace('.', '/').concat(".class");
                InputStream is = getResourceAsStream(path);
                if (is == null) {
                    throw new ClassNotFoundException("找不到类的文件: " + name);
                }

                byte[] originalBytes = is.readAllBytes();
                is.close();

                // 使用我们预先构建的 transformer 来增强字节码
                byte[] transformedBytes = transformer.transform(
                        this,
                        name,
                        null, // classBeingRedefined, null for first-time loading
                        null, // protectionDomain
                        originalBytes
                );

                // 如果 transformer 没有进行转换，则使用原始字节码
                if (transformedBytes == null) {
                    transformedBytes = originalBytes;
                }

                // 使用增强后的字节码来定义这个类
                return defineClass(name, transformedBytes, 0, transformedBytes.length);

            } catch (IOException | IllegalClassFormatException e) {
                throw new ClassNotFoundException("无法加载或转换类: " + name, e);
            }
        }

        // 对于所有其他类，使用默认的加载机制
        return super.loadClass(name, resolve);
    }
}
