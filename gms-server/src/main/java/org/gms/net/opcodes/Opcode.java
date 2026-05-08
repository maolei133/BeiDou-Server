package org.gms.net.opcodes;

/**
 * 操作码（Opcode）接口。
 * <p>
 * 为所有操作码枚举（如 {@link RecvOpcode} 和 {@link SendOpcode}）提供一个通用契约。
 * 它确保了每个操作码都具有可读的整数值，并允许在运行时动态地修改该值。
 * 这种设计是实现从外部源（如脚本文件）热重载操作码值的关键。
 */
public interface Opcode {

    /**
     * 获取此操作码的当前整数值。
     *
     * @return 操作码的整数值。
     */
    int getValue();

    /**
     * 设置此操作码的整数值。
     * <p>
     * 此方法允许在运行时更改操作码的值，例如在从配置文件或脚本加载新值时。
     *
     * @param code 要设置的新整数值。
     */
    void setValue(int code);

    /**
     * 返回此操作码的枚举名称。
     * <p>
     * 这是 {@link Enum#name()} 的默认实现，接口中包含此方法是为了方便
     * 在泛型上下文中通过接口引用直接访问枚举实例的名称。
     *
     * @return 枚举常量的名称。
     */
    String name();
}
