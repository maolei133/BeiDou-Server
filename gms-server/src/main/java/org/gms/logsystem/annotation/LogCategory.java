/* This file is part of the BeiDou Maple Story Server
Copyright (C) 2025 BeiDou Server https://github.com/BeiDouMS/BeiDou-Server
Magical-H https://github.com/Magical-H

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation version 3 as published by
the Free Software Foundation. You may not use, modify or distribute
this program under any otheer version of the GNU Affero General Public
License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; witout even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.


You should have received a copy of the GNU Affero General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
*/

package org.gms.logsystem.annotation;

import java.lang.annotation.*;

/**
 * 日志分类注解 - 用于标记和定义日志分类
 * 支持在运行时通过注解驱动的方式定义日志分类
 *
 * @author logs-system
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface LogCategory {
    /**
     * 大类名称
     */
    String majorCategory();

    /**
     * 小类名称
     */
    String minorCategory();

    /**
     * 分类描述
     */
    String description() default "";

    /**
     * 性能等级: HIGH(高频), MEDIUM(中频), LOW(低频)
     */
    String level() default "MEDIUM";

    /**
     * 是否启用
     */
    boolean enabled() default true;
}
