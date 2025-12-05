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

package org.gms.logsystem.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.gms.logsystem.annotation.AutoLogContext;
import org.gms.logsystem.context.GameLogContext;
import org.gms.logsystem.context.LogContextManager;
import org.springframework.stereotype.Component;

/**
 * 日志上下文AOP切面 - 自动在方法执行时注入日志上下文
 * 支持通过@AutoLogContext注解自动捕获客户端和角色信息
 *
 * @author logs-system
 */
@Slf4j
@Aspect
@Component
public class LogContextAspect {
    private final LogContextManager contextManager;

    public LogContextAspect(LogContextManager contextManager) {
        this.contextManager = contextManager;
    }

    /**
     * 拦截标注了@AutoLogContext的方法，自动管理日志上下文
     */
    @Around("@annotation(autoLogContext)")
    public Object autoInjectContext(ProceedingJoinPoint joinPoint, AutoLogContext autoLogContext) throws Throwable {
        if (!autoLogContext.enabled()) {
            return joinPoint.proceed();
        }

        GameLogContext context = contextManager.getCurrentContext();
        boolean isNewContext = context == null;

        try {
            // 如果没有上下文，创建新的
            if (isNewContext) {
                context = contextManager.createContext();
                log.debug("为方法 {} 创建新的日志上下文", joinPoint.getSignature().getName());
            }

            // 执行目标方法
            Object result = joinPoint.proceed();

            log.debug("方法 {} 执行成功，上下文统计: {}", joinPoint.getSignature().getName(), contextManager.getContextCount());
            return result;
        } catch (Throwable throwable) {
            log.error("方法 {} 执行异常: {}", joinPoint.getSignature().getName(), throwable.getMessage(), throwable);
            throw throwable;
        } finally {
            // 如果是新创建的上下文，执行完毕后清除
            if (isNewContext) {
                contextManager.clearCurrentContext();
                log.debug("清除方法 {} 创建的日志上下文", joinPoint.getSignature().getName());
            }
        }
    }
}
