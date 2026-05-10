package org.gms.controller;

import org.gms.exception.BizException;
import org.gms.service.AccountService;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class LogSystemControllerTest {

    private final LogSystemController controller = new LogSystemController(
            mock(com.fasterxml.jackson.databind.ObjectMapper.class),
            mock(AccountService.class),
            mock(Environment.class));

    @Test
    void invalidLoggerLevelShouldUseUnifiedBusinessFailure() {
        BizException exception = assertThrows(
                BizException.class,
                () -> controller.setLoggerLevel("root", "BAD_LEVEL"));

        assertEquals(10001, exception.getErrorCode());
        assertEquals("无效的日志级别: BAD_LEVEL", exception.getErrorMsg());
    }

    @Test
    void invalidConfigFileNameShouldUseUnifiedBusinessFailure() {
        BizException exception = assertThrows(
                BizException.class,
                () -> controller.readConfigFile("../../secret.txt"));

        assertEquals(10001, exception.getErrorCode());
        assertEquals("非法的文件名: ../../secret.txt", exception.getErrorMsg());
    }
}
