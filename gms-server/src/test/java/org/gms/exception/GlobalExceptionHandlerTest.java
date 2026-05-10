package org.gms.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.gms.model.dto.ResultBody;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.http.HttpMethod;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void bizExceptionShouldReturnBusinessCodeAndUnifiedFields() {
        HttpServletRequest request = request("/server/v1/test/biz", "POST");

        ResultBody<Object> response = handler.bizExceptionHandler(request, new BizException(12345, "业务失败"));

        assertEquals(12345, response.getCode());
        assertEquals("业务失败", response.getMessage());
        assertEquals("/server/v1/test/biz", response.getPath());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void parameterExceptionShouldReturnValidationCode() {
        HttpServletRequest request = request("/server/v1/test/param", "GET");

        ResultBody<Object> response = handler.parameterExceptionHandler(request, new IllegalArgumentException("参数错误"));

        assertEquals(10001, response.getCode());
        assertEquals("参数错误", response.getMessage());
        assertEquals("/server/v1/test/param", response.getPath());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void authenticationExceptionShouldReturnLoginExpiredCode() {
        HttpServletRequest request = request("/server/v1/test/auth", "GET");

        ResultBody<Object> response = handler.authenticationExceptionHandler(request, new BadCredentialsException("认证失败"));

        assertEquals(20002, response.getCode());
        assertEquals("认证失败或登录已失效", response.getMessage());
        assertEquals("/server/v1/test/auth", response.getPath());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void accessDeniedExceptionShouldReturnForbiddenCode() {
        HttpServletRequest request = request("/server/v1/test/forbidden", "GET");

        ResultBody<Object> response = handler.accessDeniedExceptionHandler(request, new AccessDeniedException("权限不足"));

        assertEquals(30001, response.getCode());
        assertEquals("权限不足，禁止访问", response.getMessage());
        assertEquals("/server/v1/test/forbidden", response.getPath());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void notFoundExceptionShouldReturnNotFoundCode() {
        HttpServletRequest request = request("/missing.js", "GET");

        ResultBody<Object> response = handler.notFoundExceptionHandler(request, new NoResourceFoundException(HttpMethod.GET, "/missing.js"));

        assertEquals(40404, response.getCode());
        assertEquals("请求的资源不存在", response.getMessage());
        assertEquals("/missing.js", response.getPath());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void systemExceptionShouldReturnInternalErrorCode() {
        HttpServletRequest request = request("/server/v1/test/system", "GET");

        ResultBody<Object> response = handler.exceptionHandler(request, new NullPointerException("空指针"));

        assertEquals(50000, response.getCode());
        assertEquals("服务器内部错误!", response.getMessage());
        assertEquals("/server/v1/test/system", response.getPath());
        assertNotNull(response.getTimestamp());
    }

    private HttpServletRequest request(String path, String method) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(path);
        when(request.getMethod()).thenReturn(method);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        return request;
    }
}
