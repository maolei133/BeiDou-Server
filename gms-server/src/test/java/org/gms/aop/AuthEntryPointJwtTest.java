package org.gms.aop;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthEntryPointJwtTest {

    @Test
    void commenceShouldReturnUnifiedAuthenticationBody() throws Exception {
        AuthEntryPointJwt entryPoint = new AuthEntryPointJwt();
        HttpServletRequest request = request("/server/v1/protected", "GET");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter responseBody = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseBody));

        entryPoint.commence(request, response, new BadCredentialsException("认证失败"));

        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        JSONObject body = JSON.parseObject(responseBody.toString());
        assertEquals(20002, body.getInteger("code"));
        assertEquals("认证失败或登录已失效", body.getString("message"));
        assertEquals("/server/v1/protected", body.getString("path"));
        assertNotNull(body.getLong("timestamp"));
    }

    private HttpServletRequest request(String path, String method) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(path);
        when(request.getMethod()).thenReturn(method);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        return request;
    }
}