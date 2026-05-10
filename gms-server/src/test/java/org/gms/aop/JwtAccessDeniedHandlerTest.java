package org.gms.aop;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtAccessDeniedHandlerTest {

    @Test
    void handleShouldReturnUnifiedAccessDeniedBody() throws Exception {
        JwtAccessDeniedHandler handler = new JwtAccessDeniedHandler();
        HttpServletRequest request = request("/server/v1/admin", "POST");
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter responseBody = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(responseBody));

        handler.handle(request, response, new AccessDeniedException("权限不足"));

        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        JSONObject body = JSON.parseObject(responseBody.toString());
        assertEquals(30001, body.getInteger("code"));
        assertEquals("权限不足，禁止访问", body.getString("message"));
        assertEquals("/server/v1/admin", body.getString("path"));
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