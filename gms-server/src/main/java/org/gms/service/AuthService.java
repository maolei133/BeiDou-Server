package org.gms.service;

import lombok.AllArgsConstructor;
import org.gms.exception.BizException;
import org.gms.util.JwtUtils;
import org.gms.dao.entity.AccountsDO;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

@Service
@AllArgsConstructor
public class AuthService {
    private static final int AUTHENTICATION_ERROR_CODE = 20002;
    private static final String AUTHENTICATION_ERROR_MESSAGE = "账号或密码错误";
    private static final String TOKEN_INVALID_MESSAGE = "认证失败或登录已失效";

    private final AccountService accountService;
    private final JwtUtils jwtUtils;

    public Map<String, String> getToken(String name, String password) {
        AccountsDO account = accountService.findByName(name);
        if (account == null || !accountService.checkPassword(password, account)) {
            throw new BizException(AUTHENTICATION_ERROR_CODE, AUTHENTICATION_ERROR_MESSAGE);
        }

        HashMap<String, String> result = new HashMap<>();
        result.put("token", jwtUtils.generateJwtToken(account.getName()));
        return result;
    }

    public Map<String, String> refreshToken(String token) {
        if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
            token = token.substring(7);
            if (!jwtUtils.validateJwtToken(token)) {
                throw new BizException(AUTHENTICATION_ERROR_CODE, TOKEN_INVALID_MESSAGE);
            }
            String username = jwtUtils.getUserNameFromJwtToken(token);
            AccountsDO account = accountService.findByName(username);
            if (account == null) {
                throw new BizException(AUTHENTICATION_ERROR_CODE, TOKEN_INVALID_MESSAGE);
            }
            HashMap<String, String> result = new HashMap<>();
            result.put("token", jwtUtils.generateJwtToken(account.getName()));
            return result;
        }
        throw new BizException(AUTHENTICATION_ERROR_CODE, TOKEN_INVALID_MESSAGE);
    }
}
