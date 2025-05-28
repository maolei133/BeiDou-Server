package org.gms.util;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.exceptions.ValidateException;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTPayload;
import cn.hutool.jwt.JWTUtil;
import cn.hutool.jwt.JWTValidator;
import cn.hutool.jwt.signers.JWTSigner;
import cn.hutool.jwt.signers.JWTSignerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.duration}")
    private int jwtDuration;

    public String generateJwtToken(String username) {
        JWTPayload jwtPayload = new JWTPayload()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiresAt(new Date((new Date()).getTime() + jwtDuration));

        return JWTUtil.createToken(jwtPayload.getClaimsJson(), generalKey());
    }

    public String getUserNameFromJwtToken(String token) {
        return JWT.of(token).setSigner(generalKey()).getPayloads().getStr(JWTPayload.SUBJECT);
    }

    public boolean validateJwtToken(String authToken) {
        try {
            JWTValidator.of(authToken).validateAlgorithm(generalKey()).validateDate(DateUtil.date());
            return true;
        } catch (ValidateException e) {
            logger.error("访问者的Token无效: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("访问者的Token参数为空: {}", e.getMessage());
        }

        return false;
    }

    private JWTSigner generalKey() {
        return JWTSignerUtil.hs512(jwtSecret.getBytes());
    }
}
