package org.gms.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.duration}")
    private int jwtDuration;

    private SecretKey key;

    @PostConstruct
    public void init() {
        // 注解：在Bean初始化后，根据jwtSecret字符串生成一个用于HMAC-SHA算法的SecretKey实例。
        // 这是jjwt 0.12.x版本推荐的安全做法。
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 生成JWT Token。
     * @param username 用户名
     * @return 返回生成的Token字符串
     */
    public String generateJwtToken(String username) {
        // 注解：使用新的jjwt API构建token。
        // 方法链中的 subject, issuedAt, expiration 是旧版 setSubject, setIssuedAt, setExpiration 的替代。
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtDuration))
                .signWith(key) // 注解：使用生成的SecretKey进行签名，算法会根据Key的类型自动推断。
                .compact();
    }

    /**
     * 从JWT Token中获取用户名。
     * @param token Token字符串
     * @return 返回用户名
     */
    public String getUserNameFromJwtToken(String token) {
        // 注解：使用新的jjwt API解析token。
        // 必须先使用 verifyWith(key) 指定密钥，然后 build() 构建解析器，最后解析。
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    /**
     * 验证JWT Token的有效性。
     * @param authToken Token字符串
     * @return 如果有效返回true，否则返回false
     */
    public boolean validateJwtToken(String authToken) {
        try {
            // 注解：使用新的jjwt API解析并验证token。
            // 如果签名无效、token格式错误或已过期，此方法会抛出相应的异常。
            Jwts.parser().verifyWith(key).build().parseSignedClaims(authToken);
            return true;
        } catch (SignatureException e) {
            // 注解：SignatureException的包路径已更新为 io.jsonwebtoken.security.SignatureException
            logger.error("访问者的Token签名无效: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("访问者的Token无效: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("访问者的Token已过期: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("访问者的Token不被支持: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("访问者的Token参数为空: {}", e.getMessage());
        }

        return false;
    }
}
