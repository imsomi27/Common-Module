package com.module.common.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {

    private final SecretKey secretKey;

    private final long accessTokenExpireTimeMillis;
    private final long refreshTokenExpireTimeMillis;

    public JwtTokenProvider(@Value("${}") String secretKey,
                            @Value("${}") long accessTokenExpireTimeMin) {
        this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpireTimeMillis = Duration.ofMinutes(accessTokenExpireTimeMin).toMillis();
        this.refreshTokenExpireTimeMillis = Duration.ofMinutes(accessTokenExpireTimeMin).toMillis();
    }

    public String createAccessToken(String userPk, List<String> roles) {
        Date now = new Date();
        Date expiresAt = new Date(now.getTime() + accessTokenExpireTimeMillis);

        return Jwts.builder()
                .subject(userPk)
                .claim("isAdmin", false)
                .issuedAt(now)
                .expiration(expiresAt)
                .subject(String.valueOf(secretKey))
                .compact();
    }

    // 토큰으로부터 클레임 추출
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // JWT 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // Log 예외 처리 (만료, 위변조 등)
            return false;
        }
    }
}
