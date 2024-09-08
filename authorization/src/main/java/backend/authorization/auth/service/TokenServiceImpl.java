package backend.authorization.auth.service;

import backend.authorization.auth.model.ActiveUser;
import backend.authorization.auth.model.UserCustom;
import backend.authorization.auth.repository.ActiveUserRepository;
import backend.authorization.auth.token.AccessToken;
import backend.authorization.auth.token.RefreshToken;
import backend.authorization.common.exception.RefreshTokenException;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SignatureException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Date;
import java.util.NoSuchElementException;

import static backend.authorization.auth.constant.Constant.REFRESH_TOKEN_EXPIRED;
import static backend.authorization.auth.constant.Constant.REFRESH_TOKEN_NOT_FOUND;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final ActiveUserRepository activeUserRepository;

    @Value("${secret}")
    private String secret;
    private Key key;

    @PostConstruct
    public void init() {
        this.key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    @Override
    public AccessToken convertAccessToken(String token) {
        return new AccessToken(token, key);
    }

    @Override
    public void setAuthentication(Long userId, String username) {
        UserCustom userCustom = new UserCustom(userId, username);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userCustom, null, Collections.singleton(new SimpleGrantedAuthority("USER")));
        SecurityContextHolder.getContext().setAuthentication(token);
    }

    @Override
    public AccessToken generateAccessToken(Long userId, String username) {
        return new AccessToken(userId, username, key);
    }

    @Override
    public RefreshToken generateRefreshToken(Long userId, String username) {
        RefreshToken refreshToken = new RefreshToken();

        // Refresh token Redis 에 저장
        ActiveUser activeUser = new ActiveUser(userId, username, refreshToken);
        activeUserRepository.save(activeUser);

        return refreshToken;
    }

    public AccessToken refreshAccessToken(String refreshToken) {
        ActiveUser activeUser = activeUserRepository.findById(refreshToken)
                .orElseThrow(() -> new NoSuchElementException(REFRESH_TOKEN_NOT_FOUND));

        if (activeUser.getExpiredAt().isBefore(LocalDateTime.now())) {
            // refresh token 만료됨을 확인하면
            activeUserRepository.deleteById(refreshToken); // Active User 가 아니므로 ActiveUserRepo Redis 에서 삭제
            throw new RefreshTokenException(REFRESH_TOKEN_EXPIRED);
        }

        // Refresh Token 이 유효할 경우에만 새로운 Access Token 을 발급
        return generateAccessToken(activeUser.getId(), activeUser.getUsername());
    }

    public void deleteRefreshToken(String refreshToken) {
        activeUserRepository.deleteById(refreshToken);
    }

    public boolean validateToken(String token) {
        try {
            // 토큰을 파싱하고 claim 검증
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            log.info("token , claims {} {}" , token, claims);
            // 만료되었는지 확인 후 return
            return !claims.getExpiration().before(Date.from(Instant.now()));
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT token compact of handler are invalid: {}", e.getMessage());
        }

        // 유효하지 않음을 return
        return false;
    }

    public Key getKey() {
        return key;
    }
}