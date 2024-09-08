package backend.authorization.auth.filter;

import backend.authorization.auth.constant.Constant;
import backend.authorization.auth.model.CustomOAuth2AuthenticatedPrincipal;
import backend.authorization.auth.model.UserCustom;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

@Component
@Slf4j
@RequiredArgsConstructor
public class CustomTokenIntrospector implements OpaqueTokenIntrospector {

    @Value("${secret}")
    private String secret;
    private Key key;

    @PostConstruct
    public void init() {
        this.key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Claims 에서 id 추출
            Long id = claims.get("aud", Long.class); // User Id 는 aud 클레임에 있음
            log.info("custom token Introspector userId :: {}", id);

            if (id == null) {
                throw new OAuth2AuthenticationException(new OAuth2Error("Invalid Token", Constant.INVALID_ACCESS_TOKEN, null));
            }

            String issuer = claims.get("iss", String.class);
            Date expiration = claims.getExpiration();

            // 발행자와 만료시간 추가적으로 검증
            if (issuer == null || expiration.before(Date.from(Instant.now()))) {
                throw new OAuth2AuthenticationException(new OAuth2Error("Invalid Token", Constant.INVALID_ACCESS_TOKEN, null));
            }

            // UserCustom 객체 생성
            UserCustom userCustom = new UserCustom(id, claims.get("username", String.class));

            // 반환할 OAuth2AuthenticatedPrincipal 객체 생성
            return new CustomOAuth2AuthenticatedPrincipal(userCustom, Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

        } catch (Exception e) {
            // JWT가 유효하지 않을 경우 OAuth2AuthenticationException 발생
            throw new OAuth2AuthenticationException(new OAuth2Error("Invalid Token", Constant.INVALID_ACCESS_TOKEN, null));
        }
    }
}
