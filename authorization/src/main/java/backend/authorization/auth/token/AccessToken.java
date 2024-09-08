package backend.authorization.auth.token;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import lombok.ToString;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Getter
@ToString
public class AccessToken {

    public static final int EXPIRED_AFTER = 15; // 15분

    // 암호화된 token
    private final String token;

    // key
    private final Key key;

    // 만료 일자
    private LocalDateTime expiredAt;

    // AccessToken 생성자 (발급 시)
    // User가 아니라 UserPrincipal로 만들도록 수정
    public AccessToken(Long id, String username, Key key) {
        LocalDateTime expiredAt = LocalDateTime.now().plusMinutes(EXPIRED_AFTER);
        Date expiredDate = Date.from(expiredAt.atZone(ZoneId.systemDefault()).toInstant());

        // claims 만들기
        Map<String, Object> claims = new HashMap<>();

        claims.put("iss", "skeleton"); // 발행인
        claims.put("aud", id); // 토큰 대상자(User PK)
        claims.put("exp", LocalDateTime.now().toString()); // 발행 시간

        this.key = key;
        this.expiredAt = expiredAt;
        this.token = createJwtAuthToken(username, claims, expiredDate);
    }

    public String createJwtAuthToken(String username, Map<String, Object> claimMap, Date expiredDate) {
        return Jwts.builder()
                .setSubject(username)
                .addClaims(claimMap)
                .signWith(key, SignatureAlgorithm.HS256)
                .setExpiration(expiredDate)
                .compact();
    }

    public AccessToken(String token, Key key) {
        this.token = token;
        this.key = key;
    }

    public Claims getData() {
        return Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}