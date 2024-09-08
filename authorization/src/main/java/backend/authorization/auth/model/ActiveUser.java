package backend.authorization.auth.model;

import backend.authorization.auth.token.RefreshToken;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.time.LocalDateTime;

/**
 * Refresh token 확인 용 Redis 저장 entity
 */
@Getter
@RedisHash(value = "activeUser", timeToLive = 14400) // 4시간 TTL
@ToString
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ActiveUser {
    @Id
    private String refreshToken;

    private LocalDateTime expiredAt;

    private Long id; // user pk

    private String username;

    private LocalDateTime createdAt;

    public ActiveUser(Long id, String username, RefreshToken refreshToken) {
        this.id = id;
        this.username = username;

        this.refreshToken = refreshToken.getToken();
        this.expiredAt = refreshToken.getExpiredAt();

        this.createdAt = LocalDateTime.now();
    }
}
