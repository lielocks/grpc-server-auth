package backend.authorization.auth.dto;

import lombok.Getter;
import lombok.ToString;


@Getter
@ToString
public class AuthTokens {
    private String refreshToken;
    private LoginResponse loginResponse;

    public AuthTokens(String refreshToken, String accessToken, String username) {
        this.refreshToken = refreshToken;
        this.loginResponse = new LoginResponse(username, accessToken);
    }
}