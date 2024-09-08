package backend.authorization.auth.service;


import backend.authorization.auth.dto.AuthTokens;
import backend.authorization.auth.dto.LoginRequest;

public interface AuthService {
    AuthTokens login(LoginRequest loginRequest);
    String reissueToken(String refreshToken);
    void logOut(String refreshToken);
}
