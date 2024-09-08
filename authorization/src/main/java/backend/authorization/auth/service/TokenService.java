package backend.authorization.auth.service;


import backend.authorization.auth.token.AccessToken;
import backend.authorization.auth.token.RefreshToken;

public interface TokenService {
    AccessToken convertAccessToken(String token);
    void setAuthentication(Long userId, String username);
    AccessToken generateAccessToken(Long userId, String username);
    RefreshToken generateRefreshToken(Long userId, String username);
    AccessToken refreshAccessToken(String refreshToken);
    void deleteRefreshToken(String refreshToken);
}