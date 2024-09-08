package backend.authorization.auth.controller;

import backend.authorization.auth.dto.AuthTokens;
import backend.authorization.auth.dto.LoginRequest;
import backend.authorization.auth.dto.LoginResponse;
import backend.authorization.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private static final String REFRESH_TOKEN_COOKIE_NAME = "REFRESH_TOKEN";

    /**
     * Login API
     * @return Access Token(15분 후 만료), Refresh token(3시간 후 만료)
     */
    @PostMapping("/api/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        AuthTokens authTokens = authService.login(loginRequest);

        // 쿠키에 Refresh token 담기
        ResponseCookie refreshTokenCookie = getCookie(authTokens.getRefreshToken(), 4 * 60 * 60);

        // HTTP 응답 헤더에 쿠키 추가
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.ok().headers(headers).body(authTokens.getLoginResponse());
    }

    /**
     * Access Token 재발급 Reissue API
     * @param refreshToken
     * @return 새로운 Access Token
     */
    @PostMapping("/api/token/reissue")
    public ResponseEntity<String> reissueToken(@CookieValue(name = REFRESH_TOKEN_COOKIE_NAME) String refreshToken) {
        log.info("/api/token/reissue");
        return ResponseEntity.ok().body(authService.reissueToken(refreshToken));
    }

    /**
     * 로그아웃
     * Redis/쿠키에서 Refresh Token 삭제
     *
     * @param refreshToken
     * @return
     */
    @PostMapping("/api/logout")
    public ResponseEntity<Void> logOut(@CookieValue(name = REFRESH_TOKEN_COOKIE_NAME) String refreshToken) {
        // Redis에서 REFRESH_TOKEN 삭제
        authService.logOut(refreshToken);

        // 쿠키에서 REFRESH_TOKEN 삭제
        ResponseCookie refreshTokenCookie = getCookie("", 0);

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.noContent().headers(headers).build();
    }

    /**
     * 쿠키 생성 메소드
     *
     * @param value  RefreshToken
     * @param maxAge 유효 시간
     * @return 쿠키 객체
     */
    private ResponseCookie getCookie(String value, long maxAge) {
        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, value)
                .httpOnly(true)  // JavaScript에서 쿠키에 접근하지 못하게 설정
                .path("/")       // 쿠키의 경로 설정
                .secure(false) // HTTP 요청 허락
                .maxAge(maxAge) // 유효시간
                .sameSite("Strict") // SameSite 설정
                .build();
    }


}
