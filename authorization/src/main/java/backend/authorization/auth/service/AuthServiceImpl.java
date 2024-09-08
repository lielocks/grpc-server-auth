package backend.authorization.auth.service;

import backend.authorization.auth.dto.AuthTokens;
import backend.authorization.auth.dto.LoginRequest;
import backend.authorization.auth.token.AccessToken;
import backend.authorization.auth.token.RefreshToken;
import backend.authorization.common.exception.RefreshTokenException;
import backend.authorization.user.model.User;
import backend.authorization.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.NoSuchElementException;

import static backend.authorization.auth.constant.Constant.*;


@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final TokenService tokenService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public AuthTokens login(LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new NoSuchElementException(WRONG_USERNAME));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new BadCredentialsException(WRONG_PASSWORD);
        }

        tokenService.setAuthentication(user.getId(), user.getUsername());

        // access refresh token 생성
        AccessToken accessToken = tokenService.generateAccessToken(user.getId(), user.getUsername());
        RefreshToken refreshToken = tokenService.generateRefreshToken(user.getId(), user.getUsername());

        return new AuthTokens(refreshToken.getToken(), accessToken.getToken(), user.getUsername());
    }

    @Override
    @Transactional(readOnly = true)
    public String reissueToken(String refreshToken) {
        return tokenService.refreshAccessToken(refreshToken).getToken();
    }

    @Override
    @Transactional
    public void logOut(String refreshToken) {
        if(!StringUtils.hasText(refreshToken)) {
            throw new RefreshTokenException(NO_REFRESH_TOKEN);
        }

        tokenService.deleteRefreshToken(refreshToken);
    }
}
