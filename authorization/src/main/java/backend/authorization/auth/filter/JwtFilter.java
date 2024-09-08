package backend.authorization.auth.filter;

import backend.authorization.auth.service.TokenService;
import backend.authorization.auth.token.AccessToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Session 은 stateless 상태로 관리되기 때문에 oncePerRequest 즉 해당 한번의 요청이 끝나면 소멸된다.
@Slf4j
@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    private final TokenService tokenService;

    /**
     *
     * @throws ExpiredJwtException Access Token 유효시간 만료 시
     * @throws JwtException MalformedJwtException 등 유효하지 않은 JWT가 들어왔을 떄
     * @throws NumberFormatException Jwt Claim 내부 정보 형변환 과정에서 발생 가능
     *
     */
    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("*** JWT FILTER: REQUEST URL :: {}", request.getRequestURL());

        // 헤더에서 Access Token 추출
        String token = resolveToken(request);

        if (token != null) {
            AccessToken accessToken = tokenService.convertAccessToken(token);

            // Session 에 사용자 등록해주면 사용자 정보를 요청하는 경로의 요청을 정상적으로 진행 가능함
            setAuthenticationFromClaims(accessToken.getData());
        }
        // access Token 이 null 이면 다음 필터로 넘긴다
        // 해당 method 가 종료되기 전에 doFilter 를 호출해서 filterChain 에 엮인 해당 request 와 response 를
        // 해당 filter 에서는 종료해주고 다음 filter 에 넘겨준다.
        filterChain.doFilter(request, response);
    }

    /**
     * header 에서 token 추출
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length()).trim();
        }

        return null;
    }

    private void setAuthenticationFromClaims(Claims claims) {
        Long userId = Long.valueOf(String.valueOf(claims.get("aud")));
        String username = claims.getSubject();

        tokenService.setAuthentication(userId, username);
    }
}
