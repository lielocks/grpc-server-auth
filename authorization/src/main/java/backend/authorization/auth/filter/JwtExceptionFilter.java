package backend.authorization.auth.filter;

import backend.authorization.common.dto.ErrorResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static backend.authorization.auth.constant.Constant.*;

/**
 * JwtFilter에서 발생하는 예외처리용 필터
 */
@Component
@Slf4j
public class JwtExceptionFilter extends OncePerRequestFilter {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // JWT 필터에서 발생한 예외처리
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            // Access Token 만료
            setErrorResponse(response, ACCESS_TOKEN_EXPIRED);
        } catch (JwtException | NumberFormatException e) {
            // 유효하지 않은 JWT 토큰 도착
            setErrorResponse(response, INVALID_ACCESS_TOKEN);
        } catch (Exception e) {
            e.printStackTrace();
            setErrorResponse(response, UNEXPECTED_ERROR_OCCUR);
        }
    }

    /**
     * 예외 발생 시 응답 객체를 만드는 메소드
     * 401 UNAUTHORIZED
     */
    public void setErrorResponse(HttpServletResponse response, String message) throws IOException {
        ErrorResponseDto errorResponse = new ErrorResponseDto(message, HttpStatus.UNAUTHORIZED);

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json; charset=UTF-8");

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
