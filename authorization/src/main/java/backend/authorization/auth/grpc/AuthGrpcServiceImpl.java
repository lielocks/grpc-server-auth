package backend.authorization.auth.grpc;

import auth.Auth;
import auth.AuthServiceGrpc;
import backend.authorization.auth.service.TokenServiceImpl;
import io.grpc.stub.StreamObserver;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
@Slf4j
@RequiredArgsConstructor
public class AuthGrpcServiceImpl extends AuthServiceGrpc.AuthServiceImplBase {
    private final TokenServiceImpl tokenService;

    @Override
    public void verifyToken(Auth.TokenRequest request, StreamObserver<Auth.TokenResponse> responseObserver) {
        String token = request.getToken();
        boolean isValid = tokenService.validateToken(token);

        Long userId = null;
        try {
            // JWT 토큰 디코딩
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(tokenService.getKey()) // 서명 키 설정
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            userId = Long.parseLong(claims.get("aud").toString());
            log.info("auth server userID :: {}", userId);
        } catch (JwtException | IllegalArgumentException e) {
            // JWT 디코딩 오류 처리
            log.error("JWT decoding error :: {}", e.getMessage());
            throw e; // 적절한 예외 처리를 통해 클라이언트에 오류를 반환
        }

        Auth.TokenResponse response = Auth.TokenResponse.newBuilder()
                .setIsValid(isValid)
                .setUserId(userId != null ? userId : -1L)
                .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }
}

