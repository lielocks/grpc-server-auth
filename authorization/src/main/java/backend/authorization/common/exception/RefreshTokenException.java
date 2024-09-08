package backend.authorization.common.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class RefreshTokenException extends RuntimeException {
    private String message;
}
