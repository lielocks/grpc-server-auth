package backend.authorization.common.exception;

import backend.authorization.common.dto.ErrorResponseDto;
import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
@Builder
public class GeneralException extends RuntimeException {
    private final String message;
    private final HttpStatus status;

    public GeneralException(String message, HttpStatus status) {
        super(message);
        this.message = message;
        this.status = status;
    }

    public ErrorResponseDto toErrorResponseDto() {
        return new ErrorResponseDto(this.message, this.status);
    }
}