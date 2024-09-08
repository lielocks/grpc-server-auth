package backend.authorization.common.aop;

import backend.authorization.common.dto.ErrorResponseDto;
import backend.authorization.common.exception.GeneralException;
import backend.authorization.common.exception.RefreshTokenException;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.HibernateException;
import org.hibernate.TypeMismatchException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.NoSuchElementException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String DEFAULT_ERROR_MSG = "알 수 없는 에러가 발생했습니다. 운영자에게 문의 바랍니다.";

    @ExceptionHandler({IllegalStateException.class, IllegalArgumentException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponseDto handleIllegalStateException(RuntimeException e){
        return new ErrorResponseDto(e.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler({TypeMismatchException.class, HttpMessageNotReadableException.class})
    public ErrorResponseDto handleTypeException(HibernateException e){
        return new ErrorResponseDto(e.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(GeneralException.class)
    public ResponseEntity<ErrorResponseDto> handleGeneralException(GeneralException e) {
        ErrorResponseDto errorResponse = e.toErrorResponseDto();
        return new ResponseEntity<>(errorResponse, e.getStatus());
    }

    @ExceptionHandler(RefreshTokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponseDto handleRefreshTokenException(RefreshTokenException e) {
        return new ErrorResponseDto(e.getMessage(), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponseDto handleUsernameNotFoundException(UsernameNotFoundException e) {
        return new ErrorResponseDto(e.getMessage(), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(BadCredentialsException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponseDto handleBadCredentialsException(BadCredentialsException e) {
        return new ErrorResponseDto(e.getMessage(), HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponseDto handleNoSuchElementException(NoSuchElementException e) {
        return new ErrorResponseDto(e.getMessage(), HttpStatus.NOT_FOUND);
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(Exception.class)
    public ErrorResponseDto handleException(Exception e) {
        log.error(e.getMessage(), e);
        return new ErrorResponseDto(DEFAULT_ERROR_MSG, HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
