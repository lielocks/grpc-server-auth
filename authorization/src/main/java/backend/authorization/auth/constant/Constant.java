package backend.authorization.auth.constant;

public class Constant {
    public static final String WRONG_USERNAME = "아이디를 확인해주세요";
    public static final String WRONG_PASSWORD = "비밀번호를 확인해주세요";
    public static final String NO_REFRESH_TOKEN = "리프레쉬 토큰이 포함되지 않았습니다";
    public static final String REFRESH_TOKEN_NOT_FOUND = "저장된 리프레쉬 토큰이 없습니다";
    public static final String ACCESS_TOKEN_EXPIRED = "액세스 토큰이 만료되었습니다. 재발급해주세요";
    public static final String INVALID_ACCESS_TOKEN = "유효하지 않은 액세스 토큰입니다. 다시 로그인해주세요.";
    public static final String UNEXPECTED_ERROR_OCCUR = "예기치 못한 오류가 발생했습니다. 잠시 뒤 다시 시도해주세요";
    public static final String PLEASE_LOGIN = "로그인이 필요한 엔드포인트입니다.";
    public static final String REFRESH_TOKEN_EXPIRED = "리프레쉬 토큰이 만료되었습니다. 다시 로그인해주세요.";
    public static final String AUTHORIZATION_HEADER_INVALID = "Authorization header 의 정보가 누락되었거나 유효하지 않습니다.";
}
