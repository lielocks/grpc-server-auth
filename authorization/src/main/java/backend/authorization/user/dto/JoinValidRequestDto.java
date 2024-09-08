package backend.authorization.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class JoinValidRequestDto {

    @NotBlank(message = "Username cannot be blank")
    @Size(min = 4, max = 15, message = "사용자명은 4자 이상 15자 이하로 등록 가능합니다.")
    private String username;

    @NotBlank(message = "Password cannot be blank")
    @Size(max = 15, message = "비밀번호는 15자 이하로 등록 가능합니다.")
    @Pattern(
            regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{1,}$",
            message = "비밀번호는 문자, 숫자, 특수문자 각 하나씩 포함되어야 합니다."
    )
    private String password;
}
