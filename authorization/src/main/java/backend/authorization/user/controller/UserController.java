package backend.authorization.user.controller;

import backend.authorization.user.dto.JoinValidRequestDto;
import backend.authorization.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserService userService;

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/join")
    public void register(@RequestBody @Valid JoinValidRequestDto validRequestDto){
        userService.join(validRequestDto);
    }

}
