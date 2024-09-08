package backend.authorization.user.service;

import backend.authorization.user.constant.Constants;
import backend.authorization.user.dto.JoinValidRequestDto;
import backend.authorization.user.model.User;
import backend.authorization.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Transactional
    public void join(JoinValidRequestDto validRequestDto) {
        if (userRepository.existsByUsername(validRequestDto.getUsername())) {
            throw new IllegalStateException(Constants.USERNAME_ALREADY_EXISTS);
        }
        userRepository.save(User.builder().username(validRequestDto.getUsername())
                .password(passwordEncoder.encode(validRequestDto.getPassword()))
                .build());
    }

}
