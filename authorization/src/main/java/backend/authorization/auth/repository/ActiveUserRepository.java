package backend.authorization.auth.repository;

import backend.authorization.auth.model.ActiveUser;
import org.springframework.data.repository.Repository;

import java.util.Optional;

public interface ActiveUserRepository extends Repository<ActiveUser, String> {
    ActiveUser save(ActiveUser activeUser);
    Optional<ActiveUser> findById(String refreshToken);
    void deleteById(String refreshToken);
}