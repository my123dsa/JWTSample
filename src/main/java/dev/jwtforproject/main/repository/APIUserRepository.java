package dev.jwtforproject.main.repository;

import dev.jwtforproject.main.domain.APIUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import javax.swing.text.html.Option;
import java.util.Optional;

@Repository
public interface APIUserRepository extends JpaRepository<APIUser, Long> {
    Optional<APIUser> findByEmail(String email);
}
