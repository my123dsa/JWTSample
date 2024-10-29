package dev.jwtforproject.main.repository;

import dev.jwtforproject.main.domain.APIUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface APIUserRepository extends JpaRepository<APIUser, Long> {
    APIUser findByEmail(String email);
}
