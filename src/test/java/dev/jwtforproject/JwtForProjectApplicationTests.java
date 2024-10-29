package dev.jwtforproject;

import dev.jwtforproject.main.domain.APIUser;
import dev.jwtforproject.main.repository.APIUserRepository;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.Commit;

@SpringBootTest
@Transactional // 트랜잭션이 테스트 내에서 적용됨
@Commit // 테스트 완료 후 롤백하지 않고 커밋함
class JwtForProjectApplicationTests {

    @Autowired
    private APIUserRepository apiUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Test
    @Transactional // 트랜잭션이 테스트 내에서 적용됨
    @Commit
    void contextLoads() {
        for (int i=0;i<10;i++){
            APIUser apiUser = APIUser.builder()
                    .mid(String.valueOf(i))
                    .email("test@email.com")
                    .mpw(passwordEncoder.encode("1111"))
                    .build();
            apiUserRepository.save(apiUser);
        }

    }

}
