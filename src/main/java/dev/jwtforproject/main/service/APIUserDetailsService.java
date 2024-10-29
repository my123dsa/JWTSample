package dev.jwtforproject.main.service;


import dev.jwtforproject.main.domain.APIUser;

import dev.jwtforproject.main.dto.CustomUserDetail;
import dev.jwtforproject.main.repository.APIUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class APIUserDetailsService implements UserDetailsService {

    //주입
    private final APIUserRepository apiUserRepository;


    @Override
    public CustomUserDetail loadUserByUsername(String username) throws UsernameNotFoundException {

        APIUser apiUser = apiUserRepository.findById(Long.parseLong(username))
                .orElseThrow(() -> new UsernameNotFoundException("Cannot find mid"));

        log.info("APIUserDetailsService apiUser-------------------------------------");

//        APIUserDTO dto =  new APIUserDTO(
//                apiUser.getMid().toString(),
//                apiUser.getMpw(),
//                List.of(new SimpleGrantedAuthority("ROLE_USER")));
//
//        log.info(dto);//APIUserDTO(mid=0, mpw=$2a$10$LtilE758h1P5sBABx483kObrd3MYmhdgVQ5f69nEQ9ZgkOZW78MSG, email=null)

        List<SimpleGrantedAuthority> roles= new ArrayList<>();
        roles.add(new SimpleGrantedAuthority("ROLE_USER"));
        return CustomUserDetail.
                of(apiUser.getMid(), apiUser.getEmail(), apiUser.getMpw(), roles);

//        return dto;
    }
    public APIUser findByEmail(String email) {
        return apiUserRepository.findByEmail(email);
    }
}
