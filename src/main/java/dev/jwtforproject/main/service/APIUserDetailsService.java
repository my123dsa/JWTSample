package dev.jwtforproject.main.service;


import dev.jwtforproject.main.domain.APIUser;
import dev.jwtforproject.main.dto.CustomUserDetail;
import dev.jwtforproject.main.repository.APIUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@Log4j2
@RequiredArgsConstructor
public class APIUserDetailsService implements UserDetailsService {

    //주입
    private final APIUserRepository apiUserRepository;


    @Override
    public CustomUserDetail loadUserByUsername(String username) throws UsernameNotFoundException {

        APIUser apiUser = apiUserRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Cannot find email"));

        log.info("APIUserDetailsService apiUser-------------------------------------");


        List<SimpleGrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority("ROLE_USER"));

        CustomUserDetail customUserDetail = CustomUserDetail.
                of(apiUser.getId(), apiUser.getEmail(), apiUser.getPassword(), roles);
        log.info(String.valueOf(customUserDetail));
        return customUserDetail;
    }

    public APIUser findByEmail(String email) {
        return apiUserRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Cannot find email"));
    }
}
