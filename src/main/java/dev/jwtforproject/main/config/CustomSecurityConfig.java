package dev.jwtforproject.main.config;


import dev.jwtforproject.main.filter.APILoginFilter;
import dev.jwtforproject.main.filter.RefreshTokenFilter;
import dev.jwtforproject.main.filter.TokenCheckFilter;
import dev.jwtforproject.main.handler.APILoginSuccessHandler;
import dev.jwtforproject.main.service.APIUserDetailsService;
import dev.jwtforproject.main.util.JWTUtil;
import dev.jwtforproject.main.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


import java.util.Arrays;

@Configuration
@Slf4j
@EnableMethodSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {

    private final JWTUtil jwtUtil;
    //주입
    private final APIUserDetailsService apiUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)throws Exception {

        log.info("-----------------------configuration---------------------");

        //AuthenticationManager설정
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(apiUserDetailsService).passwordEncoder(passwordEncoder());
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
        http.authenticationManager(authenticationManager);


        //APILoginFilter
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);
        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil);
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);


        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))//세션을 생성하거나 유지하지 않음
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .addFilterBefore(
                        apiLoginFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(
                        tokenCheckFilter(jwtUtil, apiUserDetailsService), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(
                        new RefreshTokenFilter("/refreshToken", jwtUtil), TokenCheckFilter.class)

//                .exceptionHandling(ex->ex)
//                .logout(logout->logout)
//                .login(login-> login)
        ;

        return http.build();
    }

//        //APILoginFilter의 위치 조정
//        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);
//        //api로 시작하는 모든 경로는 TokenCheckFilter 동작
//        http.addFilterBefore(tokenCheckFilter(jwtUtil, apiUserDetailsService), UsernamePasswordAuthenticationFilter.class);
//        //refreshToken 호출 처리
//        http.addFilterBefore(new RefreshTokenFilter("/refreshToken", jwtUtil), TokenCheckFilter.class);

    private TokenCheckFilter tokenCheckFilter(JWTUtil jwtUtil, APIUserDetailsService
            apiUserDetailsService){
        return new TokenCheckFilter(apiUserDetailsService, jwtUtil);
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

}
