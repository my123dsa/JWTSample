package dev.jwtforproject.main.filter;

import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;

@Slf4j
public class APILoginFilter extends AbstractAuthenticationProcessingFilter {

    //AbstractAuthenticationProcessingFilter에게 url 설정
    //위 클래스는 인증 관련 요청을 처리하는 역할
    public APILoginFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    //인증 시도할때 하는 메소드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        log.info("APILoginFilter-----------------------------------");

        if (request.getMethod().equalsIgnoreCase("GET")) {
            log.info("GET METHOD NOT SUPPORT");
            return null;
        }
        log.info("-----------------------------------------");
        log.info(request.getMethod());

        Map<String, String> jsonData = parseRequestJSON(request);

        log.info("jsonData: " + jsonData);

        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(
                jsonData.get("email"),
                jsonData.get("password"));

        return getAuthenticationManager().authenticate(authenticationToken);
    }


    private Map<String, String> parseRequestJSON(HttpServletRequest request) {

        //JSON 데이터를 분석해서 mid, mpw 전달 값을 Map으로 처리
        try (Reader reader = new InputStreamReader(request.getInputStream())) {

            Gson gson = new Gson();

            return gson.fromJson(reader, Map.class);

        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return null;
    }
}
