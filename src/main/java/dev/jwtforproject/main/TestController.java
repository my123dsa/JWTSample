package dev.jwtforproject.main;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    @GetMapping("/generate")
    public String generateToken() {

        return "Hello World";
    }
    @GetMapping("/refresh")
    public String refreshToken() {
        return "Hello World";
    }
    @GetMapping("/getData")
    public String getData() {
        return "Hello World";
    }
}
