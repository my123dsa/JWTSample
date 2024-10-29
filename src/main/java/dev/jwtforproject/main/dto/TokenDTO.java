package dev.jwtforproject.main.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenDTO {
    @NotNull
    private String GrantType;

    @NotNull
    private String accessToken;

    public static TokenDTO fromString(String accessToken) {
        return TokenDTO.builder()
                .GrantType("Bearer")
                .accessToken(accessToken)
                .build();
    }
}
