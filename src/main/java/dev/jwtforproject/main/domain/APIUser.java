package dev.jwtforproject.main.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class APIUser {

    @Id
    private String mid;
    private String mpw;
    private String email;

    public void changePw(String mpw){
        this.mpw = mpw;
    }
}