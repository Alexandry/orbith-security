package br.com.orbithr.security.oribthr.security.domain;


import lombok.Data;

@Data
public class Logout {


    private String refreshToken;
    private String clientId;
    private String clientSecret;
}
