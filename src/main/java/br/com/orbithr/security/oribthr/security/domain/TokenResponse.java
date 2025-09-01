package br.com.orbithr.security.oribthr.security.domain;


import lombok.Data;

@Data
public class TokenResponse {

    private String access_token;
    private String refresh_token;
    private String token_type;
    private long   expires_in;
    private long   refresh_expires_in;
    private String scope;
    private String session_state;
}
