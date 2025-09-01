package br.com.orbithr.security.oribthr.security.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "security.bff.idp")
public class IdpProperties {

    private String baseUrl;      // ex: http://localhost:8080
    private String realm;        // ex: empresa
    private String clientId;     // ex: app-bff
    private String clientSecret; // ex: CHANGE-ME
    private String scope;


    public String tokenUri()  { return baseUrl + "/realms/" + realm + "/protocol/openid-connect/token"; }
    public String logoutUri() { return baseUrl + "/realms/" + realm + "/protocol/openid-connect/logout"; }
    public String jwksUri()   { return baseUrl + "/realms/" + realm + "/protocol/openid-connect/certs"; }
    public String issuerUri() { return baseUrl + "/realms/" + realm; }
}
