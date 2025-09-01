package br.com.orbithr.security.oribthr.security.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "security.bff")
public class BffProperties {

    private String audience;
    private String endpoint;


}
