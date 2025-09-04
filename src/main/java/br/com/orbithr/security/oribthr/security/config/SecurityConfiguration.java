package br.com.orbithr.security.oribthr.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;


@AutoConfiguration
@EnableConfigurationProperties({IdpProperties.class, BffProperties.class})
@ConditionalOnProperty(prefix = "security.bff", name = "enabled", havingValue = "true", matchIfMissing = true)
@RequiredArgsConstructor
@ComponentScan("br.com.orbithr.security.oribthr.security")
public class SecurityConfiguration {

    private final IdpProperties props;
    private final BffProperties bff;

    @Bean
    public WebClient keycloakWebClient() {
        return WebClient.builder()
                .exchangeStrategies(ExchangeStrategies.builder()
                        .codecs(c -> c.defaultCodecs().maxInMemorySize(4 * 1024 * 1024))
                        .build())
                .defaultHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(props.issuerUri());

        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(props.issuerUri());
        if (StringUtils.hasText(bff.getAudience())) {
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    withIssuer,
                    new AudienceValidator(bff.getAudience())
            ));
        } else {
            decoder.setJwtValidator(withIssuer);
        }
        return decoder;
    }

    /** Validação automática do JWT via JWKS do IDP */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder decoder, BffProperties bffProperties) throws Exception {
        String[] publicPatterns = Arrays.stream(
                        Optional.ofNullable(bff.getEndpoints()).orElse("").split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toArray(String[]::new);
        return   http
                // Desabilita CSRF (se necessário)
                .csrf(csrf -> csrf.disable())

                // Configura sessões como stateless
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Permissão para os endpoints públicos (login, refresh, logout)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(publicPatterns).permitAll()
                        .anyRequest().authenticated()
                )

                // Configura o Resource Server (JWT)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(decoder)
                                .jwtAuthenticationConverter(new JwtConverter()))
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                )
                .build();
    }
}
