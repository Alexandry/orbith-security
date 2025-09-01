package br.com.orbithr.security.oribthr.security.controller;


import br.com.orbithr.security.oribthr.security.config.IdpProperties;
import br.com.orbithr.security.oribthr.security.domain.TokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class LoginController {

    private final WebClient webClient;
    private final IdpProperties props;

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<TokenResponse> login(@RequestParam String username, @RequestParam String password) {
        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", props.getClientId());
        form.add("client_secret", props.getClientSecret());
        form.add("username", username);
        form.add("password", password);

        TokenResponse body = webClient.post()
                .uri(props.tokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .block();

        HttpHeaders headers = new HttpHeaders();
        if (body != null && body.getSession_state() != null) {
            headers.add("X-Session-ID", body.getSession_state());
        }
        return new ResponseEntity<>(body, headers, HttpStatus.OK);
    }

    @PostMapping(value =  "/refresh", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<TokenResponse> refresh(@RequestParam String refreshToken) {
        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", props.getClientId());
        form.add("client_secret", props.getClientSecret());
        form.add("refresh_token", refreshToken);

        TokenResponse body = webClient.post()
                .uri(props.tokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .block();

        HttpHeaders headers = new HttpHeaders();
        if (body != null && body.getSession_state() != null) {
            headers.add("X-Session-ID", body.getSession_state());
        }
        return new ResponseEntity<>(body, headers, HttpStatus.OK);
    }

    @PostMapping(value = "/logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> logout(@RequestParam String refreshToken) {
        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add("client_id", props.getClientId());
        form.add("client_secret", props.getClientSecret());
        form.add("refresh_token", refreshToken);

        webClient.post()
                .uri(props.logoutUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .retrieve()
                .toBodilessEntity()
                .block();

        return ResponseEntity.ok().build();
    }
}
