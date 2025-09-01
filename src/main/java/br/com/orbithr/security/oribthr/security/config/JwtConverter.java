package br.com.orbithr.security.oribthr.security.config;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.*;
import java.util.stream.Collectors;

public class JwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    @SuppressWarnings("unchecked")
    private static Collection<String> extractRoles(Jwt jwt) {
        Set<String> roles = new HashSet<>();

        // realm_access.roles
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null) {
            Object rr = realmAccess.getOrDefault("roles", Collections.emptyList());
            if (rr instanceof Collection<?> c) c.forEach(r -> roles.add(String.valueOf(r)));
        }

        // resource_access.{client}.roles
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            resourceAccess.values().forEach(v -> {
                if (v instanceof Map<?, ?> m) {
                    Object rs = m.get("roles");
                    if (rs instanceof Collection<?> c2) c2.forEach(r -> roles.add(String.valueOf(r)));
                }
            });
        }

        return roles;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<String> roles = extractRoles(jwt);
        Collection<GrantedAuthority> authorities = roles.stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .collect(Collectors.toSet());

        var delegate = new JwtAuthenticationConverter();
        delegate.setJwtGrantedAuthoritiesConverter(t -> authorities);
        return delegate.convert(jwt);
    }
}
