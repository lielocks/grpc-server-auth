package backend.authorization.auth.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import java.util.Collection;
import java.util.Map;

public class CustomOAuth2AuthenticatedPrincipal implements OAuth2AuthenticatedPrincipal {
    private final UserCustom userCustom;
    private final Collection<GrantedAuthority> authorities;

    public CustomOAuth2AuthenticatedPrincipal(UserCustom userCustom, Collection<GrantedAuthority> authorities) {
        this.userCustom = userCustom;
        this.authorities = authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of("user", userCustom);
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return userCustom.getUsername();
    }
}
