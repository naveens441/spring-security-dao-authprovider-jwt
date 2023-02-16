package springsecuritydaoauthproviderjwt.springsecuritydaoauthproviderjwt.configuration;


import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class LoginFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    private final JwtHelper jwtHelper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var username = request.getHeader("userName");
        var password = request.getHeader("password");

        var authenticated = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                username, password
        ));
        response.setHeader(HttpHeaders.AUTHORIZATION, createToken(authenticated));
    }
    private String createToken(Authentication authenticated) {
        var user = (User) authenticated.getPrincipal();
        var roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return jwtHelper.createToken(user.getUsername(), Map.of("roles", roles));

    }
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        var method = request.getMethod();
        var uri = request.getRequestURI();
        var isLogin = HttpMethod.POST.matches(method) && uri.startsWith("/login");
        return !isLogin;
    }
}
