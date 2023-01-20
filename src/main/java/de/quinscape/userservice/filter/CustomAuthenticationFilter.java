package de.quinscape.userservice.filter;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final int TEN_MINUTES = 10 * 60 * 1000;
    private final int THIRTY_MINUTES = 30 * 60 * 1000;

    /**
     * nur für dieses Beispiel ist es so simple, eigentlich eine sichere Zeichenkombinatio !NICHT im quell text System.Env
     */
    private final String SECRET = "secret";

    /**
     * gets user credentials to pass on to the attemptAuthentication method
     * @param authenticationManager
     */
    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    /**
     * authenticates user: "login is successful" : "username or password not found"
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is: " + username);
        log.info("Password is: " + password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    /**
     * creates and sends access token and the refresh token to the user after successful authentication
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        User user = (User) authentication.getPrincipal();
        List<String> collectedUserAuthorities = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        // 1. customize and create the JWT access token using the HMAC256 Algorithm.
        // 2. saves users roles(authority) inside JWT
        Algorithm algorithm = Algorithm.HMAC256(SECRET.getBytes());
        String access_token = com.auth0.jwt.JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + TEN_MINUTES))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", collectedUserAuthorities)
                .sign(algorithm);



        // 3. creates refresh token with an extended expiration date
        String refresh_token = com.auth0.jwt.JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + THIRTY_MINUTES))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

        // 4. package the token inside a HashMap and ....
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);

        // 4.1 ... parse it into the content inside the JSON Object Response object
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }
}


























