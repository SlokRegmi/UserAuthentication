package authentication.RESTAuthentication.config;

import authentication.RESTAuthentication.Exception.CustomAccessDeniedHandler;
import authentication.RESTAuthentication.Exception.CustomAuthenticationEntryPoint;
import authentication.RESTAuthentication.filter.JWTFilter;
//import authentication.RESTAuthentication.filter.RateLimitingFilter;
import authentication.RESTAuthentication.util.EncryptDecrypt;
import authentication.RESTAuthentication.util.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.security.interfaces.RSAPublicKey;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private CustomAccessDeniedHandler accessDeniedHandler;

    @Autowired
    private CustomAuthenticationEntryPoint authenticationEntryPoint;



    @Value("classpath:app.pub")
    private RSAPublicKey publicKey;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JWTFilter jwtFilter) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/dataSecurity/**").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
//                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.publicKey).build();
    }

    @Bean
    public EncryptDecrypt encryptDecrypt() {
        return new EncryptDecrypt();
    }

    @Bean
    public TokenService tokenService(JwtDecoder jwtDecoder,EncryptDecrypt encryptDecrypt) {
        return new TokenService(jwtDecoder,encryptDecrypt);
    }

    @Bean
    public JWTFilter jwtFilter(TokenService tokenService, EncryptDecrypt encryptDecrypt) {
        return new JWTFilter(tokenService, encryptDecrypt);
    }
//    @Bean
//    RateLimitingFilter rateLimitingFilter() {
//        return new RateLimitingFilter();
//    }
}