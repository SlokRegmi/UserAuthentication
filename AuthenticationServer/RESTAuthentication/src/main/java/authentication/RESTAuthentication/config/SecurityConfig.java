package authentication.RESTAuthentication.config;

import authentication.RESTAuthentication.Exception.CustomAccessDeniedHandler;
import authentication.RESTAuthentication.Exception.CustomAuthenticationEntryPoint;
import authentication.RESTAuthentication.filter.JWTFilter;
import authentication.RESTAuthentication.services.CustomUserDetailsService;
import authentication.RESTAuthentication.util.EncryptDecrypt;
import authentication.RESTAuthentication.util.TokenService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Autowired
    private CustomAccessDeniedHandler accessDeniedHandler;

    @Autowired
    private CustomAuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    // These fields are not actually used in this version of the code, so we can ignore them for now.
    @Value("abcdefg1234567890")
    private String publicKeyPath;

    @Value("abcdefg1234567890")
    private String privateKeyPath;

    @Bean
    public SecurityFilterChain securityFilterChain(TokenService tokenService, EncryptDecrypt encryptDecrypt, HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/authorization/connect","/authorization/renewToken").permitAll()

                        .anyRequest().authenticated()
                )
                .addFilterBefore(new JWTFilter(tokenService, encryptDecrypt), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        authoritiesConverter.setAuthoritiesClaimName("roles");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }

    @Bean
    public KeyPair keyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Save the public key to a file
            String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                    Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()) +
                    "\n-----END PUBLIC KEY-----\n";
            try (FileWriter fileWriter = new FileWriter("src/main/resources/app.pub")) {
                fileWriter.write(publicKeyPEM);
            } catch (IOException e) {
                System.err.println("Failed to write public key to file: " + e.getMessage());
            }

            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not available", e);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        try {
            return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair().getPublic()).build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create JWT decoder", e);
        }
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        try {
            JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair().getPublic())
                    .privateKey((RSAPrivateKey) keyPair().getPrivate())
                    .build();
            JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
            return new NimbusJwtEncoder(jwks);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create JWT encoder", e);
        }
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public EncryptDecrypt encryptDecrypt() {
        return new EncryptDecrypt();
    }
}