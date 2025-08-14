package authentication.RESTAuthentication.util;

import authentication.RESTAuthentication.entities.Role;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
public class TokenService {


    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private EncryptDecrypt encryptDecrypt;

    public TokenService(JwtDecoder jwtDecoder, EncryptDecrypt encryptDecrypt) {
        this.jwtDecoder = jwtDecoder;
        this.encryptDecrypt = encryptDecrypt;
    }

    public Jwt getAccessToken(String token) {
        try {
            return jwtDecoder.decode(token);
        } catch (Exception e) {
            log.error("Failed to decode access token", e);
            throw new RuntimeException("Invalid token format");
        }
    }

    public boolean isTokenValid(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            Instant now = Instant.now();
            return jwt.getExpiresAt() != null && jwt.getExpiresAt().isAfter(now);
        } catch (JwtException e) {
            log.error("Invalid JWT token", e);
            return false;
        }
    }

    public String extractUsernameFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getSubject();
        } catch (JwtException e) {
            log.error("Failed to extract username from token", e);
            return null;
        }
    }

    public List<String> extractRolesFromToken(String token) { // Changed return type to List<String>
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaimAsStringList("roles");
        } catch (JwtException e) {
            log.error("Failed to extract roles from token", e);
            return null;
        }
    }

    public String extractClientIPFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaimAsString("client_ip");
        } catch (JwtException e) {
            log.error("Failed to extract client IP from token", e);
            return null;
        }
    }

    public Long extractUserIdFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            String userIdStr = jwt.getClaimAsString("user_id");
            return userIdStr != null ? Long.valueOf(userIdStr) : null;
        } catch (JwtException | NumberFormatException e) {
            log.error("Failed to extract user ID from token", e);
            return null;
        }
    }

    public String extractTokenTypeFromToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaimAsString("token_type");
        } catch (JwtException e) {
            log.error("Failed to extract token type from token", e);
            return null;
        }
    }


    private List<Role> convertStringsToRoles(List<String> roleStrings) {
        return roleStrings.stream()
                .map(roleName -> {
                    try {
                        return Role.valueOf(roleName);
                    } catch (IllegalArgumentException e) {
                        log.warn("Invalid role name: {}", roleName);
                        return null;
                    }
                })
                .filter(role -> role != null)
                .collect(Collectors.toList());
    }
}