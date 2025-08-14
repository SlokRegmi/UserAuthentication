package authentication.RESTAuthentication.util;

import authentication.RESTAuthentication.entities.Role;
import authentication.RESTAuthentication.entities.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Arrays;

@Service
@Slf4j
public class TokenService {

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private EncryptDecrypt encryptDecrypt;

    public String generateAccessToken(User user, String clientIP) {
        Instant now = Instant.now();

        // Convert roles to strings for JWT claims
        List<String> roleStrings = user.getRoles().stream()
                .map(Role::name) // Convert enum to string
                .collect(Collectors.toList());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("secure-api")
                .issuedAt(now)
                .expiresAt(now.plus(15, ChronoUnit.MINUTES))
                .subject(user.getUsername())
                .claim("roles", roleStrings)
                .claim("client_ip", clientIP)
                .claim("user_id", user.getId().toString()) // Convert to String
                .claim("token_type", "access")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    public String generateRefreshToken(User user, String clientIP) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("secure-api")
                .issuedAt(now)
                .expiresAt(now.plus(7, ChronoUnit.DAYS))
                .subject(user.getUsername())
                .claim("client_ip", clientIP)
                .claim("user_id", user.getId().toString()) // Convert to String

                .claim("token_type", "refresh")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
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
//            System.out.println(token);
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

    public String updateAccessToken(String refreshToken, String accessToken) {
        if (!isTokenValid(refreshToken)) {
            log.error("Invalid or expired refresh token provided.");
            throw new RuntimeException("Invalid or expired refresh token");
        }

        String tokenType = extractTokenTypeFromToken(refreshToken);
        if (!"refresh".equals(tokenType)) {
            log.error("Token provided is not a refresh token");
            throw new RuntimeException("Invalid token type - expected refresh token");
        }

        Long userId = extractUserIdFromToken(refreshToken);
        String username = extractUsernameFromToken(refreshToken);
        String clientIP = extractClientIPFromToken(accessToken);
        String usernameFromAccessToken = extractUsernameFromToken(accessToken);
        if (username == null || !username.equals(usernameFromAccessToken)) {
            log.error("Username from access token does not match username from refresh token");
            throw new RuntimeException("Username mismatch between access and refresh tokens");
        }
        List<String> roleStrings = extractRolesFromToken(accessToken);

        if (userId == null || username == null ) {
            log.error("Failed to extract user details from refresh token.");
            throw new RuntimeException("Invalid refresh token payload");
        }

        User user = new User();
        user.setId(userId);
        user.setUsername(username);
        List<Role> roles = convertStringsToRoles(roleStrings);
        user.setRoles(roles);

        return generateAccessToken(user, "1" );// aahile ko laagi dummy pathako xa
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