package authentication.RESTAuthentication.controller;


import authentication.RESTAuthentication.dto.loginRequest;
import authentication.RESTAuthentication.dto.TokenResponse;
import authentication.RESTAuthentication.entities.User;
import authentication.RESTAuthentication.services.AuthenticationService;
import authentication.RESTAuthentication.util.EncryptDecrypt;
import authentication.RESTAuthentication.util.TokenService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/authorization")
@Slf4j
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private JwtEncoder jwtEncoder;
    @Autowired
    private EncryptDecrypt encryptDecrypt;

    @PostMapping("/connect")
    public ResponseEntity<String> connect(HttpServletRequest httpRequest) {
        String username = null;
        String password;
        try {
            String clientIP = getClientIP(httpRequest);
            // Authenticate user data from Basic Authentication
            String bearerToken = httpRequest.getHeader("Authorization");
            if (bearerToken != null && bearerToken.startsWith("Basic ")) {
                String token = bearerToken.substring(6);

                try {
                    byte[] decodedBytes = Base64.getDecoder().decode(token);
                    String userDetails = new String(decodedBytes, StandardCharsets.UTF_8);

                    String[] userDetailsArray = userDetails.split(":", 2);
                    if (userDetailsArray.length != 2) {
                        log.warn("Invalid token format provided ");
                        return ResponseEntity.badRequest().build();
                    }

                    username = userDetailsArray[0];
                    password = userDetailsArray[1];

                    log.info("Decoded Basic Auth - Username: {}, Password: {}", username, password);



                } catch (IllegalArgumentException e) {
                    log.error("Failed to decode Base64 token: {}", token, e);
                    return ResponseEntity.badRequest().build();
                }

            } else {
                log.warn("No Bearer token provided for user: {}", username);
                return ResponseEntity.badRequest().build();
            }

            log.info("Login attempt from IP: {} for user: {}", clientIP, username);

            User user = authenticationService.authenticate(username, password);

            String accessToken = tokenService.generateAccessToken(user, clientIP);
            String refreshToken = tokenService.generateRefreshToken(user, clientIP);

            TokenResponse response = TokenResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(900) // 15 minutes
                    .build();

            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResponse = objectMapper.writeValueAsString(response);

            log.info("Successful login for user: {} from IP: {}", username, clientIP);
            return ResponseEntity.ok(encryptDecrypt.encrypt(jsonResponse));

        } catch (UsernameNotFoundException | BadCredentialsException e) {
            log.warn("Failed login attempt for user: {}", username);
            return ResponseEntity.badRequest().body("NOT VALID");
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @PostMapping("/renewToken")
    public ResponseEntity<String> renewToken(HttpServletRequest request) throws Exception {
        Map<String, Object> userTokenDetails = (Map<String, Object>) request.getAttribute("userTokenDetails");
        Map<String, Object> completeData = (Map<String, Object>) request.getAttribute("completeData");

        if (userTokenDetails == null || completeData == null) {
            return ResponseEntity.badRequest().body("Token details or complete data missing");
        }
       String old_accessToken = userTokenDetails.get("accessToken").toString();
        String refreshToken = userTokenDetails.get("refreshToken").toString();
        String accessToken = tokenService.updateAccessToken(userTokenDetails.get("refreshToken").toString(),
                userTokenDetails.get("accessToken").toString());
        TokenResponse response = TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(900) // 15 minutes
                .build();

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(response);
        return ResponseEntity.ok(encryptDecrypt.encrypt(jsonResponse));
    }


    private String getClientIP(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    @PostMapping("/encryptValue")
    public ResponseEntity<String> encryptValue(HttpServletRequest request) {
        try {

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> requestBody = (Map<String, Object>) request.getAttribute("requestBody");
            if (requestBody == null) {
                return ResponseEntity.badRequest().body("Request body not found in attributes");
            }
            String stringRequestBody = objectMapper.writeValueAsString(requestBody);
//            System.out.println("Request Body: " + stringRequestBody);
            String encryptedValue = encryptDecrypt.encrypt(stringRequestBody);
            return ResponseEntity.ok(encryptedValue);
        } catch (Exception e) {
            log.error("Error encrypting value: {}", e.getMessage());
            return ResponseEntity.status(500).body("Encryption failed");
        }
    }

    @PostMapping("/decryptValue")
    public ResponseEntity<String> decryptValue(HttpServletRequest request) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> requestBody = (Map<String, Object>) request.getAttribute("requestBody");
            if (requestBody == null) {
                return ResponseEntity.badRequest().body("Request body not found in attributes");
            }
            String encryptedValue = requestBody.get("Value").toString();
            String decryptedValue = encryptDecrypt.decrypt(encryptedValue);
            return ResponseEntity.ok(decryptedValue);
        } catch (Exception e) {
            log.error("Error decrypting value: {}", e.getMessage());
            return ResponseEntity.status(500).body("Decryption failed");
        }
    }

    @PostMapping ("/trial")
    public ResponseEntity<String> trial (HttpServletRequest request) {
        Map<String, Object> completeData = (Map<String, Object>) request.getAttribute("completeData");
        if (completeData == null) {
            return ResponseEntity.badRequest().body("Complete data not found in attributes");
        }
        String username = (String) completeData.get("username");
        String password = (String) completeData.get("password");
        if (username == null || password == null) {
            return ResponseEntity.badRequest().body("Username or password not found in complete data");

        }
        log.info("Username: {}, Password: {}", username, password);
        System.out.println("Username: " + username);
        String abc = request.getRequestURI();
        return ResponseEntity.ok("COMPLETETED");
    }

}