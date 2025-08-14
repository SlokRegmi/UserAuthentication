package authentication.RESTAuthentication.filter;


import authentication.RESTAuthentication.Wrapper.CachedBodyHttpServletRequest;
import authentication.RESTAuthentication.util.EncryptDecrypt;
import authentication.RESTAuthentication.util.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class JWTFilter implements Filter {

    private final TokenService tokenService;
    private final EncryptDecrypt encryptDecrypt;

    @Autowired
    public JWTFilter(TokenService tokenService, EncryptDecrypt encryptDecrypt) {
        this.tokenService = tokenService;
        this.encryptDecrypt = encryptDecrypt;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        HttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request);

        if (request.getRequestURI().contains("/authorization/connect")) {
            filterChain.doFilter(wrappedRequest, servletResponse);
            return;
        }

        String authorizationHeader = wrappedRequest.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            sendErrorResponse(response, 401, "Missing or invalid Authorization header");
            return;
        }

        String base64Token = authorizationHeader.substring(7).trim();
        try {
            // Step 1: Decrypt token
            String tokenDetailsJson = encryptDecrypt.decrypt(base64Token);
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, String> userTokenDetailsMap = objectMapper.readValue(tokenDetailsJson, Map.class);
            request.setAttribute("userTokenDetails", userTokenDetailsMap);

            // Step 2: Validate access token
            Boolean isValid = tokenService.isTokenValid(userTokenDetailsMap.get("accessToken"));
            if (!isValid) {
                sendErrorResponse(response, 401, "Invalid or expired token");
                return;
            }

            String tokenUsername = tokenService.extractUsernameFromToken(userTokenDetailsMap.get("accessToken"));

            // Step 3: Extract completeData from request body
            Map<String, Object> requestData = objectMapper.readValue(wrappedRequest.getInputStream(), Map.class);
            String completeData = (String) requestData.get("completeData");
            if (completeData == null || completeData.isEmpty()) {
                sendErrorResponse(response, 401, "Data is missing");
                return;
            }

            // Step 4: Decrypt completeData and store it for controller use
            String decryptedData = encryptDecrypt.decrypt(completeData);
            Map<String, Object> completeDataMap = objectMapper.readValue(decryptedData, Map.class);
            request.setAttribute("completeData", completeDataMap);

            // Step 5: Username check
            String username = (String) completeDataMap.get("username");
            if (username == null || username.isEmpty()) {
                sendErrorResponse(response, 401, "Username is required");
                return;
            }
            String password = (String) completeDataMap.get("password");
            if (password == null || password.isEmpty()) {
                sendErrorResponse(response, 401, "Password is required");
                return;
            }
            if (!tokenUsername.equals(username)) {
                sendErrorResponse(response, 401, "Token username does not match request username");
                return;
            }

            // Continue to controller
            filterChain.doFilter(wrappedRequest, servletResponse);

        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            sendErrorResponse(response, 401, "Invalid Base64 token");
        } catch (Exception e) {
            e.printStackTrace();
            sendErrorResponse(response, 500, "Internal server error");
        }
    }


    private void sendErrorResponse(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now().toString());
        errorResponse.put("status", status);
        errorResponse.put("error", status == 401 ? "Unauthorized" : "Forbidden");
        errorResponse.put("message", message);

        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().write(mapper.writeValueAsString(errorResponse));
    }

    @Override
    public void init(jakarta.servlet.FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }
}