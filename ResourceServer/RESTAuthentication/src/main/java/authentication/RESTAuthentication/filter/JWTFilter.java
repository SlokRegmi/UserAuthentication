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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Collections;

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
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request);
        // BEARER TOKEN CHECK GARXA -----------------------------------------------------
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            sendErrorResponse(response, 401, "Missing or invalid Authorization header");
            return;
        }

        String base64Token = authorizationHeader.substring(7).trim();
        try {
            String TokensDetails = encryptDecrypt.decrypt(base64Token);
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, String> userTokenDetailsMap = objectMapper.readValue(TokensDetails, Map.class);

            String accessToken = userTokenDetailsMap.get("accessToken");

            if (accessToken == null || !tokenService.isTokenValid(accessToken)) {
                sendErrorResponse(response, 401, "Invalid or expired token");
                return;
            }

            String tokenUsername = tokenService.extractUsernameFromToken(accessToken);

            if (tokenUsername != null) {
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        tokenUsername,
                        null,
                        Collections.emptyList() //Actual Authorities sanga haalne
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            //------------------------------------------------------------------------------
            //-----------------USER KO PARAM KO DATA LINXA ---------------------------------------------------------------

            Map<String, String> userData = new HashMap<>();
            userData = objectMapper.readValue(wrappedRequest.getInputStream(), Map.class);

            if (userData == null || userData.isEmpty()) {
                sendErrorResponse(response, 400, "Request body is empty or invalid");
                return;
            }

            if (wrappedRequest.getRequestURI().contains("/encryptData")) {
                if (userData.get("username") == null || userData.get("password") == null) {
                    sendErrorResponse(response, 400, "Username or password is missing");
                    return;
                }
                if (!userData.get("username").toString().equals(tokenUsername)) {
                    sendErrorResponse(response, 401, "Username in request does not match token username");
                    return;
                }
                request.setAttribute("dataToEncrypt", userData);
                filterChain.doFilter(wrappedRequest, response);
                return;
            }
            String completeData =  userData.get("completeData");
            if (completeData == null || completeData.isEmpty()) {
                sendErrorResponse(response, 400, "Data is missing");
                return;
            }
            String decryptedData = encryptDecrypt.decrypt(completeData);
            System.out.println("Decrypted Data: " + decryptedData);
            Map<String, String> map = new HashMap<>();
            String[] pairs = decryptedData.replaceAll("[\\{\\}]", "").split("\\s*,\\s*");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=");
                if (keyValue.length == 2) {
                    map.put(keyValue[0], keyValue[1]);
                }
            }
            request.setAttribute("completeData", map);

            filterChain.doFilter(wrappedRequest, response);

        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            sendErrorResponse(response  , 401, "Invalid Base64 token");
        } catch (Exception e) {
            e.printStackTrace();
            sendErrorResponse(response, 500, "Internal Server Error");
        }
    }

    private void sendErrorResponse(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now().toString());
        errorResponse.put("status", status);
        errorResponse.put("error", "Unauthorized");
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