//package authentication.RESTAuthentication.filter;
//
//import authentication.RESTAuthentication.Wrapper.CachedBodyHttpServletRequest;
//import authentication.RESTAuthentication.util.RateLimiter;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.MediaType;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.time.LocalDateTime;
//import java.time.format.DateTimeFormatter;
//import java.util.HashMap;
//import java.util.Map;
//
//@Component
//@Slf4j
//public class RateLimitingFilter extends OncePerRequestFilter {
//
//    private final ObjectMapper objectMapper;
//
//    @Autowired
//    private RateLimiter rateLimiter; // Inject the RateLimiter bean
//
//    public RateLimitingFilter() {
//        this.objectMapper = new ObjectMapper();
//        this.objectMapper.registerModule(new JavaTimeModule());
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request);
//
//        int clientID = 123;
//        String requestURI = wrappedRequest.getRequestURI();
//
//        if (requestURI.contains("/thisIsExample")) {
//            if (!rateLimiter.isAllowed(clientID)) {
//                log.warn("Rate limit exceeded for client ID: {}", clientID);
//                handleRateLimitExceeded(response, clientID);
//                return;
//            } else {
//                addRateLimitHeaders(response, clientID);
//                filterChain.doFilter(wrappedRequest, response);
//            }
//        } else {
//            filterChain.doFilter(wrappedRequest, response);
//        }
//    }
//
//    private void addRateLimitHeaders(HttpServletResponse response, int clientID) {
//        try {
//            RateLimiter.RateLimitStatus status = rateLimiter.getRateLimitStatus(clientID);
//
//            response.setHeader("X-RateLimit-Hourly-Limit", String.valueOf(status.getHourlyLimit()));
//            response.setHeader("X-RateLimit-Hourly-Remaining", String.valueOf(status.getHourlyRemaining()));
//            response.setHeader("X-RateLimit-Minute-Limit", String.valueOf(status.getMinuteLimit()));
//            response.setHeader("X-RateLimit-Minute-Remaining", String.valueOf(status.getMinuteRemaining()));
//
//        } catch (Exception e) {
//            log.warn("Failed to add rate limit headers", e);
//        }
//    }
//
//    private void handleRateLimitExceeded(HttpServletResponse response, int clientID) throws IOException {
//        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//
//        RateLimiter.RateLimitStatus status = rateLimiter.getRateLimitStatus(clientID);
//
//        response.setHeader("X-RateLimit-Hourly-Limit", String.valueOf(status.getHourlyLimit()));
//        response.setHeader("X-RateLimit-Hourly-Remaining", String.valueOf(status.getHourlyRemaining()));
//        response.setHeader("X-RateLimit-Minute-Limit", String.valueOf(status.getMinuteLimit()));
//        response.setHeader("X-RateLimit-Minute-Remaining", String.valueOf(status.getMinuteRemaining()));
//
//        if (status.getMinuteRemaining() == 0) {
//            response.setHeader("Retry-After", "60"); // 1 minute
//        } else {
//            response.setHeader("Retry-After", "3600"); // 1 hour
//        }
//
//        Map<String, Object> errorResponse = new HashMap<>();
//        errorResponse.put("error", "RATE_LIMIT_EXCEEDED");
//
//        String limitType;
//        if (status.getMinuteRemaining() == 0) {
//            limitType = "minute";
//        } else {
//            limitType = "hourly";
//        }
//
//        errorResponse.put("message", String.format("Rate limit exceeded for client ID: %d. %s limit reached.",
//                clientID, limitType));
//        errorResponse.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
//        errorResponse.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
//
//        // Add limit details to response body
//        Map<String, Object> limits = new HashMap<>();
//        limits.put("hourly", Map.of(
//                "limit", status.getHourlyLimit(),
//                "remaining", status.getHourlyRemaining(),
//                "current", status.getHourlyCount()
//        ));
//        limits.put("minute", Map.of(
//                "limit", status.getMinuteLimit(),
//                "remaining", status.getMinuteRemaining(),
//                "current", status.getMinuteCount()
//        ));
//        errorResponse.put("rateLimits", limits);
//
//        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
//    }
//}