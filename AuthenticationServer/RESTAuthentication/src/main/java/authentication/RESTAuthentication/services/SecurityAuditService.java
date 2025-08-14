package authentication.RESTAuthentication.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Service
@Slf4j
public class SecurityAuditService {

    private final ConcurrentHashMap<String, AuditEvent> auditLog = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LoginAttemptInfo> loginAttempts = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private final AtomicLong eventCounter = new AtomicLong(0);

    public SecurityAuditService() {
        // Schedule cleanup task every hour to remove old entries
        scheduler.scheduleAtFixedRate(this::cleanupExpiredEntries, 1, 1, TimeUnit.HOURS);
    }

    public void logSecurityEvent(String eventType, String username, String clientIP, String details) {
        AuditEvent auditEvent = new AuditEvent();
        auditEvent.setEventType(eventType);
        auditEvent.setUsername(username);
        auditEvent.setClientIP(clientIP);
        auditEvent.setDetails(details);
        auditEvent.setTimestamp(LocalDateTime.now());

        String key = "audit_" + eventCounter.incrementAndGet() + "_" + System.currentTimeMillis();
        auditLog.put(key, auditEvent);

        log.info("Security Event - Type: {}, User: {}, IP: {}, Details: {}",
                eventType, username, clientIP, details);
    }

    public void logLoginAttempt(String username, String clientIP, boolean successful) {
        String eventType = successful ? "LOGIN_SUCCESS" : "LOGIN_FAILED";
        String details = successful ? "User successfully authenticated" : "Authentication failed";

        logSecurityEvent(eventType, username, clientIP, details);

        // Track failed attempts
        if (!successful) {
            String key = username + ":" + clientIP;
            LoginAttemptInfo info = loginAttempts.computeIfAbsent(key, k -> new LoginAttemptInfo());

            LocalDateTime now = LocalDateTime.now();

            // Reset if more than an hour has passed
            if (info.getWindowStart().isBefore(now.minusHours(1))) {
                info.reset(now);
            }

            info.incrementAttempts();

            if (info.getAttempts() > 5) {
                logSecurityEvent("SUSPICIOUS_ACTIVITY", username, clientIP,
                        "Multiple failed login attempts: " + info.getAttempts());
            }
        } else {
            // Clear failed attempts on successful login
            String key = username + ":" + clientIP;
            loginAttempts.remove(key);
        }
    }

    public Map<String, AuditEvent> getRecentAuditEvents(int limit) {
        Map<String, AuditEvent> recentEvents = new HashMap<>();
        auditLog.entrySet().stream()
                .sorted((e1, e2) -> e2.getValue().getTimestamp().compareTo(e1.getValue().getTimestamp()))
                .limit(limit)
                .forEach(entry -> recentEvents.put(entry.getKey(), entry.getValue()));
        return recentEvents;
    }

    public long getFailedLoginAttempts(String username, String clientIP) {
        String key = username + ":" + clientIP;
        LoginAttemptInfo info = loginAttempts.get(key);

        if (info == null) {
            return 0;
        }

        LocalDateTime now = LocalDateTime.now();

        // If window has expired, return 0
        if (info.getWindowStart().isBefore(now.minusHours(1))) {
            return 0;
        }

        return info.getAttempts();
    }

    private void cleanupExpiredEntries() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(30);

        // Remove audit events older than 30 days
        auditLog.entrySet().removeIf(entry -> entry.getValue().getTimestamp().isBefore(cutoff));

        // Remove login attempt entries older than 1 hour
        LocalDateTime attemptCutoff = LocalDateTime.now().minusHours(1);
        loginAttempts.entrySet().removeIf(entry -> entry.getValue().getWindowStart().isBefore(attemptCutoff));

        log.debug("Cleaned up expired security audit entries. Audit log size: {}, Login attempts size: {}",
                auditLog.size(), loginAttempts.size());
    }

    public static class AuditEvent {
        private String eventType;
        private String username;
        private String clientIP;
        private String details;
        private LocalDateTime timestamp;

        // Getters and setters
        public String getEventType() { return eventType; }
        public void setEventType(String eventType) { this.eventType = eventType; }

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getClientIP() { return clientIP; }
        public void setClientIP(String clientIP) { this.clientIP = clientIP; }

        public String getDetails() { return details; }
        public void setDetails(String details) { this.details = details; }

        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

        @Override
        public String toString() {
            return String.format("AuditEvent{eventType='%s', username='%s', clientIP='%s', details='%s', timestamp=%s}",
                    eventType, username, clientIP, details, timestamp);
        }
    }

    private static class LoginAttemptInfo {
        private LocalDateTime windowStart;
        private long attempts;

        public LoginAttemptInfo() {
            this.windowStart = LocalDateTime.now();
            this.attempts = 0;
        }

        public void reset(LocalDateTime newWindowStart) {
            this.windowStart = newWindowStart;
            this.attempts = 0;
        }

        public void incrementAttempts() {
            this.attempts++;
        }

        public LocalDateTime getWindowStart() {
            return windowStart;
        }

        public long getAttempts() {
            return attempts;
        }
    }
}