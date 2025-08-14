package authentication.RESTAuthentication.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class RateLimitingService {

    private final ConcurrentHashMap<String, RateLimitInfo> rateLimitMap = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final int MAX_REQUESTS_PER_HOUR = 100;

    public RateLimitingService() {
        // Schedule cleanup task to remove expired entries every 10 minutes
        scheduler.scheduleAtFixedRate(this::cleanupExpiredEntries, 10, 10, TimeUnit.MINUTES);
    }

    public boolean isAllowed(String clientIP) {
        RateLimitInfo info = rateLimitMap.computeIfAbsent(clientIP, k -> new RateLimitInfo());

        LocalDateTime now = LocalDateTime.now();

        // Reset if more than an hour has passed
        if (info.getWindowStart().isBefore(now.minusHours(1))) {
            info.reset(now);
        }

        info.incrementCount();

        boolean allowed = info.getCount() <= MAX_REQUESTS_PER_HOUR;

        if (!allowed) {
            log.warn("Rate limit exceeded for IP: {}. Current count: {}", clientIP, info.getCount());
        }

        return allowed;
    }

    public long getRemainingRequests(String clientIP) {
        RateLimitInfo info = rateLimitMap.get(clientIP);

        if (info == null) {
            return MAX_REQUESTS_PER_HOUR;
        }

        LocalDateTime now = LocalDateTime.now();

        // If window has expired, return max requests
        if (info.getWindowStart().isBefore(now.minusHours(1))) {
            return MAX_REQUESTS_PER_HOUR;
        }

        return Math.max(0, MAX_REQUESTS_PER_HOUR - info.getCount());
    }

    private void cleanupExpiredEntries() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(1);
        rateLimitMap.entrySet().removeIf(entry -> entry.getValue().getWindowStart().isBefore(cutoff));
        log.debug("Cleaned up expired rate limit entries. Current size: {}", rateLimitMap.size());
    }

    private static class RateLimitInfo {
        private LocalDateTime windowStart;
        private long count;

        public RateLimitInfo() {
            this.windowStart = LocalDateTime.now();
            this.count = 0;
        }

        public void reset(LocalDateTime newWindowStart) {
            this.windowStart = newWindowStart;
            this.count = 0;
        }

        public void incrementCount() {
            this.count++;
        }

        public LocalDateTime getWindowStart() {
            return windowStart;
        }

        public long getCount() {
            return count;
        }
    }
}