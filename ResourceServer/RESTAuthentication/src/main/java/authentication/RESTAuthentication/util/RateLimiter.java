//package authentication.RESTAuthentication.util;
//
//import jakarta.websocket.server.ServerEndpoint;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.stereotype.Service;
//
//import java.time.LocalDateTime;
//import java.util.concurrent.ConcurrentHashMap;
//import java.util.concurrent.Executors;
//import java.util.concurrent.ScheduledExecutorService;
//import java.util.concurrent.TimeUnit;
//
//@Service
//@Slf4j
//public class RateLimiter {
//
//    private final ConcurrentHashMap<String, RateLimitInfo> rateLimitMap = new ConcurrentHashMap<>();
//    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
//    private static final int MAX_REQUESTS_PER_HOUR = 100;
//    private static final int MAX_REQUESTS_PER_MINUTE = 6;
//
//    public RateLimiter() {
//        scheduler.scheduleAtFixedRate(this::cleanupExpiredEntries, 10, 10, TimeUnit.MINUTES);
//    }
//
//    public boolean isAllowed(int clientID) {
//        RateLimitInfo info = rateLimitMap.computeIfAbsent(String.valueOf(clientID), k -> new RateLimitInfo());
//
//        LocalDateTime now = LocalDateTime.now();
//
//        // Check and reset hourly window if needed
//        if (info.getHourlyWindowStart().isBefore(now.minusHours(1))) {
//            info.resetHourly(now);
//        }
//
//        // Check and reset minute window if needed
//        if (info.getMinuteWindowStart().isBefore(now.minusMinutes(1))) {
//            info.resetMinute(now);
//        }
//
//        // Check both limits BEFORE incrementing
//        boolean withinHourlyLimit = info.getHourlyCount() < MAX_REQUESTS_PER_HOUR;
//        boolean withinMinuteLimit = info.getMinuteCount() < MAX_REQUESTS_PER_MINUTE;
//
//        if (!withinHourlyLimit) {
//            log.warn("Hourly rate limit exceeded for client ID: {}. Current count: {}", clientID, info.getHourlyCount());
//            return false;
//        }
//
//        if (!withinMinuteLimit) {
//            log.warn("Minute rate limit exceeded for client ID: {}. Current count: {}", clientID, info.getMinuteCount());
//            return false;
//        }
//
//        // If both limits allow it, increment both counters
//        info.incrementCounts();
//
//        log.debug("Request allowed for client ID: {}. Hourly: {}/{}, Minute: {}/{}",
//                clientID, info.getHourlyCount(), MAX_REQUESTS_PER_HOUR,
//                info.getMinuteCount(), MAX_REQUESTS_PER_MINUTE);
//
//        return true;
//    }
//
//    private void cleanupExpiredEntries() {
//        LocalDateTime cutoff = LocalDateTime.now().minusHours(1);
//        rateLimitMap.entrySet().removeIf(entry ->
//                entry.getValue().getHourlyWindowStart().isBefore(cutoff));
//        log.debug("Cleaned up expired rate limit entries. Current size: {}", rateLimitMap.size());
//    }
//
//    public RateLimitStatus getRateLimitStatus(int clientID) {
//        RateLimitInfo info = rateLimitMap.get(String.valueOf(clientID));
//        if (info == null) {
//            return new RateLimitStatus(0, 0, MAX_REQUESTS_PER_HOUR, MAX_REQUESTS_PER_MINUTE);
//        }
//
//        LocalDateTime now = LocalDateTime.now();
//
//        // Reset windows if expired
//        if (info.getHourlyWindowStart().isBefore(now.minusHours(1))) {
//            info.resetHourly(now);
//        }
//        if (info.getMinuteWindowStart().isBefore(now.minusMinutes(1))) {
//            info.resetMinute(now);
//        }
//
//        return new RateLimitStatus(
//                info.getHourlyCount(),
//                info.getMinuteCount(),
//                MAX_REQUESTS_PER_HOUR,
//                MAX_REQUESTS_PER_MINUTE
//        );
//    }
//
//    private static class RateLimitInfo {
//        private LocalDateTime hourlyWindowStart;
//        private LocalDateTime minuteWindowStart;
//        private long hourlyCount;
//        private long minuteCount;
//
//        public RateLimitInfo() {
//            LocalDateTime now = LocalDateTime.now();
//            this.hourlyWindowStart = now;
//            this.minuteWindowStart = now;
//            this.hourlyCount = 0;
//            this.minuteCount = 0;
//        }
//
//        public void resetHourly(LocalDateTime newWindowStart) {
//            this.hourlyWindowStart = newWindowStart;
//            this.hourlyCount = 0;
//        }
//
//        public void resetMinute(LocalDateTime newWindowStart) {
//            this.minuteWindowStart = newWindowStart;
//            this.minuteCount = 0;
//        }
//
//        public void incrementCounts() {
//            this.hourlyCount++;
//            this.minuteCount++;
//        }
//
//        public LocalDateTime getHourlyWindowStart() {
//            return hourlyWindowStart;
//        }
//
//        public LocalDateTime getMinuteWindowStart() {
//            return minuteWindowStart;
//        }
//
//        public long getHourlyCount() {
//            return hourlyCount;
//        }
//
//        public long getMinuteCount() {
//            return minuteCount;
//        }
//    }
//
//    public static class RateLimitStatus {
//        private final long hourlyCount;
//        private final long minuteCount;
//        private final int hourlyLimit;
//        private final int minuteLimit;
//
//        public RateLimitStatus(long hourlyCount, long minuteCount, int hourlyLimit, int minuteLimit) {
//            this.hourlyCount = hourlyCount;
//            this.minuteCount = minuteCount;
//            this.hourlyLimit = hourlyLimit;
//            this.minuteLimit = minuteLimit;
//        }
//
//        public long getHourlyRemaining() {
//            return Math.max(0, hourlyLimit - hourlyCount);
//        }
//
//        public long getMinuteRemaining() {
//            return Math.max(0, minuteLimit - minuteCount);
//        }
//
//        // Getters
//        public long getHourlyCount() { return hourlyCount; }
//        public long getMinuteCount() { return minuteCount; }
//        public int getHourlyLimit() { return hourlyLimit; }
//        public int getMinuteLimit() { return minuteLimit; }
//    }
//}