package authentication.RESTAuthentication.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class IPWhiteListService {

    private final ConcurrentHashMap<String, BlacklistInfo> blacklistMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AttemptInfo> attemptMap = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    private List<String> whitelistedIPs;
    private List<String> whitelistedCIDRs;

    public IPWhiteListService(@Value("${security.ip.whitelist:}") List<String> whitelistedIPs,
                              @Value("${security.ip.whitelist-cidrs:}") List<String> whitelistedCIDRs) {
        this.whitelistedIPs = whitelistedIPs;
        this.whitelistedCIDRs = whitelistedCIDRs;

        // Schedule cleanup task every 10 minutes
        scheduler.scheduleAtFixedRate(this::cleanupExpiredEntries, 10, 10, TimeUnit.MINUTES);
    }

    public boolean isIPAllowed(String ip) {
        // +For now nothing is blacklisted and all is allowed

        return true;
//        // Check if IP is blacklisted
//        if (isBlacklisted(ip)) {
//            log.warn("IP {} is blacklisted", ip);
//            return false;
//        }
//
//        // Check whitelist
//        if (whitelistedIPs != null && whitelistedIPs.contains(ip)) {
//            return true;
//        }
//
//        // Check CIDR ranges
//        if (whitelistedCIDRs != null) {
//            for (String cidr : whitelistedCIDRs) {
//                if (isIPInCIDR(ip, cidr)) {
//                    return true;
//                }
//            }
//        }
//
//        // Log failed attempt
//        logFailedAttempt(ip);
//        return false;
    }

    private boolean isBlacklisted(String ip) {


        //FOR NOW NOTHING IS BLACKLISTED
        return false;
//        BlacklistInfo info = blacklistMap.get(ip);
//        if (info == null) {
//            return false;
//        }
//
//        // Check if blacklist has expired
//        if (info.getExpiryTime().isBefore(LocalDateTime.now())) {
//            blacklistMap.remove(ip);
//            return false;
//        }
//
//        return true;
    }

    private void logFailedAttempt(String ip) {
        AttemptInfo info = attemptMap.computeIfAbsent(ip, k -> new AttemptInfo());

        LocalDateTime now = LocalDateTime.now();

        if (info.getWindowStart().isBefore(now.minusHours(1))) {
            info.reset(now);
        }

        info.incrementAttempts();

        if (info.getAttempts() > 5) {
            blacklistIP(ip, 24, TimeUnit.HOURS);
            log.warn("IP {} blacklisted due to {} failed attempts", ip, info.getAttempts());
        }
    }

    public void blacklistIP(String ip, long duration, TimeUnit unit) {
        LocalDateTime expiryTime = LocalDateTime.now().plus(duration, convertToChronoUnit(unit));
        blacklistMap.put(ip, new BlacklistInfo(expiryTime));
        log.info("IP {} blacklisted until {}", ip, expiryTime);
    }

    private void cleanupExpiredEntries() {
        LocalDateTime now = LocalDateTime.now();

        blacklistMap.entrySet().removeIf(entry -> entry.getValue().getExpiryTime().isBefore(now));

        LocalDateTime attemptCutoff = now.minusHours(1);
        attemptMap.entrySet().removeIf(entry -> entry.getValue().getWindowStart().isBefore(attemptCutoff));

        log.debug("Cleaned up expired entries. Blacklist size: {}, Attempts size: {}",
                blacklistMap.size(), attemptMap.size());
    }

    private boolean isIPInCIDR(String ip, String cidr) {
        try {
            String[] parts = cidr.split("/");
            InetAddress targetAddr = InetAddress.getByName(ip);
            InetAddress networkAddr = InetAddress.getByName(parts[0]);
            int prefixLength = Integer.parseInt(parts[1]);

            byte[] targetBytes = targetAddr.getAddress();
            byte[] networkBytes = networkAddr.getAddress();

            int bytesToCheck = prefixLength / 8;
            int bitsToCheck = prefixLength % 8;

            for (int i = 0; i < bytesToCheck; i++) {
                if (targetBytes[i] != networkBytes[i]) {
                    return false;
                }
            }

            if (bitsToCheck > 0) {
                int mask = 0xFF << (8 - bitsToCheck);
                return (targetBytes[bytesToCheck] & mask) == (networkBytes[bytesToCheck] & mask);
            }

            return true;
        } catch (UnknownHostException | NumberFormatException | ArrayIndexOutOfBoundsException e) {
            log.error("Error checking IP {} against CIDR {}: {}", ip, cidr, e.getMessage());
            return false;
        }
    }

    private java.time.temporal.ChronoUnit convertToChronoUnit(TimeUnit unit) {
        switch (unit) {
            case SECONDS: return java.time.temporal.ChronoUnit.SECONDS;
            case MINUTES: return java.time.temporal.ChronoUnit.MINUTES;
            case HOURS: return java.time.temporal.ChronoUnit.HOURS;
            case DAYS: return java.time.temporal.ChronoUnit.DAYS;
            default: return java.time.temporal.ChronoUnit.SECONDS;
        }
    }

    private static class BlacklistInfo {
        private final LocalDateTime expiryTime;

        public BlacklistInfo(LocalDateTime expiryTime) {
            this.expiryTime = expiryTime;
        }

        public LocalDateTime getExpiryTime() {
            return expiryTime;
        }
    }

    private static class AttemptInfo {
        private LocalDateTime windowStart;
        private long attempts;

        public AttemptInfo() {
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