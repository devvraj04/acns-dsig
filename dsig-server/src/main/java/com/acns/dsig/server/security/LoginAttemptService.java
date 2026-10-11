package com.acns.dsig.server.security;

import com.acns.dsig.server.persistence.User;
import com.acns.dsig.server.persistence.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory and persistent brute-force prevention and login lockout manager.
 * Protects authentication endpoints by tracking failed attempts
 * and enforcing temporary account lockout after 5 consecutive failures.
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    public static final int MAX_ATTEMPTS = 5;
    public static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

    private record AttemptInfo(int attempts, long lastAttemptTime) {}

    private final Map<String, AttemptInfo> attemptsCache = new ConcurrentHashMap<>();
    private final UserRepository userRepository;

    @Autowired
    public LoginAttemptService(@Autowired(required = false) UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public LoginAttemptService() {
        this.userRepository = null;
    }

    @Transactional
    public void loginSucceeded(String key) {
        if (key == null || key.isBlank()) {
            return;
        }
        String normalizedKey = normalizeKey(key);
        attemptsCache.remove(normalizedKey);

        if (userRepository != null) {
            try {
                Optional<User> userOpt = userRepository.findByUsername(normalizedKey);
                if (userOpt.isPresent()) {
                    User user = userOpt.get();
                    if (user.getFailedLogins() > 0 || user.getLockedUntil() != null) {
                        user.setFailedLogins(0);
                        user.setLockedUntil(null);
                        userRepository.save(user);
                    }
                }
            } catch (Exception e) {
                log.warn("Could not reset failed logins in database for {}: {}", normalizedKey, e.getMessage());
            }
        }
    }

    @Transactional
    public void loginFailed(String key) {
        if (key == null || key.isBlank()) {
            return;
        }
        String normalizedKey = normalizeKey(key);

        // If the account is already locked, do not extend the lockout duration
        if (isBlocked(normalizedKey)) {
            log.warn("Account '{}' is already locked. Rejecting attempt without extending lockout.", normalizedKey);
            return;
        }

        long now = System.currentTimeMillis();
        AttemptInfo updated = attemptsCache.compute(normalizedKey, (k, v) -> {
            if (v == null || (now - v.lastAttemptTime()) > LOCKOUT_DURATION_MS) {
                return new AttemptInfo(1, now);
            }
            return new AttemptInfo(v.attempts() + 1, now);
        });

        int currentAttempts = updated.attempts();
        log.warn("Failed login attempt for user/key '{}'. Current consecutive failures: {}",
                normalizedKey, currentAttempts);

        if (userRepository != null) {
            try {
                Optional<User> userOpt = userRepository.findByUsername(normalizedKey);
                if (userOpt.isPresent()) {
                    User user = userOpt.get();
                    user.setFailedLogins(currentAttempts);
                    if (currentAttempts >= MAX_ATTEMPTS) {
                        Instant lockUntil = Instant.ofEpochMilli(now + LOCKOUT_DURATION_MS);
                        user.setLockedUntil(lockUntil);
                        log.warn("Account '{}' locked until {} due to {} failed attempts",
                                normalizedKey, lockUntil, currentAttempts);
                    }
                    userRepository.save(user);
                }
            } catch (Exception e) {
                log.warn("Could not persist failed login attempt for {}: {}", normalizedKey, e.getMessage());
            }
        }
    }

    public boolean isBlocked(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        String normalizedKey = normalizeKey(key);
        long now = System.currentTimeMillis();

        AttemptInfo info = attemptsCache.get(normalizedKey);
        if (info != null) {
            if ((now - info.lastAttemptTime()) > LOCKOUT_DURATION_MS) {
                attemptsCache.remove(normalizedKey);
            } else if (info.attempts() >= MAX_ATTEMPTS) {
                return true;
            }
        }

        if (userRepository != null) {
            try {
                Optional<User> userOpt = userRepository.findByUsername(normalizedKey);
                if (userOpt.isPresent()) {
                    User user = userOpt.get();
                    Instant lockedUntil = user.getLockedUntil();
                    if (lockedUntil != null && lockedUntil.isAfter(Instant.now())) {
                        return true;
                    }
                }
            } catch (Exception e) {
                log.warn("Could not check persistent lockout status for {}: {}", normalizedKey, e.getMessage());
            }
        }

        return false;
    }

    public int getAttempts(String key) {
        if (key == null || key.isBlank()) {
            return 0;
        }
        AttemptInfo info = attemptsCache.get(normalizeKey(key));
        return info == null ? 0 : info.attempts();
    }

    public void reset(String key) {
        loginSucceeded(key);
    }

    public void resetCache() {
        attemptsCache.clear();
    }

    private String normalizeKey(String key) {
        return key.trim().toLowerCase();
    }
}
