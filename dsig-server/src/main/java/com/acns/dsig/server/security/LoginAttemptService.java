package com.acns.dsig.server.security;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory brute-force prevention and login lockout manager.
 */
@Service
public class LoginAttemptService {

    public static final int MAX_ATTEMPTS = 5;
    public static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

    private record AttemptInfo(int attempts, long lastAttemptTime) {}

    private final Map<String, AttemptInfo> attemptsCache = new ConcurrentHashMap<>();

    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
    }

    public void loginFailed(String key) {
        long now = System.currentTimeMillis();
        attemptsCache.compute(key, (k, v) -> {
            if (v == null || (now - v.lastAttemptTime()) > LOCKOUT_DURATION_MS) {
                return new AttemptInfo(1, now);
            }
            return new AttemptInfo(v.attempts() + 1, now);
        });
    }

    public boolean isBlocked(String key) {
        AttemptInfo info = attemptsCache.get(key);
        if (info == null) return false;
        long now = System.currentTimeMillis();
        if ((now - info.lastAttemptTime()) > LOCKOUT_DURATION_MS) {
            attemptsCache.remove(key);
            return false;
        }
        return info.attempts() >= MAX_ATTEMPTS;
    }
}
