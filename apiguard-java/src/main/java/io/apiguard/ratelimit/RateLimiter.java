package io.apiguard.ratelimit;

import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe sliding-window rate limiter keyed by a string (typically an IP address).
 * All state is in-memory — for distributed rate limiting wire in a Redis-backed
 * implementation instead.
 */
@Component
public class RateLimiter {

    private final int  maxCalls;
    private final long windowMs;
    private final int  windowSeconds;

    private final ConcurrentHashMap<String, Deque<Long>> store = new ConcurrentHashMap<>();

    /**
     * Creates a limiter with default limits: 100 requests per 60 seconds.
     */
    public RateLimiter() {
        this(100, 60);
    }

    /**
     * @param maxCalls      maximum number of calls permitted per window
     * @param windowSeconds sliding window duration in seconds
     */
    public RateLimiter(int maxCalls, int windowSeconds) {
        this.maxCalls      = maxCalls;
        this.windowSeconds = windowSeconds;
        this.windowMs      = windowSeconds * 1_000L;
    }

    /**
     * Checks whether a new request from {@code key} is within the rate limit.
     *
     * @param key identifier to rate-limit on (e.g. IP address or user ID)
     * @return {@code true} if the request is allowed, {@code false} if throttled
     */
    public boolean isAllowed(String key) {
        long now = System.currentTimeMillis();
        store.putIfAbsent(key, new ArrayDeque<>());
        Deque<Long> window = store.get(key);

        synchronized (window) {
            // Evict timestamps outside the current window
            while (!window.isEmpty() && now - window.peekFirst() > windowMs) {
                window.pollFirst();
            }
            if (window.size() >= maxCalls) {
                return false;
            }
            window.addLast(now);
            return true;
        }
    }

    public int getMaxCalls()      { return maxCalls;      }
    public int getWindowSeconds() { return windowSeconds; }
}
