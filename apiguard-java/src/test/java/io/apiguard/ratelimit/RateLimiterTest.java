package io.apiguard.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimiterTest {

    @Test
    @DisplayName("Allows requests within the limit")
    void allowsRequestsWithinLimit() {
        RateLimiter limiter = new RateLimiter(5, 60);
        for (int i = 0; i < 5; i++) {
            assertThat(limiter.isAllowed("192.168.1.1")).isTrue();
        }
    }

    @Test
    @DisplayName("Blocks the request that exceeds the limit")
    void blocksRequestExceedingLimit() {
        RateLimiter limiter = new RateLimiter(3, 60);
        limiter.isAllowed("10.0.0.1");
        limiter.isAllowed("10.0.0.1");
        limiter.isAllowed("10.0.0.1");
        assertThat(limiter.isAllowed("10.0.0.1")).isFalse();
    }

    @Test
    @DisplayName("Different keys have independent counters")
    void independentCountersPerKey() {
        RateLimiter limiter = new RateLimiter(2, 60);
        limiter.isAllowed("ip-a");
        limiter.isAllowed("ip-a");
        // ip-a is now at limit, ip-b should still be allowed
        assertThat(limiter.isAllowed("ip-a")).isFalse();
        assertThat(limiter.isAllowed("ip-b")).isTrue();
    }
}
