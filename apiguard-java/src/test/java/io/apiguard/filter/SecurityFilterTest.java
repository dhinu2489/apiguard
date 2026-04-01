package io.apiguard.filter;

import io.apiguard.exception.AuthException;
import io.apiguard.jwt.JwtValidator;
import io.apiguard.ratelimit.RateLimiter;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityFilterTest {

    @Mock JwtValidator jwtValidator;
    @Mock RateLimiter  rateLimiter;
    @Mock FilterChain  chain;
    @Mock Claims       claims;

    SecurityFilter filter;

    @BeforeEach
    void setUp() {
        filter = new SecurityFilter(
            jwtValidator,
            rateLimiter,
            Set.of("/health", "/docs")
        );
        when(rateLimiter.getWindowSeconds()).thenReturn(60);
    }

    @Test
    @DisplayName("Public paths bypass JWT authentication")
    void publicPath_skipsAuth() throws Exception {
        when(rateLimiter.isAllowed(any())).thenReturn(true);
        MockHttpServletRequest  req = new MockHttpServletRequest("GET", "/health");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilterInternal(req, res, chain);

        verify(chain).doFilter(req, res);
        verify(jwtValidator, never()).validate(any());
        assertThat(res.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("Missing Authorization header returns 401")
    void missingAuthHeader_returns401() throws Exception {
        when(rateLimiter.isAllowed(any())).thenReturn(true);
        MockHttpServletRequest  req = new MockHttpServletRequest("GET", "/api/invoices");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilterInternal(req, res, chain);

        assertThat(res.getStatus()).isEqualTo(401);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Valid JWT allows request through")
    void validJwt_allowsRequest() throws Exception {
        when(rateLimiter.isAllowed(any())).thenReturn(true);
        when(jwtValidator.validate(any())).thenReturn(claims);
        when(claims.getSubject()).thenReturn("user-123");

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/invoices");
        req.addHeader("Authorization", "Bearer valid.jwt.token");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilterInternal(req, res, chain);

        verify(chain).doFilter(req, res);
        assertThat(req.getAttribute("claims")).isEqualTo(claims);
    }

    @Test
    @DisplayName("Expired JWT returns 401")
    void expiredJwt_returns401() throws Exception {
        when(rateLimiter.isAllowed(any())).thenReturn(true);
        when(jwtValidator.validate(any())).thenThrow(new AuthException("Token has expired"));

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/invoices");
        req.addHeader("Authorization", "Bearer expired.jwt.token");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilterInternal(req, res, chain);

        assertThat(res.getStatus()).isEqualTo(401);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Rate-limited request returns 429 with Retry-After header")
    void rateLimited_returns429() throws Exception {
        when(rateLimiter.isAllowed(any())).thenReturn(false);

        MockHttpServletRequest  req = new MockHttpServletRequest("GET", "/api/invoices");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilterInternal(req, res, chain);

        assertThat(res.getStatus()).isEqualTo(429);
        assertThat(res.getHeader("Retry-After")).isEqualTo("60");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("Security headers are set on all responses")
    void securityHeaders_arePresent() throws Exception {
        when(rateLimiter.isAllowed(any())).thenReturn(true);
        MockHttpServletRequest  req = new MockHttpServletRequest("GET", "/health");
        MockHttpServletResponse res = new MockHttpServletResponse();

        filter.doFilterInternal(req, res, chain);

        assertThat(res.getHeader("X-Frame-Options")).isEqualTo("DENY");
        assertThat(res.getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(res.getHeader("Strict-Transport-Security"))
            .contains("max-age=31536000");
    }
}
