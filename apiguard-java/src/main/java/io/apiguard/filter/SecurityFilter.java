package io.apiguard.filter;

import io.apiguard.exception.AuthException;
import io.apiguard.jwt.JwtValidator;
import io.apiguard.ratelimit.RateLimiter;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Drop-in servlet filter providing JWT authentication, rate limiting,
 * and security headers. Register as a Spring bean — auto-configuration
 * picks it up via {@link io.apiguard.config.ApiguardAutoConfiguration}.
 */
@Component
@Order(1)
public class SecurityFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SecurityFilter.class);

    private static final Map<String, String> SECURITY_HEADERS = Map.of(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options",    "nosniff",
        "X-Frame-Options",           "DENY",
        "Content-Security-Policy",   "default-src 'self'",
        "Referrer-Policy",           "strict-origin-when-cross-origin",
        "Permissions-Policy",        "geolocation=(), microphone=()"
    );

    private final JwtValidator jwtValidator;
    private final RateLimiter  rateLimiter;
    private final Set<String>  publicPaths;

    public SecurityFilter(JwtValidator jwtValidator,
                          RateLimiter rateLimiter,
                          Set<String> publicPaths) {
        this.jwtValidator = jwtValidator;
        this.rateLimiter  = rateLimiter;
        this.publicPaths  = publicPaths;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest  req,
                                    HttpServletResponse res,
                                    FilterChain         chain)
            throws ServletException, IOException {

        String requestId = UUID.randomUUID().toString();
        res.setHeader("X-Request-ID", requestId);

        // ── Rate limiting ─────────────────────────────────
        String ip = req.getRemoteAddr();
        if (!rateLimiter.isAllowed(ip)) {
            log.warn("rate_limit_exceeded requestId={} ip={}", requestId, ip);
            res.setHeader("Retry-After", String.valueOf(rateLimiter.getWindowSeconds()));
            res.sendError(429, "Rate limit exceeded");
            return;
        }

        // ── Security headers ──────────────────────────────
        SECURITY_HEADERS.forEach(res::setHeader);

        // ── JWT authentication ────────────────────────────
        String path     = req.getRequestURI();
        boolean isPublic = publicPaths.stream().anyMatch(path::startsWith);

        if (!isPublic) {
            String authHeader = req.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                res.sendError(401, "Missing or invalid Authorization header");
                return;
            }
            try {
                Claims claims = jwtValidator.validate(authHeader.substring(7));
                req.setAttribute("claims", claims);
                log.info("auth_ok requestId={} subject={} path={}",
                         requestId, claims.getSubject(), path);
            } catch (AuthException ex) {
                log.warn("auth_failed requestId={} ip={} reason={}",
                         requestId, ip, ex.getMessage());
                res.sendError(401, ex.getMessage());
                return;
            }
        }

        chain.doFilter(req, res);

        log.info("request method={} path={} status={} requestId={}",
                 req.getMethod(), path, res.getStatus(), requestId);
    }
}
