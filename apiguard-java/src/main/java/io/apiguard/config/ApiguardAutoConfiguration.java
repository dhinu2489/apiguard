package io.apiguard.config;

import io.apiguard.filter.SecurityFilter;
import io.apiguard.jwt.JwtValidator;
import io.apiguard.ratelimit.RateLimiter;
import io.apiguard.rbac.RBACEnforcer;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;

/**
 * Spring Boot auto-configuration for apiguard.
 * Registers all apiguard beans when {@code apiguard.jwt.public-key} is set.
 * No {@code @ComponentScan} needed in the consumer's app.
 */
@AutoConfiguration
@EnableConfigurationProperties(ApiguardProperties.class)
public class ApiguardAutoConfiguration {

    private final ApiguardProperties props;
    private final ResourceLoader resourceLoader;

    public ApiguardAutoConfiguration(ApiguardProperties props,
                                     ResourceLoader resourceLoader) {
        this.props          = props;
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public JwtValidator jwtValidator() {
        String pem = loadPublicKeyPem(props.getJwt().getPublicKey());
        return new JwtValidator(
            pem,
            props.getJwt().getAlgorithm(),
            props.getJwt().getIssuer(),
            props.getJwt().getAudience()
        );
    }

    @Bean
    public RateLimiter rateLimiter() {
        return new RateLimiter(
            props.getRateLimit().getMaxCalls(),
            props.getRateLimit().getWindowSeconds()
        );
    }

    @Bean
    public SecurityFilter securityFilter(JwtValidator jwtValidator,
                                         RateLimiter rateLimiter) {
        return new SecurityFilter(
            jwtValidator,
            rateLimiter,
            new HashSet<>(props.getPublicPaths())
        );
    }

    @Bean
    public RBACEnforcer rbacEnforcer() {
        return new RBACEnforcer();
    }

    private String loadPublicKeyPem(String location) {
        try {
            if (location == null || location.isBlank()) {
                throw new IllegalStateException(
                    "apiguard.jwt.public-key must be set");
            }
            try (InputStream is = resourceLoader.getResource(location).getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        } catch (IOException ex) {
            throw new IllegalStateException(
                "Failed to load JWT public key from: " + location, ex);
        }
    }
}
