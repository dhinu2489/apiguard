package io.apiguard.jwt;

import io.apiguard.exception.AuthException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Validates RS256 / ES256 signed JWTs.
 * Constructed by {@link io.apiguard.config.ApiguardAutoConfiguration}
 * from application properties.
 */
public class JwtValidator {

    private static final Logger log = LoggerFactory.getLogger(JwtValidator.class);

    private final JwtParser parser;

    /**
     * @param publicKeyPem  PEM-encoded RSA or EC public key (with or without headers)
     * @param algorithm     "RSA" or "EC" — matches the signing key type
     * @param issuer        Expected {@code iss} claim — set null to skip check
     * @param audience      Expected {@code aud} claim — set null to skip check
     */
    public JwtValidator(String publicKeyPem,
                        String algorithm,
                        String issuer,
                        String audience) {
        JwtParserBuilder builder = Jwts.parserBuilder()
            .setSigningKey(loadPublicKey(publicKeyPem, algorithm));

        if (issuer   != null) builder.requireIssuer(issuer);
        if (audience != null) builder.requireAudience(audience);

        this.parser = builder.build();
    }

    /**
     * Validates the token and returns its claims.
     *
     * @param token raw JWT string (without "Bearer " prefix)
     * @return parsed and verified {@link Claims}
     * @throws AuthException if the token is invalid, expired, or untrusted
     */
    public Claims validate(String token) {
        try {
            return parser.parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException ex) {
            throw new AuthException("Token has expired", ex);
        } catch (UnsupportedJwtException ex) {
            throw new AuthException("Unsupported JWT format", ex);
        } catch (MalformedJwtException ex) {
            throw new AuthException("Malformed JWT", ex);
        } catch (SignatureException ex) {
            throw new AuthException("Invalid JWT signature", ex);
        } catch (IllegalArgumentException ex) {
            throw new AuthException("JWT token is empty or null", ex);
        }
    }

    private PublicKey loadPublicKey(String pem, String algorithm) {
        try {
            String stripped = pem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----",   "")
                .replaceAll("\\s",                  "");
            byte[] decoded = Base64.getDecoder().decode(stripped);
            return KeyFactory.getInstance(algorithm)
                             .generatePublic(new X509EncodedKeySpec(decoded));
        } catch (Exception ex) {
            throw new IllegalStateException(
                "Failed to load public key — check apiguard.jwt.public-key in your config", ex);
        }
    }
}
